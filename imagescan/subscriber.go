package imagescan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/castai/kvisor/castai"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	imgcollectorconfig "github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/config"
	"github.com/castai/kvisor/controller"
	"github.com/castai/kvisor/metrics"
)

type castaiClient interface {
	SendImageMetadata(ctx context.Context, meta *castai.ImageMetadata) error
	GetSyncState(ctx context.Context, filter *castai.SyncStateFilter) (*castai.SyncStateResponse, error)
}

func NewSubscriber(
	log logrus.FieldLogger,
	cfg config.ImageScan,
	imageScanner imageScanner,
	client castaiClient,
	k8sVersionMinor int,
) *Subscriber {
	ctx, cancel := context.WithCancel(context.Background())
	return &Subscriber{
		ctx:             ctx,
		cancel:          cancel,
		imageScanner:    imageScanner,
		client:          client,
		delta:           newDeltaState(),
		log:             log.WithField("component", "imagescan"),
		cfg:             cfg,
		k8sVersionMinor: k8sVersionMinor,
		timeGetter:      timeGetter(),
	}
}

func timeGetter() func() time.Time {
	return func() time.Time {
		return time.Now().UTC()
	}
}

type Subscriber struct {
	ctx             context.Context
	cancel          context.CancelFunc
	delta           *deltaState
	imageScanner    imageScanner
	client          castaiClient
	log             logrus.FieldLogger
	cfg             config.ImageScan
	k8sVersionMinor int
	timeGetter      func() time.Time
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	rt := []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&appsv1.ReplicaSet{}),
		reflect.TypeOf(&batchv1.Job{}),
		reflect.TypeOf(&corev1.Node{}),
	}
	return rt
}

func (s *Subscriber) Run(ctx context.Context) error {
	scanTicker := time.NewTicker(s.cfg.ScanInterval)
	defer scanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case deltaItem := <-s.delta.queue:
			s.handleDelta(deltaItem.event, deltaItem.obj)
		case <-scanTicker.C:
			if err := s.scheduleScans(ctx); err != nil {
				s.log.Errorf("images scan failed: %v", err)
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.delta.queue <- deltaQueueItem{
		event: controller.EventAdd,
		obj:   obj,
	}
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.delta.queue <- deltaQueueItem{
		event: controller.EventUpdate,
		obj:   obj,
	}
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.delta.queue <- deltaQueueItem{
		event: controller.EventDelete,
		obj:   obj,
	}
}

func (s *Subscriber) handleDelta(event controller.Event, o controller.Object) {
	switch event {
	case controller.EventAdd, controller.EventUpdate:
		s.delta.upsert(o)
	case controller.EventDelete:
		s.delta.delete(o)
	}
}

func (s *Subscriber) scheduleScans(ctx context.Context) (rerr error) {
	s.syncRemoteState(ctx)
	s.sendImageOwnerChanges(ctx)

	pendingImages := s.findPendingImages()
	// Scan few pending images in small batches.
	concurrentScans := s.concurrentScansNumber()
	imagesForScan := pendingImages
	if len(imagesForScan) > concurrentScans {
		imagesForScan = imagesForScan[:concurrentScans]
	}
	if l := len(imagesForScan); l > 0 {
		s.log.Infof("scheduling %d images scans", l)
		if err := s.scanImages(ctx, imagesForScan); err != nil {
			return err
		}
		s.log.Info("images scan finished")
	} else {
		s.log.Debug("skipping images scan, no pending images")
	}

	return nil
}

func (s *Subscriber) findPendingImages() []*image {
	images := s.delta.getImages()

	now := s.timeGetter()

	var privateImagesCount int
	pendingImages := lo.Filter(images, func(v *image, _ int) bool {
		isPrivateImage := errors.Is(v.lastScanErr, errPrivateImage)
		if isPrivateImage {
			privateImagesCount++
		}
		return !v.scanned &&
			len(v.owners) > 0 &&
			!isPrivateImage &&
			(v.nextScan.IsZero() || v.nextScan.Before(now))
	})
	sort.Slice(pendingImages, func(i, j int) bool {
		return pendingImages[i].failures < pendingImages[j].failures
	})
	s.log.Infof("found %d images, pending images %d", len(images), len(pendingImages))
	metrics.SetTotalImagesCount(len(images))
	metrics.SetPendingImagesCount(len(pendingImages))
	if privateImagesCount > 0 {
		s.log.Warnf("skipping %d private images", privateImagesCount)
	}
	return pendingImages
}

func (s *Subscriber) scanImages(ctx context.Context, images []*image) error {
	var wg sync.WaitGroup
	for _, img := range images {
		if img.name == "" {
			return fmt.Errorf("no image name set, image_id=%s", img.id)
		}

		wg.Add(1)
		go func(img *image) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			ctx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
			defer cancel()

			log := s.log.WithField("image", img.name)
			log.Info("scanning image")
			if err := s.scanImage(ctx, img); err != nil {
				log.Errorf("image scan failed: %v", err)
				s.delta.setImageScanError(img, err)
				return
			}
			log.Info("image scan finished")
			s.delta.updateImage(img, func(img *image) {
				img.scanned = true
			})
		}(img)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Subscriber) scanImage(ctx context.Context, img *image) (rerr error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	mode := s.getScanMode(img)

	var nodeNames []string
	if imgcollectorconfig.Mode(mode) == imgcollectorconfig.ModeHostFS {
		// In HostFS we need to choose only from nodes which contains this image.
		nodeNames = lo.Keys(img.nodes)
		if len(nodeNames) == 0 {
			return errors.New("image with empty nodes")
		}
	} else {
		nodeNames = lo.Keys(s.delta.nodes)
	}

	// Resolve best node.
	memQty := resource.MustParse(s.cfg.MemoryRequest)
	cpuQty := resource.MustParse(s.cfg.CPURequest)
	resolvedNode, err := s.delta.findBestNode(nodeNames, memQty.AsDec(), cpuQty.AsDec())
	if err != nil {
		return err
	}

	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeImage, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeImage, start)
	}()

	return s.imageScanner.ScanImage(ctx, ScanImageParams{
		ImageName:                   img.name,
		ImageID:                     img.id,
		ContainerRuntime:            string(img.containerRuntime),
		Mode:                        mode,
		ResourceIDs:                 lo.Keys(img.owners),
		NodeName:                    resolvedNode,
		DeleteFinishedJob:           true,
		WaitForCompletion:           true,
		WaitDurationAfterCompletion: 30 * time.Second,
	})
}

func (s *Subscriber) concurrentScansNumber() int {
	if s.delta.nodeCount() == 1 {
		return 1
	}

	return int(s.cfg.MaxConcurrentScans)
}

// getScanMode returns configured image scan mode if set.
// If mode is empty it will be determined automatically based on container runtime inside scanner.go
//
// Special case:
// If hostfs mode is used and image scan fails due to missing layers remote image scan will be used as fallback.
func (s *Subscriber) getScanMode(img *image) string {
	mode := s.cfg.Mode
	if s.delta.isHostFsDisabled() || (img.lastScanErr != nil && errors.Is(img.lastScanErr, errImageScanLayerNotFound)) {
		mode = string(imgcollectorconfig.ModeRemote)
	}
	return mode
}

func (s *Subscriber) sendImageOwnerChanges(ctx context.Context) {
	images := s.delta.getImages()

	var errg errgroup.Group
	errg.SetLimit(10)

	for _, img := range images {
		img := img
		if img.ownerChanges.empty() {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		errg.Go(func() error {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if err := s.client.SendImageMetadata(ctx, &castai.ImageMetadata{
				ImageName:          img.name,
				ImageID:            img.id,
				Architecture:       img.architecture,
				ResourceIDs:        img.ownerChanges.addedIDS,
				RemovedResourceIDs: img.ownerChanges.removedIDs,
			}); err != nil {
				return err
			}
			// Reset owner changes state.
			img.ownerChanges.clear()
			return nil
		})
	}

	if err := errg.Wait(); err != nil {
		s.log.Errorf("sending image metadata with owners change only: %v", err)
	}
}

func (s *Subscriber) syncRemoteState(ctx context.Context) {
	images := s.delta.getImages()
	notScannedImages := lo.Filter(images, func(item *image, index int) bool {
		return !item.scanned
	})
	imagesIds := lo.Map(notScannedImages, func(item *image, index int) string {
		return item.id
	})
	resp, err := s.client.GetSyncState(ctx, &castai.SyncStateFilter{ImagesIds: imagesIds})
	if err != nil {
		s.log.Errorf("getting images sync state from remote: %v", err)
		return
	}
	for _, scannedImage := range resp.ScannedImages {
		s.delta.setImageScanned(scannedImage.CacheKey())
	}
}
