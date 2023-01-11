package imagescan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/castai/kvisor/config"
	"github.com/castai/kvisor/controller"
	"github.com/castai/kvisor/metrics"
)

func NewSubscriber(
	log logrus.FieldLogger,
	cfg config.ImageScan,
	imageScanner imageScanner,
	k8sVersionMinor int,
	delta *deltaState,
) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())
	return &Subscriber{
		ctx:             ctx,
		cancel:          cancel,
		imageScanner:    imageScanner,
		delta:           delta,
		log:             log,
		cfg:             cfg,
		k8sVersionMinor: k8sVersionMinor,
	}
}

type Subscriber struct {
	ctx             context.Context
	cancel          context.CancelFunc
	delta           *deltaState
	imageScanner    imageScanner
	log             logrus.FieldLogger
	cfg             config.ImageScan
	k8sVersionMinor int
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
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.ScanInterval):
			if err := s.scheduleScans(ctx); err != nil {
				s.log.Errorf("images scan failed: %v", err)
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.handleDelta(controller.EventAdd, obj)
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.handleDelta(controller.EventUpdate, obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.handleDelta(controller.EventDelete, obj)
}

func (s *Subscriber) handleDelta(event controller.Event, o controller.Object) {
	switch event {
	case controller.EventAdd:
		s.delta.upsert(o)
	case controller.EventUpdate:
		s.delta.upsert(o)
	case controller.EventDelete:
		s.delta.delete(o)
	}
}

func (s *Subscriber) scheduleScans(ctx context.Context) (rerr error) {
	images := lo.Values(s.delta.getImages())
	pendingImages := lo.Filter(images, func(v *image, _ int) bool {
		return !v.scanned && v.name != "" && len(v.owners) > 0
	})
	sort.Slice(pendingImages, func(i, j int) bool {
		return pendingImages[i].failures < pendingImages[j].failures
	})
	s.log.Infof("found %d images, pending images %d", len(images), len(pendingImages))
	metrics.SetTotalImagesCount(len(images))
	metrics.SetPendingImagesCount(len(pendingImages))

	// During each scan schedule we scan only configured amount of images.
	imagesForScan := pendingImages
	if len(imagesForScan) > int(s.cfg.MaxConcurrentScans) {
		imagesForScan = imagesForScan[:s.cfg.MaxConcurrentScans]
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

func (s *Subscriber) scanImages(ctx context.Context, images []*image) error {
	var wg sync.WaitGroup
	for _, img := range images {
		if img.name == "" {
			return fmt.Errorf("no image name set: %+v", img)
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
				// Increase image failures on error.
				s.delta.updateImage(img.id, func(img *image) {
					img.failures++
				})
				return
			}
			log.Info("image scan finished")
			s.delta.updateImage(img.id, func(img *image) {
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

	nodeNames := lo.Keys(img.nodes)
	var nodeName string
	if len(nodeNames) == 0 {
		return errors.New("image with empty nodes")
	}

	nodeName = nodeNames[0]
	if len(nodeNames) > 1 {
		// Resolve best node.
		memQty := resource.MustParse(s.cfg.MemoryRequest)
		cpuQty := resource.MustParse(s.cfg.CPURequest)
		resolvedNode, err := s.delta.findBestNode(nodeNames, memQty.AsDec(), cpuQty.AsDec())
		if err != nil {
			return err
		} else {
			nodeName = resolvedNode
		}
	}

	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeImage, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeImage, start)
	}()

	return s.imageScanner.ScanImage(ctx, ScanImageParams{
		ImageName:                   img.name,
		ImageID:                     img.id,
		ContainerRuntime:            img.containerRuntime,
		ResourceIDs:                 lo.Keys(img.owners),
		NodeName:                    nodeName,
		Tolerations:                 img.podTolerations, // Assign the same tolerations as on pod. That will ensure that scan job can run on selected node.
		DeleteFinishedJob:           true,
		WaitForCompletion:           true,
		WaitDurationAfterCompletion: 30 * time.Second,
	})
}
