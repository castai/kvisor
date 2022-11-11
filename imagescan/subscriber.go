package imagescan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/metrics"
)

type castaiClient interface {
	SendImageMetadata(ctx context.Context, meta *castai.ImageMetadata) error
}

func NewSubscriber(
	log logrus.FieldLogger,
	cfg config.ImageScan,
	client castaiClient,
	imageScanner imageScanner,
	k8sVersionMinor int,
	delta *deltaState,
) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())
	return &Subscriber{
		ctx:             ctx,
		cancel:          cancel,
		client:          client,
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
	client          castaiClient
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
		return !v.scanned && v.name != ""
	})
	sort.Slice(pendingImages, func(i, j int) bool {
		return pendingImages[i].failures < pendingImages[j].failures
	})
	s.log.Debugf("found %d images, pending images %d", len(images), len(pendingImages))

	// During each scan schedule we scan only configured amount of images.
	imagesForScan := pendingImages
	if len(imagesForScan) > int(s.cfg.MaxConcurrentScans) {
		imagesForScan = imagesForScan[:s.cfg.MaxConcurrentScans]
	}

	if l := len(imagesForScan); l > 0 {
		s.log.Infof("scheduling %d images scans", l)
		sem := semaphore.NewWeighted(s.cfg.MaxConcurrentScans)
		for _, img := range imagesForScan {
			if img.name == "" {
				return fmt.Errorf("no image name set: %+v", img)
			}

			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			go func(img *image) {
				defer sem.Release(1)

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
					img.resourcesChanged = false
				})
			}(img)
		}

		if err := sem.Acquire(ctx, s.cfg.MaxConcurrentScans); err != nil {
			return err
		}

		s.log.Info("images scan finished")
	} else {
		s.log.Debug("skipping images scan, no pending images")
	}

	imagesWithChangedResources := lo.Filter(images, func(v *image, _ int) bool {
		return v.scanned && v.resourcesChanged && v.name != ""
	})
	if l := len(imagesWithChangedResources); l > 0 {
		s.log.Infof("updating %d images resources", l)
		for _, img := range imagesWithChangedResources {
			if err := s.client.SendImageMetadata(ctx, &castai.ImageMetadata{
				ImageName:   img.name,
				ImageID:     img.id,
				ResourceIDs: lo.Keys(img.resourcesIDs),
			}); err != nil {
				return fmt.Errorf("sending image metadata resources update: %w", err)
			}
			s.delta.updateImage(img.id, func(img *image) {
				img.resourcesChanged = false
			})
		}
	}

	return nil
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
		resolvedNode, err := s.delta.findBestNode(nodeNames, memQty.AsDec())
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
		ImageName:         img.name,
		ImageID:           img.id,
		ContainerRuntime:  img.containerRuntime,
		ResourceIDs:       lo.Keys(img.resourcesIDs),
		NodeName:          nodeName,
		Tolerations:       img.podTolerations, // Assign the same tolerations as on pod. That will ensure that scan job can run on selected node.
		DeleteFinishedJob: true,
		WaitForCompletion: true,
	})
}
