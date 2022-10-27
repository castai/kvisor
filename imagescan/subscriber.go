package imagescan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"gopkg.in/inf.v0"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/imagescan/allow"
	"github.com/castai/sec-agent/metrics"
)

func NewSubscriber(
	log logrus.FieldLogger,
	cfg config.ImageScan,
	client castai.Client,
	imageScanner imageScanner,
	k8sVersionMinor int,
	nodeResolver func([]string, *inf.Dec) (string, error),
) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())
	scannedImagesCache, _ := lru.New(10000)

	return &Subscriber{
		ctx:                ctx,
		cancel:             cancel,
		client:             client,
		imageScanner:       imageScanner,
		delta:              newDeltaState(),
		log:                log,
		cfg:                cfg,
		k8sVersionMinor:    k8sVersionMinor,
		scannedImagesCache: scannedImagesCache,
		bestNodeResolver:   nodeResolver,
	}
}

type Subscriber struct {
	ctx                context.Context
	cancel             context.CancelFunc
	client             castai.Client
	delta              *deltaState
	imageScanner       imageScanner
	scannedImagesCache *lru.Cache
	log                logrus.FieldLogger
	cfg                config.ImageScan
	k8sVersionMinor    int
	bestNodeResolver   func([]string, *inf.Dec) (string, error)
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	rt := []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&appsv1.ReplicaSet{}),
		reflect.TypeOf(&batchv1.Job{}),
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
	s.modifyDelta(controller.EventAdd, obj)
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.modifyDelta(controller.EventDelete, obj)
}

func (s *Subscriber) modifyDelta(event controller.Event, o controller.Object) {
	switch event {
	case controller.EventAdd:
		s.delta.upsert(o)
	case controller.EventUpdate:
		s.delta.upsert(o)
	case controller.EventDelete:
		s.delta.delete(o)
	}
}

type imageInfo struct {
	imageName      string
	imageID        string
	containerID    string
	resourcesIDs   []string
	nodeNames      map[string]struct{}
	podTolerations []corev1.Toleration
}

func (s *Subscriber) scheduleScans(ctx context.Context) (rerr error) {
	podsMap := s.delta.getPods()
	if len(podsMap) == 0 {
		return nil
	}
	pods := lo.Filter(lo.Values(podsMap), func(v *corev1.Pod, _ int) bool {
		return v.Status.Phase == corev1.PodRunning || v.Status.Phase == corev1.PodSucceeded
	})
	if len(pods) == 0 {
		s.log.Debug("no running or succeeded pods found, skipping images scan")
		return nil
	}

	rsMap := s.delta.getReplicaSets()
	jobsMap := s.delta.getJobs()

	// TODO: Pods cleanup is too simple here.
	// TODO: Need to keep track of containers scan state and only remove pods with all completed containers.
	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeImage, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeImage, start)
		if rerr == nil {
			s.delta.deletePods(podsMap)
		}
	}()

	imgs, err := collectImages(pods, rsMap, jobsMap)
	if err != nil {
		return fmt.Errorf("collecting images: %v", err)
	}

	s.log.Infof("scheduling %d images scan for %d pods", len(imgs), len(pods))

	sem := semaphore.NewWeighted(s.cfg.MaxConcurrentScans)
	for imageName, info := range imgs {
		if err := sem.Acquire(ctx, 1); err != nil {
			return err
		}
		go func(imageName string, info *imageInfo) {
			defer sem.Release(1)

			ctx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
			defer cancel()

			log := s.log.WithField("image", imageName)
			log.Info("scanning image")
			if err := s.scanImage(ctx, log, info); err != nil {
				if errors.Is(err, allow.ErrNoCandidates) {
					// TODO: no nodes with resources, schedule job for later
					log.Debugf("no resources to scan image %q", info.imageName)
				}
				log.Errorf("image scan failed: %v", err)
				return
			}
			log.Info("image scan finished")
		}(imageName, info)
	}

	if err := sem.Acquire(ctx, s.cfg.MaxConcurrentScans); err != nil {
		return err
	}

	s.log.Info("images scan finished")

	return nil
}

func (s *Subscriber) scanImage(ctx context.Context, log logrus.FieldLogger, info *imageInfo) error {
	// If image is already scanned, sync update resource ids.
	uniqueResourceIDs := lo.Uniq(info.resourcesIDs)
	if cacheResourceIDs, ok := s.scannedImagesCache.Get(info.imageID); ok {
		diff, _ := lo.Difference(cacheResourceIDs.([]string), uniqueResourceIDs)
		if len(diff) == 0 {
			log.Debug("skipping scan, image already scanned and synced")
			return nil
		}
		if err := s.client.SendImageMetadata(ctx, &castai.ImageMetadata{
			ImageName:   info.imageName,
			ImageID:     info.imageID,
			ResourceIDs: diff,
		}); err != nil {
			return fmt.Errorf("sending image metadata resources update: %w", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	nodeNames := lo.Keys(info.nodeNames)
	var nodeName string
	if len(nodeNames) > 0 {
		nodeName = nodeNames[0]

		if len(nodeNames) > 1 {
			// resolve best node
			memQty := resource.MustParse(s.cfg.MemoryRequest)
			resolvedNode, err := s.bestNodeResolver(nodeNames, memQty.AsDec())
			if err != nil {
				return err
			} else {
				nodeName = resolvedNode
			}
		}
	}

	err := s.imageScanner.ScanImage(ctx, ScanImageParams{
		ImageName:         info.imageName,
		ImageID:           info.imageID,
		ContainerID:       info.containerID,
		ResourceIDs:       uniqueResourceIDs,
		NodeName:          nodeName,
		Tolerations:       info.podTolerations, // Assign the same tolerations as on pod. That will ensure that scan job can run on selected node.
		DeleteFinishedJob: true,
		WaitForCompletion: true,
	})
	if err != nil {
		return err
	}

	// Add image to scanned images cache.
	s.scannedImagesCache.Add(info.imageID, info.resourcesIDs)

	return nil
}

func collectImages(pods []*corev1.Pod, rsMap map[string]*appsv1.ReplicaSet, jobsMap map[string]*batchv1.Job) (map[string]*imageInfo, error) {
	imgs := map[string]*imageInfo{}
	for _, pod := range pods {
		containers := pod.Spec.Containers
		containers = append(containers, pod.Spec.InitContainers...)

		containerStatuses := pod.Status.ContainerStatuses
		containerStatuses = append(containerStatuses, pod.Status.InitContainerStatuses...)

		for _, cont := range containers {
			nodeName := pod.Spec.NodeName
			resourceID := getPodOwnerID(pod, rsMap, jobsMap)
			v, ok := imgs[cont.Image]
			if ok {
				v.nodeNames[nodeName] = struct{}{}
				v.resourcesIDs = append(v.resourcesIDs, resourceID)
			} else {
				cs, found := lo.Find(containerStatuses, func(v corev1.ContainerStatus) bool {
					return v.Name == cont.Name
				})
				if !found {
					return nil, fmt.Errorf("container %s status not found for pod %s", cont.Name, pod.Name)
				}
				imgs[cont.Image] = &imageInfo{
					imageName:      cont.Image,
					imageID:        cs.ImageID,
					containerID:    cs.ContainerID,
					resourcesIDs:   []string{resourceID},
					podTolerations: pod.Spec.Tolerations,
					nodeNames: map[string]struct{}{
						nodeName: {},
					},
				}
			}
		}
	}
	return imgs, nil
}

func getPodOwnerID(pod *corev1.Pod, rsMap map[string]*appsv1.ReplicaSet, jobsMap map[string]*batchv1.Job) string {
	if len(pod.OwnerReferences) == 0 {
		return string(pod.UID)
	}

	ref := pod.OwnerReferences[0]

	switch ref.Kind {
	case "ReplicaSet":
		for _, val := range rsMap {
			if val.UID == ref.UID {
				if len(val.OwnerReferences) > 0 {
					return string(val.OwnerReferences[0].UID)
				}
				return string(ref.UID)
			}
		}
	case "Job":
		for _, val := range jobsMap {
			if val.UID == ref.UID {
				if len(val.OwnerReferences) > 0 {
					return string(val.OwnerReferences[0].UID)
				}
				return string(ref.UID)
			}
		}
	}

	return string(ref.UID)
}
