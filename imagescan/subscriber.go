package imagescan

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	corev1 "k8s.io/api/core/v1"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
)

var supportedTypes = []reflect.Type{
	reflect.TypeOf(&corev1.Pod{}),
}

type Config struct {
	ScanInterval       time.Duration
	MaxConcurrentScans int64
}

func NewSubscriber(log logrus.FieldLogger, cfg Config, imageScanner imageScanner) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 15 * time.Second
	}
	if cfg.MaxConcurrentScans == 0 {
		cfg.MaxConcurrentScans = 5
	}

	return &Subscriber{
		ctx:          ctx,
		cancel:       cancel,
		imageScanner: imageScanner,
		delta:        newDeltaState(),
		log:          log,
		cfg:          cfg,
	}
}

type Subscriber struct {
	ctx          context.Context
	cancel       context.CancelFunc
	delta        *deltaState
	imageScanner imageScanner
	log          logrus.FieldLogger
	cfg          Config
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return supportedTypes
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

func (s *Subscriber) Supports(typ reflect.Type) bool {
	for i := range supportedTypes {
		if supportedTypes[i] == typ {
			return true
		}
	}

	return false
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
	Resources []castai.Resource
	NodeNames map[string]struct{}
}

func (s *Subscriber) scheduleScans(ctx context.Context) (rerr error) {
	pods := s.delta.getPods()
	if len(pods) == 0 {
		return nil
	}

	// TODO: Pods cleanup is too simple here.
	// TODO: Need to keep track of containers scan state and only remove pods with all completed containers.
	defer func() {
		if rerr == nil {
			s.delta.deletePods()
		}
	}()

	s.log.Info("scheduling images scan")

	imgs := make(map[string]*imageInfo)

	for _, pod := range pods {
		imgs = appendImage(imgs, pod.Spec.Containers, pod.Spec.NodeName, toResource(pod))
	}

	sem := semaphore.NewWeighted(s.cfg.MaxConcurrentScans)
	for imageName, info := range imgs {
		if err := sem.Acquire(ctx, 1); err != nil {
			return err
		}
		go func(imageName string, info *imageInfo) {
			defer sem.Release(1)

			ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()

			log := s.log.WithField("image", imageName)

			nodeNames := lo.Keys(info.NodeNames)
			var nodeName string
			if len(nodeNames) > 0 {
				nodeName = nodeNames[0] // TODO: Find most suitable node for run the job. We should prefer nodes with free resources.
			}

			log.Info("scanning image")
			if err := s.imageScanner.ScanImage(ctx, ScanImageConfig{
				ImageName:         imageName,
				ImageID:           "todo",
				NodeName:          nodeName,
				DeleteFinishedJob: true,
				WaitForCompletion: true,
			}); err != nil {
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

func appendImage(imgs map[string]*imageInfo, containers []corev1.Container, nodeName string, resource castai.Resource) map[string]*imageInfo {
	for _, cont := range containers {
		v, ok := imgs[cont.Image]
		if ok {
			v.NodeNames[nodeName] = struct{}{}
			v.Resources = append(v.Resources, resource)
		} else {
			imgs[cont.Image] = &imageInfo{
				Resources: []castai.Resource{resource},
				NodeNames: map[string]struct{}{
					nodeName: {},
				},
			}
		}
	}
	return imgs
}

func toResource(pod *corev1.Pod) castai.Resource {
	objMeta := pod.ObjectMeta
	owner := getPodOwner(pod)
	return castai.Resource{
		ObjectMeta: castai.ObjectMeta{
			Namespace: owner.name,
			Name:      objMeta.Namespace,
		},
		ObjectType: castai.ObjectType{
			APIVersion: owner.APIVersion,
			Kind:       owner.kind,
		},
	}
}

type owner struct {
	name       string
	kind       string
	APIVersion string
}

func getPodOwner(pod *corev1.Pod) owner {
	if len(pod.OwnerReferences) == 0 {
		return owner{}
	}

	ref := pod.OwnerReferences[0]
	if ref.Kind == "ReplicaSet" {
		ref.Kind = "Deployment"
		nameParts := strings.Split(ref.Name, "-")
		ref.Name = strings.Replace(ref.Name, "-"+nameParts[len(nameParts)-1], "", 1)
	}
	apiVersion := "v1"
	if ref.Kind != "Pod" {
		apiVersion = "apps/v1"
	}
	return owner{
		name:       ref.Name,
		kind:       ref.Kind,
		APIVersion: apiVersion,
	}
}
