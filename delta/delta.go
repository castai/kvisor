package delta

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/controller"
)

// newDelta initializes the delta struct which is used to collect cluster deltas, debounce them and map to CAST AI
// requests.
func newDelta(log logrus.FieldLogger, logLevel logrus.Level, provider SnapshotProvider) *delta {
	return &delta{
		log:      log,
		logLevel: logLevel,
		snapshot: provider,
		cache:    map[string]castai.DeltaItem{},
		skippers: []skipper{},
	}
}

const (
	kindPod     = "Pod"
	kindJob     = "Job"
	kindCronJob = "CronJob"
	kindNode    = "Node"
)

// skipper allows to skip adding item to delta cache.
type skipper func(obj object) bool

// delta is used to collect cluster deltas, debounce them and map to CAST AI requests. It holds a cache of queue items
// which is referenced any time a new item is added to debounce the items.
type delta struct {
	log      logrus.FieldLogger
	logLevel logrus.Level
	snapshot SnapshotProvider
	cache    map[string]castai.DeltaItem
	skippers []skipper
}

// add will add an item to the delta cache. It will debounce the objects.
func (d *delta) add(event controller.Event, newObj, oldObj object) {
	for _, skipper := range d.skippers {
		if skipper(newObj) {
			return
		}
	}

	key := string(newObj.GetUID())
	gvr := newObj.GetObjectKind().GroupVersionKind()
	d.log.Debugf("add delta, event=%s, gvr=%s, ns=%s, name=%s", event, gvr.String(), newObj.GetNamespace(), newObj.GetName())

	deltaItem := castai.DeltaItem{
		Event:            toCASTAIEvent(event),
		ObjectUID:        string(newObj.GetUID()),
		ObjectName:       newObj.GetName(),
		ObjectNamespace:  newObj.GetNamespace(),
		ObjectKind:       gvr.Kind,
		ObjectAPIVersion: gvr.GroupVersion().String(),
		ObjectCreatedAt:  newObj.GetCreationTimestamp().UTC(),
		ObjectOwnerUID:   getOwnerUID(newObj),
		ObjectLabels:     newObj.GetLabels(),
	}
	if containers, status, changed, ok := getContainersAndStatus(newObj, oldObj); ok {
		deltaItem.ObjectContainers = containers
		deltaItem.ObjectStatus = status
		deltaItem.ObjectImagesChanged = changed
	}

	d.cache[key] = deltaItem
	d.snapshot.append(deltaItem)
}

// clear resets the delta cache. Should be called after toCASTAIRequest is successfully delivered.
func (d *delta) clear() {
	d.cache = map[string]castai.DeltaItem{}
}

// toCASTAIRequest maps the collected delta cache to the castai.Delta type.
func (d *delta) toCASTAIRequest() *castai.Delta {
	return &castai.Delta{
		Items: lo.Values(d.cache),
	}
}

type object interface {
	runtime.Object
	metav1.Object
}

func toCASTAIEvent(e controller.Event) castai.EventType {
	switch e {
	case controller.EventAdd:
		return castai.EventAdd
	case controller.EventUpdate:
		return castai.EventUpdate
	case controller.EventDelete:
		return castai.EventDelete
	}
	return ""
}

func getContainersAndStatus(newObj, oldObj controller.Object) ([]castai.Container, interface{}, bool, bool) {
	newContainers, status, ok := extractContainers(newObj)
	if !ok {
		return nil, nil, false, false
	}

	lookup := make(map[string]string)
	res := make([]castai.Container, len(newContainers))
	for i, cont := range newContainers {
		lookup[cont.Name] = cont.Image
		res[i] = castai.Container{
			Name:      cont.Name,
			ImageName: cont.Image,
		}
	}

	if oldObj != nil {
		oldContainers, _, ok := extractContainers(oldObj)
		if !ok {
			return nil, nil, false, false
		}

		for _, cont := range oldContainers {
			if v, ok := lookup[cont.Name]; !ok || v != cont.Image {
				return res, status, true, true
			}
		}
	}

	return res, status, false, true
}

func extractContainers(obj controller.Object) ([]corev1.Container, interface{}, bool) {
	var containers []corev1.Container
	appendContainers := func(podSpec corev1.PodSpec) {
		containers = append(containers, podSpec.Containers...)
		containers = append(containers, podSpec.InitContainers...)
	}
	var st interface{}
	switch v := obj.(type) {
	case *batchv1.Job:
		st = v.Status
		appendContainers(v.Spec.Template.Spec)
	case *batchv1.CronJob:
		st = v.Status
		appendContainers(v.Spec.JobTemplate.Spec.Template.Spec)
	case *corev1.Pod:
		st = v.Status
		appendContainers(v.Spec)
	case *appsv1.Deployment:
		st = v.Status
		appendContainers(v.Spec.Template.Spec)
	case *appsv1.StatefulSet:
		st = v.Status
		appendContainers(v.Spec.Template.Spec)
	case *appsv1.DaemonSet:
		st = v.Status
		appendContainers(v.Spec.Template.Spec)
	default:
		return nil, nil, false
	}

	return containers, st, true
}

func getOwnerUID(obj controller.Object) string {
	if len(obj.GetOwnerReferences()) == 0 {
		return ""
	}
	return string(obj.GetOwnerReferences()[0].UID)
}
