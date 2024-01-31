package delta

import (
	json "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/kube"
)

type podOwnerGetter interface {
	GetPodOwnerID(pod *corev1.Pod) string
}

// newDelta initializes the delta struct which is used to collect cluster deltas, debounce them and map to CAST AI
// requests.
func newDelta(log logrus.FieldLogger, podOwnerGetter podOwnerGetter, logLevel logrus.Level, provider SnapshotProvider) *delta {
	return &delta{
		log:            log,
		logLevel:       logLevel,
		snapshot:       provider,
		cache:          map[string]castai.DeltaItem{},
		skippers:       []skipper{},
		podOwnerGetter: podOwnerGetter,
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
	log            logrus.FieldLogger
	logLevel       logrus.Level
	snapshot       SnapshotProvider
	cache          map[string]castai.DeltaItem
	skippers       []skipper
	podOwnerGetter podOwnerGetter
}

// add will add an item to the delta cache. It will debounce the objects.
func (d *delta) add(event kube.Event, obj object) {
	for _, skipper := range d.skippers {
		if skipper(obj) {
			return
		}
	}

	key := string(obj.GetUID())
	gvr := obj.GetObjectKind().GroupVersionKind()

	deltaItem := castai.DeltaItem{
		Event:             toCASTAIEvent(event),
		ObjectUID:         string(obj.GetUID()),
		ObjectName:        obj.GetName(),
		ObjectNamespace:   obj.GetNamespace(),
		ObjectKind:        gvr.Kind,
		ObjectAPIVersion:  gvr.GroupVersion().String(),
		ObjectCreatedAt:   obj.GetCreationTimestamp().UTC(),
		ObjectOwnerUID:    d.getOwnerUID(obj),
		ObjectLabels:      obj.GetLabels(),
		ObjectAnnotations: getAnnotations(obj),
	}

	containers, status, err := getContainersAndStatus(obj)
	if err != nil {
		d.log.Errorf("getting object status json: %v", err)
	}
	if len(status) > 0 {
		deltaItem.ObjectStatus = status
	}
	if len(containers) > 0 {
		deltaItem.ObjectContainers = containers
	}

	spec, err := getObjectSpec(obj)
	if err != nil {
		d.log.Errorf("getting object spec json: %v", err)
	}
	if len(spec) > 0 {
		deltaItem.ObjectSpec = spec
	}

	d.cache[key] = deltaItem
	d.snapshot.append(deltaItem)
}

func getAnnotations(obj object) map[string]string {
	switch v := obj.(type) {
	case *corev1.Service, *networkingv1.Ingress:
		return v.GetAnnotations()
	default:
		return nil
	}
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

func toCASTAIEvent(e kube.Event) castai.EventType {
	switch e {
	case kube.EventAdd:
		return castai.EventAdd
	case kube.EventUpdate:
		return castai.EventUpdate
	case kube.EventDelete:
		return castai.EventDelete
	}
	return ""
}

func (d *delta) getOwnerUID(obj kube.Object) string {
	switch v := obj.(type) {
	case *corev1.Pod:
		return d.podOwnerGetter.GetPodOwnerID(v)
	}

	if len(obj.GetOwnerReferences()) == 0 {
		return ""
	}
	return string(obj.GetOwnerReferences()[0].UID)
}

func getContainersAndStatus(obj kube.Object) ([]castai.Container, []byte, error) {
	var containers []corev1.Container
	appendContainers := func(podSpec corev1.PodSpec) {
		containers = append(containers, podSpec.Containers...)
		containers = append(containers, podSpec.InitContainers...)
	}
	var st []byte
	var err error
	switch v := obj.(type) {
	case *batchv1.Job:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec.Template.Spec)
	case *batchv1.CronJob:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec.JobTemplate.Spec.Template.Spec)
	case *corev1.Pod:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec)
	case *appsv1.Deployment:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec.Template.Spec)
	case *appsv1.StatefulSet:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec.Template.Spec)
	case *appsv1.DaemonSet:
		st, err = json.Marshal(v.Status)
		appendContainers(v.Spec.Template.Spec)
	case *networkingv1.Ingress:
		st, err = json.Marshal(v.Status)
	case *corev1.Service:
		st, err = json.Marshal(v.Status)
	case *corev1.Node:
		st, err = json.Marshal(v.Status)
	default:
		return nil, nil, nil
	}

	res := make([]castai.Container, len(containers))
	for i, cont := range containers {
		res[i] = castai.Container{
			Name:      cont.Name,
			ImageName: cont.Image,
		}
	}
	return res, st, err
}

func getObjectSpec(obj object) ([]byte, error) {
	switch v := obj.(type) {
	case *networkingv1.Ingress:
		return json.Marshal(v.Spec)
	case *corev1.Service:
		return json.Marshal(v.Spec)
	case *appsv1.Deployment:
		return json.Marshal(v.Spec)
	case *appsv1.StatefulSet:
		return json.Marshal(v.Spec)
	case *appsv1.DaemonSet:
		return json.Marshal(v.Spec)
	default:
		return nil, nil
	}
}
