package delta

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
)

// newDelta initializes the delta struct which is used to collect cluster deltas, debounce them and map to CASTAI
// requests.
func newDelta(log logrus.FieldLogger, logLevel logrus.Level) *delta {
	return &delta{
		log:          log,
		logLevel:     logLevel,
		fullSnapshot: true,
		cache:        map[string]castai.DeltaItem{},
		skippers: []skipper{
			nonStaticPodsSkipper(),
			cronJobOwnerJobsSkipper(),
		},
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

// nonStaticPodsSkipper skips non static pods.
func nonStaticPodsSkipper() skipper {
	return func(obj object) bool {
		return getObjectKind(obj) == kindPod && !isStaticPod(obj)
	}
}

// cronJobOwnerJobsSkipper skips jobs which are created by cron jobs.
func cronJobOwnerJobsSkipper() skipper {
	return func(obj object) bool {
		return getObjectKind(obj) == kindJob && isCronJobOwnedJob(obj)
	}
}

// delta is used to colelct cluster deltas, debounce them and map to CASTAI requests. It holds a cache of queue items
// which is referenced any time a new item is added to debounce the items.
type delta struct {
	log          logrus.FieldLogger
	logLevel     logrus.Level
	fullSnapshot bool
	cache        map[string]castai.DeltaItem
	skippers     []skipper
}

// add will add an item to the delta cache. It will debounce the objects.
func (d *delta) add(event controller.Event, obj object) {
	for _, skipper := range d.skippers {
		if skipper(obj) {
			return
		}
	}

	key := string(obj.GetUID())
	gvr := obj.GetObjectKind().GroupVersionKind()
	d.log.Debugf("add delta, event=%s, gvr=%s, ns=%s, name=%s", event, gvr.String(), obj.GetNamespace(), obj.GetName())

	d.cache[key] = castai.DeltaItem{
		Event:            toCASTAIEvent(event),
		ObjectUID:        string(obj.GetUID()),
		ObjectName:       obj.GetName(),
		ObjectNamespace:  obj.GetNamespace(),
		ObjectKind:       gvr.Kind,
		ObjectAPIVersion: gvr.GroupVersion().String(),
	}
}

// clear resets the delta cache and sets fullSnapshot to false. Should be called after toCASTAIRequest is successfully
// delivered.
func (d *delta) clear() {
	d.fullSnapshot = false
	d.cache = map[string]castai.DeltaItem{}
}

// toCASTAIRequest maps the collected delta cache to the castai.Delta type.
func (d *delta) toCASTAIRequest() *castai.Delta {
	return &castai.Delta{
		FullSnapshot: d.fullSnapshot,
		Items:        lo.Values(d.cache),
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

func isStaticPod(p metav1.Object) bool {
	ctrl := metav1.GetControllerOf(p)
	return ctrl != nil && ctrl.Kind == kindNode
}

func isCronJobOwnedJob(p metav1.Object) bool {
	ctrl := metav1.GetControllerOf(p)
	return ctrl != nil && ctrl.Kind == kindCronJob
}

func getObjectKind(ojb object) string {
	return ojb.GetObjectKind().GroupVersionKind().Kind
}
