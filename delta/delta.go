package delta

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
)

// newDelta initializes the delta struct which is used to collect cluster deltas, debounce them and map to CAST AI
// requests.
func newDelta(log logrus.FieldLogger, logLevel logrus.Level, provider SnapshotProvider) *delta {
	return &delta{
		log:      log,
		logLevel: logLevel,
		snapshot: provider,
		cache:    map[string]castai.DeltaItem{},
		skippers: []skipper{
			nonStaticOrStandalonePodsSkipper(),
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

// nonStaticPodsSkipper skips non static and not standalone pods pods.
func nonStaticOrStandalonePodsSkipper() skipper {
	return func(obj object) bool {
		return getObjectKind(obj) == kindPod && !isStaticOrStandalonePod(obj)
	}
}

// cronJobOwnerJobsSkipper skips jobs which are created by cron jobs.
func cronJobOwnerJobsSkipper() skipper {
	return func(obj object) bool {
		return getObjectKind(obj) == kindJob && isCronJobOwnedJob(obj)
	}
}

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
		ObjectCreatedAt:  obj.GetCreationTimestamp().UTC(),
	}

	d.snapshot.append(d.cache[key])
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

func isStaticOrStandalonePod(p metav1.Object) bool {
	ctrl := metav1.GetControllerOf(p)
	return ctrl == nil || ctrl.Kind == kindNode
}

func isCronJobOwnedJob(p metav1.Object) bool {
	ctrl := metav1.GetControllerOf(p)
	return ctrl != nil && ctrl.Kind == kindCronJob
}

func getObjectKind(obj object) string {
	return obj.GetObjectKind().GroupVersionKind().Kind
}
