package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/castai/sec-agent/version"
)

func New(
	log logrus.FieldLogger,
	f informers.SharedInformerFactory,
	itemHandlers []ItemHandler,
	v version.Interface,
) *Controller {
	typeInformerMap := map[reflect.Type]cache.SharedInformer{
		reflect.TypeOf(&corev1.Node{}):               f.Core().V1().Nodes().Informer(),
		reflect.TypeOf(&corev1.Pod{}):                f.Core().V1().Pods().Informer(),
		reflect.TypeOf(&corev1.Namespace{}):          f.Core().V1().Namespaces().Informer(),
		reflect.TypeOf(&corev1.Service{}):            f.Core().V1().Services().Informer(),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}): f.Rbac().V1().ClusterRoleBindings().Informer(),
		reflect.TypeOf(&appsv1.Deployment{}):         f.Apps().V1().Deployments().Informer(),
		reflect.TypeOf(&appsv1.DaemonSet{}):          f.Apps().V1().DaemonSets().Informer(),
		reflect.TypeOf(&appsv1.StatefulSet{}):        f.Apps().V1().StatefulSets().Informer(),
		// TODO: Add jobs, cronjobs and other resources for kubelinter.
	}

	c := &Controller{
		log:             log,
		informerFactory: f,
		itemHandlers:    itemHandlers,
		queue:           workqueue.NewNamed("castai-sec-agent"),
		informers:       typeInformerMap,
	}
	c.registerEventHandlers()

	return c
}

type Controller struct {
	log             logrus.FieldLogger
	informerFactory informers.SharedInformerFactory
	itemHandlers    []ItemHandler
	queue           workqueue.Interface
	informers       map[reflect.Type]cache.SharedInformer
}

func (c *Controller) Run(ctx context.Context) error {
	defer c.queue.ShutDown()

	c.informerFactory.Start(ctx.Done())

	syncs := make([]cache.InformerSynced, 0, len(c.informers))
	for _, informer := range c.informers {
		syncs = append(syncs, informer.HasSynced)
	}

	waitStartedAt := time.Now()
	c.log.Infof("waiting for %d informers cache to sync", len(syncs))
	if !cache.WaitForCacheSync(ctx.Done(), syncs...) {
		c.log.Error("failed to sync")
		return fmt.Errorf("failed to wait for cache sync")
	}
	c.log.Infof("informers cache synced after %v", time.Since(waitStartedAt))

	go func() {
		<-ctx.Done()
		c.queue.ShutDown()
	}()

	c.pollQueueUntilShutdown()

	return nil
}

func (c *Controller) pollQueueUntilShutdown() {
	for {
		i, shutdown := c.queue.Get()
		if shutdown {
			return
		}
		c.processItem(i)
	}
}

func (c *Controller) processItem(i interface{}) {
	defer c.queue.Done(i)

	item, ok := i.(*Item)
	if !ok {
		c.log.Errorf("queue Item is not of type *Item")
	}
	c.log.Infof("processing item %v: %s", item.ObjectKey(), item.Event)

	for _, handler := range c.itemHandlers {
		handler.Handle(item)
	}
}

func (c *Controller) registerEventHandlers() {
	for typ, informer := range c.informers {
		typ := typ
		informer := informer
		log := c.log.WithField("informer", typ.String())
		h := c.createEventHandlers(log, typ)
		informer.AddEventHandler(h)
	}
}

func (c *Controller) createEventHandlers(log logrus.FieldLogger, typ reflect.Type) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.deletedUnknownHandler(log, EventAdd, obj, func(log logrus.FieldLogger, e Event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.deletedUnknownHandler(log, EventUpdate, newObj, func(log logrus.FieldLogger, e Event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
		DeleteFunc: func(obj interface{}) {
			c.deletedUnknownHandler(log, EventDelete, obj, func(log logrus.FieldLogger, e Event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
	}
}

type handlerFunc func(log logrus.FieldLogger, event Event, obj interface{})

// deletedUnknownHandler is used to handle cache.DeletedFinalStateUnknown where an Object was deleted but the watch
// deletion Event was missed while disconnected from the api-server.
func (c *Controller) deletedUnknownHandler(log logrus.FieldLogger, e Event, obj interface{}, next handlerFunc) {
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		next(log, EventDelete, deleted.Obj)
	} else {
		next(log, e, obj)
	}
}

// genericHandler is used to add an Object to the queue.
func (c *Controller) genericHandler(
	log logrus.FieldLogger,
	expected reflect.Type,
	e Event,
	obj interface{},
) {
	if reflect.TypeOf(obj) != expected {
		log.Errorf("expected to get %v but got %T", expected, obj)
		return
	}

	// Map missing metadata since kubernetes client removes object kind and api version information.
	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := obj.(type) {
	case *appsv1.Deployment:
		o.Kind = "Deployment"
		o.APIVersion = appsV1
	case *appsv1.StatefulSet:
		o.Kind = "StatefulSet"
		o.APIVersion = appsV1
	case *appsv1.DaemonSet:
		o.Kind = "DaemonSet"
		o.APIVersion = appsV1
	case *corev1.Node:
		o.Kind = "Node"
		o.APIVersion = v1
	case *corev1.Namespace:
		o.Kind = "Namespace"
		o.APIVersion = v1
	case *corev1.Service:
		o.Kind = "Service"
		o.APIVersion = v1
	case *corev1.Pod:
		// Do not process not static pods.
		if !isStaticPod(o) {
			return
		}
	case *rbacv1.ClusterRoleBinding:
		o.Kind = "ClusterRoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	default:
		log.Error("object is not handled")
		return
	}

	c.queue.Add(&Item{
		Obj:   obj.(Object),
		Event: e,
	})
}

func isStaticPod(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" {
		return false
	}
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}
