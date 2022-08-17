package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/castai/sec-agent/version"
)

func New(log logrus.FieldLogger, f informers.SharedInformerFactory, v version.Interface) *Controller {
	typeInformerMap := map[reflect.Type]cache.SharedInformer{
		reflect.TypeOf(&corev1.Node{}):                  f.Core().V1().Nodes().Informer(),
		reflect.TypeOf(&corev1.PersistentVolume{}):      f.Core().V1().PersistentVolumes().Informer(),
		reflect.TypeOf(&corev1.PersistentVolumeClaim{}): f.Core().V1().PersistentVolumeClaims().Informer(),
		reflect.TypeOf(&corev1.Namespace{}):             f.Core().V1().Namespaces().Informer(),
		reflect.TypeOf(&corev1.Service{}):               f.Core().V1().Services().Informer(),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}):    f.Rbac().V1().ClusterRoleBindings().Informer(),
		reflect.TypeOf(&rbacv1.RoleBinding{}):           f.Rbac().V1().RoleBindings().Informer(),
		reflect.TypeOf(&appsv1.Deployment{}):            f.Apps().V1().Deployments().Informer(),
		reflect.TypeOf(&appsv1.DaemonSet{}):             f.Apps().V1().DaemonSets().Informer(),
		reflect.TypeOf(&appsv1.StatefulSet{}):           f.Apps().V1().StatefulSets().Informer(),
		reflect.TypeOf(&storagev1.StorageClass{}):       f.Storage().V1().StorageClasses().Informer(),
		// reflect.TypeOf(&batchv1.CronJob{}):              f.Batch().V1().CronJobs().Informer(), // TODO: Add jobs.
	}

	//if v.MinorInt() >= 17 {
	//	typeInformerMap[reflect.TypeOf(&storagev1.CSINode{})] = f.Storage().V1().CSINodes().Informer()
	//}
	//
	//if v.MinorInt() >= 18 {
	//	typeInformerMap[reflect.TypeOf(&autoscalingv1.HorizontalPodAutoscaler{})] =
	//		f.Autoscaling().V1().HorizontalPodAutoscalers().Informer()
	//}

	c := &Controller{
		log:             log,
		informerFactory: f,
		queue:           workqueue.NewNamed("castai-sec-agent"),
		informers:       typeInformerMap,
	}
	c.registerEventHandlers()

	return c
}

type Controller struct {
	log             logrus.FieldLogger
	informerFactory informers.SharedInformerFactory
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

	item, ok := i.(*item)
	if !ok {
		c.log.Errorf("queue item is not of type *item")
	}

	c.log.Infof("processing item %v: %s", reflect.TypeOf(item.obj), item.event)
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
			c.deletedUnknownHandler(log, eventAdd, obj, func(log logrus.FieldLogger, e event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.deletedUnknownHandler(log, eventUpdate, newObj, func(log logrus.FieldLogger, e event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
		DeleteFunc: func(obj interface{}) {
			c.deletedUnknownHandler(log, eventDelete, obj, func(log logrus.FieldLogger, e event, obj interface{}) {
				c.genericHandler(log, typ, e, obj)
			})
		},
	}
}

type handlerFunc func(log logrus.FieldLogger, event event, obj interface{})

// deletedUnknownHandler is used to handle cache.DeletedFinalStateUnknown where an object was deleted but the watch
// deletion event was missed while disconnected from the api-server.
func (c *Controller) deletedUnknownHandler(log logrus.FieldLogger, e event, obj interface{}, next handlerFunc) {
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		next(log, eventDelete, deleted.Obj)
	} else {
		next(log, e, obj)
	}
}

// genericHandler is used to add an object to the queue.
func (c *Controller) genericHandler(
	log logrus.FieldLogger,
	expected reflect.Type,
	e event,
	obj interface{},
) {
	if reflect.TypeOf(obj) != expected {
		log.Errorf("expected to get %v but got %T", expected, obj)
		return
	}

	c.queue.Add(&item{
		obj:   obj.(object),
		event: e,
	})
}
