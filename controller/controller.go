package controller

import (
	"context"
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

func New(
	log logrus.FieldLogger,
	f informers.SharedInformerFactory,
	subscribers []ObjectSubscriber,
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
		reflect.TypeOf(&batchv1.Job{}):               f.Batch().V1().Jobs().Informer(),
	}

	c := &Controller{
		log:             log,
		informerFactory: f,
		informers:       typeInformerMap,
		subscribers:     subscribers,
	}

	for typ, informer := range c.informers {
		for _, subscriber := range c.subscribers {
			if subscriber.Supports(typ) {
				informer.AddEventHandler(c.wrapHandler(subscriber))
			}
		}
	}

	return c
}

type Controller struct {
	log             logrus.FieldLogger
	informerFactory informers.SharedInformerFactory
	informers       map[reflect.Type]cache.SharedInformer
	subscribers     []ObjectSubscriber
}

func (c *Controller) Run(ctx context.Context) error {
	c.informerFactory.Start(ctx.Done())

	errGroup, ctx := errgroup.WithContext(ctx)
	for _, subscriber := range c.subscribers {
		func(ctx context.Context, subscriber ObjectSubscriber) {
			errGroup.Go(func() error {
				return c.runSubscriber(ctx, subscriber)
			})
		}(ctx, subscriber)
	}

	return errGroup.Wait()
}

func (c *Controller) runSubscriber(ctx context.Context, subscriber ObjectSubscriber) error {
	requiredInformerTypes := subscriber.RequiredInformers()
	syncs := make([]cache.InformerSynced, 0, len(requiredInformerTypes))

	for _, typ := range requiredInformerTypes {
		informer, ok := c.informers[typ]
		if !ok {
			return fmt.Errorf("no informer for type %q", typ.Name())
		}
		syncs = append(syncs, informer.HasSynced)
	}

	if len(syncs) > 0 && !cache.WaitForCacheSync(ctx.Done(), syncs...) {
		return fmt.Errorf("failed to wait for cache sync")
	}

	return subscriber.Run(ctx)
}

func (c *Controller) wrapHandler(handler cache.ResourceEventHandler) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			deleted, ok := obj.(cache.DeletedFinalStateUnknown)
			if ok {
				handler.OnDelete(deleted)
			} else {
				handler.OnAdd(obj)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			deleted, ok := newObj.(cache.DeletedFinalStateUnknown)
			if ok {
				handler.OnDelete(deleted)
			} else {
				handler.OnUpdate(oldObj, newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			handler.OnDelete(obj)
		},
	}
}
