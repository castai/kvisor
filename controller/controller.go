package controller

import (
	"context"
	"errors"
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
				err := c.runSubscriber(ctx, subscriber)
				if errors.Is(err, context.Canceled) {
					return nil
				}

				return err
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

func (c *Controller) wrapHandler(handler ResourceEventHandler) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			deletedUnknownHandler(obj, handler.OnDelete, handler.OnAdd)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			deletedUnknownHandler(newObj, handler.OnDelete, handler.OnUpdate)
		},
		DeleteFunc: func(obj interface{}) {
			deletedUnknownHandler(obj, handler.OnDelete, handler.OnDelete)
		},
	}
}

type handlerFunc func(obj Object)

// deletedUnknownHandler is used to handle cache.DeletedFinalStateUnknown where an Object was deleted but the watch
// deletion Event was missed while disconnected from the api-server.
func deletedUnknownHandler(obj interface{}, deletedHandler, nextHandler handlerFunc) {
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj, ok := deleted.Obj.(Object)
		if !ok {
			return
		}
		addObjectMeta(obj)
		deletedHandler(obj)
	} else {
		obj, ok := obj.(Object)
		if !ok {
			return
		}
		addObjectMeta(obj)
		nextHandler(obj)
	}
}

// addObjectMeta adds missing metadata since kubernetes client removes object kind and api version information.
func addObjectMeta(o Object) {
	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := o.(type) {
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
		o.Kind = "Pod"
		o.APIVersion = v1
	case *rbacv1.ClusterRoleBinding:
		o.Kind = "ClusterRoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	}
}
