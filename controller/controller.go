package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/castai/sec-agent/version"
)

func New(
	log logrus.FieldLogger,
	f informers.SharedInformerFactory,
	subscribers []ObjectSubscriber,
	k8sVersion version.Version,
) *Controller {
	typeInformerMap := map[reflect.Type]cache.SharedInformer{
		reflect.TypeOf(&corev1.Node{}):                f.Core().V1().Nodes().Informer(),
		reflect.TypeOf(&corev1.Pod{}):                 f.Core().V1().Pods().Informer(),
		reflect.TypeOf(&corev1.Namespace{}):           f.Core().V1().Namespaces().Informer(),
		reflect.TypeOf(&corev1.Service{}):             f.Core().V1().Services().Informer(),
		reflect.TypeOf(&appsv1.Deployment{}):          f.Apps().V1().Deployments().Informer(),
		reflect.TypeOf(&appsv1.DaemonSet{}):           f.Apps().V1().DaemonSets().Informer(),
		reflect.TypeOf(&appsv1.ReplicaSet{}):          f.Apps().V1().ReplicaSets().Informer(),
		reflect.TypeOf(&appsv1.StatefulSet{}):         f.Apps().V1().StatefulSets().Informer(),
		reflect.TypeOf(&batchv1.Job{}):                f.Batch().V1().Jobs().Informer(),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}):  f.Rbac().V1().ClusterRoleBindings().Informer(),
		reflect.TypeOf(&rbacv1.RoleBinding{}):         f.Rbac().V1().RoleBindings().Informer(),
		reflect.TypeOf(&rbacv1.ClusterRole{}):         f.Rbac().V1().ClusterRoles().Informer(),
		reflect.TypeOf(&rbacv1.Role{}):                f.Rbac().V1().Roles().Informer(),
		reflect.TypeOf(&networkingv1.NetworkPolicy{}): f.Networking().V1().NetworkPolicies().Informer(),
		reflect.TypeOf(&networkingv1.Ingress{}):       f.Networking().V1().Ingresses().Informer(),
	}

	if k8sVersion.MinorInt >= 21 {
		typeInformerMap[reflect.TypeOf(&batchv1.CronJob{})] = f.Batch().V1().CronJobs().Informer()
	} else {
		typeInformerMap[reflect.TypeOf(&batchv1beta1.CronJob{})] = f.Batch().V1beta1().CronJobs().Informer()
	}

	c := &Controller{
		log:             log,
		k8sVersion:      k8sVersion,
		informerFactory: f,
		informers:       typeInformerMap,
		subscribers:     subscribers,
		objectHashes:    map[string]struct{}{},
	}
	return c
}

type Controller struct {
	log             logrus.FieldLogger
	k8sVersion      version.Version
	informerFactory informers.SharedInformerFactory
	informers       map[reflect.Type]cache.SharedInformer
	subscribers     []ObjectSubscriber

	// Due to bug in k8s we need to track if obect actually changed. See https://github.com/kubernetes/kubernetes/pull/106388
	objectHashMu sync.Mutex
	objectHashes map[string]struct{}
}

func (c *Controller) Run(ctx context.Context) error {
	for typ, informer := range c.informers {
		if err := informer.SetTransform(c.transformFunc); err != nil {
			return err
		}
		informer.AddEventHandler(c.eventsHandler(ctx, typ))
	}
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
			return fmt.Errorf("no informer for type %v", typ)
		}
		syncs = append(syncs, informer.HasSynced)
	}

	if len(syncs) > 0 && !cache.WaitForCacheSync(ctx.Done(), syncs...) {
		return fmt.Errorf("failed to wait for cache sync")
	}

	return subscriber.Run(ctx)
}

func (c *Controller) transformFunc(i any) (any, error) {
	obj := i.(Object)
	// Add missing metadata which is removed by k8s.
	addObjectMeta(obj)
	// Remove manged fields since we don't need them. This should decrease memory usage.
	obj.SetManagedFields(nil)
	if _, ok := obj.(*appsv1.DaemonSet); ok {
		// Remove this fields for ds to fix https://github.com/kubernetes/kubernetes/pull/106388 by custom hashing.
		obj.SetResourceVersion("")
	}

	return obj, nil
}

func (c *Controller) eventsHandler(ctx context.Context, typ reflect.Type) cache.ResourceEventHandler {
	subscribers := lo.Filter(c.subscribers, func(v ObjectSubscriber, _ int) bool {
		for _, subType := range v.RequiredInformers() {
			if subType == typ {
				return true
			}
		}
		return false
	})
	subs := lo.Map(subscribers, func(sub ObjectSubscriber, i int) subChannel {
		return subChannel{
			handler: sub,
			events:  make(chan event, 10),
		}
	})

	// Create go routine for each subscription since we don't want to block event handlers.
	for _, sub := range subs {
		sub := sub
		go func() {
			for {
				select {
				case ev := <-sub.events:
					switch ev.eventType {
					case eventTypeAdd:
						sub.handler.OnAdd(ev.obj)
					case eventTypeUpdate:
						sub.handler.OnUpdate(ev.obj)
					case eventTypeDelete:
						sub.handler.OnDelete(ev.obj)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.notifySubscribers(obj, eventTypeAdd, subs)
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.notifySubscribers(newObj, eventTypeUpdate, subs)
		},
		DeleteFunc: func(obj any) {
			c.notifySubscribers(obj, eventTypeDelete, subs)
		},
	}
}

type eventType string

const (
	eventTypeAdd    eventType = "add"
	eventTypeUpdate eventType = "update"
	eventTypeDelete eventType = "delete"
)

type event struct {
	eventType eventType
	obj       Object
}

type subChannel struct {
	handler ResourceEventHandler
	events  chan event
}

func (c *Controller) notifySubscribers(obj any, eventType eventType, subs []subChannel) {
	var actualObj Object
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj, ok := deleted.Obj.(Object)
		if !ok {
			return
		}
		actualObj = obj
		eventType = eventTypeDelete
	} else {
		obj, ok := obj.(Object)
		if !ok {
			return
		}
		actualObj = obj
	}

	var objectHash string
	if c.k8sVersion.MinorInt < 25 && actualObj.GetObjectKind().GroupVersionKind().Kind == "DaemonSet" {
		var err error
		objectHash, err = ObjectHash(actualObj)
		if err != nil {
			c.log.Error(err)
			return
		}
	}

	if c.shouldSkipNotify(objectHash, eventType) {
		return
	}

	// Notify all subscribers.
	for _, sub := range subs {
		sub.events <- event{
			eventType: eventType,
			obj:       actualObj,
		}
	}

	// Store object hash which is used to skip notifying subscribers if object haven't changed.
	if objectHash != "" {
		c.saveObjectHash(objectHash, eventType)
	}
}

func (c *Controller) shouldSkipNotify(objectHash string, eventType eventType) bool {
	// Do not skip notify for add and update.
	if eventType == eventTypeAdd || eventType == eventTypeDelete {
		return false
	}

	c.objectHashMu.Lock()
	defer c.objectHashMu.Unlock()

	_, alreadyNotified := c.objectHashes[objectHash]
	return alreadyNotified
}

func (c *Controller) saveObjectHash(objectHash string, eventType eventType) {
	c.objectHashMu.Lock()
	defer c.objectHashMu.Unlock()

	if eventType == eventTypeDelete {
		delete(c.objectHashes, objectHash)
	} else {
		c.objectHashes[objectHash] = struct{}{}
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
	case *rbacv1.RoleBinding:
		o.Kind = "RoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *rbacv1.ClusterRole:
		o.Kind = "ClusterRole"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *rbacv1.Role:
		o.Kind = "Role"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *batchv1.Job:
		o.Kind = "Job"
		o.APIVersion = "batch/v1"
	case *batchv1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1"
	case *batchv1beta1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1beta1"
	case *networkingv1.Ingress:
		o.Kind = "Ingress"
		o.APIVersion = "networking/v1"
	case *networkingv1.NetworkPolicy:
		o.Kind = "NetworkPolicy"
		o.APIVersion = "networking/v1"
	}
}
