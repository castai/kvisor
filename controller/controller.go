package controller

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	batch "google.golang.org/genproto/googleapis/cloud/batch/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
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
		reflect.TypeOf(&batch.Job{}):                 f.Batch().V1().Jobs().Informer(),
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

	<-ctx.Done()

	return c.shutdownSubscribers()
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

func (c *Controller) shutdownSubscribers() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	wg := sync.WaitGroup{}
	doneChan := make(chan struct{})

	for _, subscriber := range c.subscribers {
		wg.Add(1)
		go func(subscriber ObjectSubscriber) {
			defer wg.Done()
			if err := subscriber.Shutdown(shutdownCtx); err != nil {
				c.log.Error(err)
			}
		}(subscriber)
	}

	go func() {
		wg.Wait()
		doneChan <- struct{}{}
	}()

	select {
	case <-doneChan:
		return nil
	case <-shutdownCtx.Done():
		return fmt.Errorf("shutdown timed out")
	}
}
