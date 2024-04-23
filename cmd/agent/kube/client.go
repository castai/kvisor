package kube

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type kubernetesObject interface {
	runtime.Object
	metav1.Object
}

type Workload struct {
	UID        types.UID
	apiVersion string
	kind       string
	Name       string
}

type kubernetesObjectWithDelete struct {
	obj               kubernetesObject
	deletionTimestamp *time.Time
}

var workloadTypes = []schema.GroupKind{
	{Group: "apps", Kind: "Deployment"},
	{Group: "apps", Kind: "StatefulSet"},
	{Group: "apps", Kind: "DaemonSet"},
	{Group: "batch", Kind: "CronJob"},
}

type Client struct {
	log      *logging.Logger
	client   kubernetes.Interface
	nodeName string

	objects           map[types.UID]kubernetesObjectWithDelete
	objectWorkloadMap map[types.UID]Workload
	mu                sync.RWMutex

	gcInterval time.Duration
}

func NewClient(log *logging.Logger, client kubernetes.Interface, nodeName string) *Client {
	return &Client{
		log:    log,
		client: client,

		objects:           make(map[types.UID]kubernetesObjectWithDelete),
		objectWorkloadMap: make(map[types.UID]Workload),

		gcInterval: 1 * time.Minute,

		nodeName: nodeName,
	}
}

func (c *Client) Run(ctx context.Context) error {
	c.startInformers(ctx)

	return c.startGC(ctx)
}

func (c *Client) startInformers(ctx context.Context) {
	informersFactory := informers.NewSharedInformerFactory(c.client, 0)

	replicaSetInformer := informersFactory.Apps().V1().ReplicaSets().Informer()
	if err := replicaSetInformer.SetTransform(informerTransformer); err != nil {
		panic(err)
	}
	if _, err := replicaSetInformer.AddEventHandler(c.eventHandler()); err != nil {
		panic(err)
	}
	jobsInformer := informersFactory.Batch().V1().Jobs().Informer()
	if err := jobsInformer.SetTransform(informerTransformer); err != nil {
		panic(err)
	}
	if _, err := jobsInformer.AddEventHandler(c.eventHandler()); err != nil {
		panic(err)
	}

	informersFactory.Start(ctx.Done())
	informersFactory.WaitForCacheSync(ctx.Done())

	// We need to register pods informers later since they depend on deployments, daemon sets etc.
	podInformerFactory := informers.NewSharedInformerFactoryWithOptions(c.client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + c.nodeName
		}))

	podsInformer := podInformerFactory.Core().V1().Pods().Informer()
	if err := podsInformer.SetTransform(informerTransformer); err != nil {
		panic(err)
	}
	if _, err := podsInformer.AddEventHandler(c.eventHandler()); err != nil {
		panic(err)
	}

	podInformerFactory.Start(ctx.Done())
	podInformerFactory.WaitForCacheSync(ctx.Done())

	go func() {
		select {
		case <-ctx.Done():
			informersFactory.Shutdown()
			podInformerFactory.Shutdown()
		}
	}()
}

func (c *Client) startGC(ctx context.Context) error {
	t := time.NewTicker(c.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.runGC()
		}
	}
}

func (c *Client) runGC() {
	c.mu.Lock()
	defer c.mu.Unlock()

	deleteBefore := time.Now().UTC().Add(-c.gcInterval)
	var deletedObjects int

	for _, obj := range c.objects {
		if dts := obj.deletionTimestamp; dts != nil {
			ts := dts
			if ts.Before(deleteBefore) {
				delete(c.objects, obj.obj.GetUID())
				delete(c.objectWorkloadMap, obj.obj.GetUID())
				deletedObjects++
			}
		}
	}

	c.log.Debugf("kube watcher gc done, deleted_objects=%d", deletedObjects)
}

func (c *Client) addKubernetesObject(obj kubernetesObject) {
	c.mu.Lock()
	c.objects[obj.GetUID()] = kubernetesObjectWithDelete{
		obj: obj,
	}
	c.mu.Unlock()

	if pod, ok := obj.(*corev1.Pod); ok {
		workload, err := c.findWorkload(pod.UID)
		if err == nil && workload != nil {
			c.mu.Lock()
			c.objectWorkloadMap[pod.UID] = *workload
			c.mu.Unlock()
		}
	}
}

func (c *Client) deleteKubernetesObject(obj kubernetesObject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o, found := c.objects[obj.GetUID()]; found {
		o.deletionTimestamp = lo.ToPtr(time.Now().UTC())
	}
}

func (c *Client) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if kubeObj, ok := obj.(kubernetesObject); ok {
				c.addKubernetesObject(kubeObj)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {},
		DeleteFunc: func(obj interface{}) {
			if kubeObj, ok := obj.(kubernetesObject); ok {
				c.deleteKubernetesObject(kubeObj)
			}
		},
	}
}

var (
	ErrNoWorkloadFound = errors.New("no workload found")
)

func (c *Client) findWorkload(id types.UID) (*Workload, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	idsToCheck := []types.UID{id}
	var lastCheckedObj kubernetesObject

	for len(idsToCheck) > 0 {
		currentID := idsToCheck[0]
		idsToCheck = idsToCheck[1:]

		obj, found := c.objects[currentID]
		if !found {
			continue
		}

		lastCheckedObj = obj.obj
		gvk := obj.obj.GetObjectKind().GroupVersionKind()

		if isWorkloadType(gvk.Group, gvk.Kind) {
			return &Workload{
				UID:        obj.obj.GetUID(),
				apiVersion: gvk.GroupVersion().String(),
				kind:       gvk.Kind,
				Name:       obj.obj.GetName(),
			}, nil
		}

		nextIDs, workload := getOwnerIDsOrWorkload(obj.obj)
		if workload != nil {
			return workload, nil
		}

		idsToCheck = append(idsToCheck, nextIDs...)
	}

	if lastCheckedObj != nil {
		gvk := lastCheckedObj.GetObjectKind().GroupVersionKind()

		// In order to avoid confusion, pods cannot be workloads.
		if gvk.Kind == "Pod" {
			return nil, ErrNoWorkloadFound
		}

		return &Workload{
			UID:        lastCheckedObj.GetUID(),
			apiVersion: gvk.GroupVersion().String(),
			kind:       gvk.Kind,
			Name:       lastCheckedObj.GetName(),
		}, nil
	}

	return nil, ErrNoWorkloadFound
}

func isWorkloadType(group, kind string) bool {
	for _, gk := range workloadTypes {
		if gk.Kind == kind && gk.Group == group {
			return true
		}
	}
	return false
}

func getOwnerIDsOrWorkload(obj kubernetesObject) ([]types.UID, *Workload) {
	owners := obj.GetOwnerReferences()
	var ownerIDs []types.UID

	for _, or := range owners {
		groupVersion, err := schema.ParseGroupVersion(or.APIVersion)
		if err != nil {
			continue
		}
		if isWorkloadType(groupVersion.Group, or.Kind) {
			return nil, &Workload{
				UID:        or.UID,
				apiVersion: or.APIVersion,
				kind:       or.Kind,
				Name:       or.Name,
			}
		}

		ownerIDs = append(ownerIDs, or.UID)
	}

	return ownerIDs, nil
}

func (c *Client) GetWorkloadFor(id types.UID) (Workload, error) {
	workload, found := c.objectWorkloadMap[id]
	if found {
		return workload, nil
	}

	return Workload{}, ErrNoWorkloadFound
}
