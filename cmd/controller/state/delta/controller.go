package delta

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

type castaiClient interface {
	KubernetesDeltaIngest(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient, error)
}

type kubeClient interface {
	GetOwnerUID(obj kube.Object) string
}

type Config struct {
	Enabled       bool
	Interval      time.Duration `validate:"required"`
	InitialDeltay time.Duration
}

func NewController(
	log *logging.Logger,
	cfg Config,
	castaiClient castaiClient,
	kubeClient kubeClient,
) *Controller {
	return &Controller{
		log:                   log.WithField("component", "delta"),
		cfg:                   cfg,
		castaiClient:          castaiClient,
		kubeClient:            kubeClient,
		pendingItems:          map[string]deltaItem{},
		deltaItemSendMaxTries: 3,
	}
}

type Controller struct {
	log          *logging.Logger
	cfg          Config
	castaiClient castaiClient
	kubeClient   kubeClient

	pendingItems          map[string]deltaItem
	deltasMu              sync.Mutex
	deltaItemSendMaxTries int
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	// Wait for initial deltas sync before starting deltas send loop.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.cfg.InitialDeltay):
	}

	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()

	firstDeltaReport := true

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.sendDeltas(ctx, firstDeltaReport)
			if firstDeltaReport {
				firstDeltaReport = false
			}
		}
	}
}

func (c *Controller) sendDeltas(ctx context.Context, firstDeltaReport bool) {
	pendingDeltas := c.popPendingItems()
	if len(pendingDeltas) == 0 {
		return
	}
	start := time.Now()

	// Cancel context to close stream after deltas are sent.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	deltaID := uuid.NewString()
	meta := []string{
		"x-delta-id", deltaID,
	}
	if firstDeltaReport {
		meta = append(meta, "x-delta-full-snapshot", "true")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, meta...)
	deltaStream, err := c.castaiClient.KubernetesDeltaIngest(ctx, grpc.UseCompressor(gzip.Name))
	if err != nil && !errors.Is(err, context.Canceled) {
		c.log.Warnf("creating delta upload stream: %v", err)
		return
	}
	defer func() {
		_ = deltaStream.CloseSend()
	}()

	var lastSentItemIndex int
	for _, item := range pendingDeltas {
		pbItem := c.toCastaiDelta(item)
		if err := c.sendDeltaItem(deltaStream, pbItem); err != nil {
			c.log.Warnf("sending delta item: %v", err)
			// Return any remaining items back to pending list.
			c.upsertPendingItems(pendingDeltas[lastSentItemIndex:])
			return
		}
		lastSentItemIndex++
	}
	c.log.Infof("sent deltas, id=%v, count=%d/%d, duration=%v", deltaID, len(pendingDeltas), lastSentItemIndex+1, time.Since(start))
}

func (c *Controller) sendDeltaItem(stream castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient, item *castaipb.KubernetesDeltaItem) error {
	for i := 0; i < c.deltaItemSendMaxTries; i++ {
		if err := stream.Send(item); err != nil {
			// Do not retry EOF. Stream is closed by server.
			if errors.Is(err, io.EOF) {
				return err
			}
			c.log.Warnf("sending delta item: %v", err)
			continue
		}
		if _, err := stream.Recv(); err != nil {
			// Do not retry EOF. Stream is closed by server.
			if errors.Is(err, io.EOF) {
				return err
			}
			c.log.Warnf("receiving delta ack: %v", err)
			continue
		}
		return nil
	}
	return errors.New("sending delta item failed after max tries")
}

func (c *Controller) recordDeltaEvent(action castaipb.KubernetesDeltaItemEvent, obj kube.Object) {
	c.deltasMu.Lock()
	defer c.deltasMu.Unlock()

	c.pendingItems[string(obj.GetUID())] = deltaItem{
		object: obj,
		action: action,
	}
}

func (c *Controller) OnAdd(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_ADD, obj)
}

func (c *Controller) OnDelete(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_REMOVE, obj)
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_UPDATE, obj)
}

func (c *Controller) popPendingItems() []deltaItem {
	c.deltasMu.Lock()
	defer c.deltasMu.Unlock()

	values := lo.Values(c.pendingItems)
	c.pendingItems = map[string]deltaItem{}

	return values
}

func (c *Controller) upsertPendingItems(items []deltaItem) {
	c.deltasMu.Lock()
	defer c.deltasMu.Unlock()

	for _, item := range items {
		if v, ok := c.pendingItems[string(item.object.GetUID())]; ok {
			item.action = v.action
			c.pendingItems[string(item.object.GetUID())] = item
		} else {
			c.pendingItems[string(item.object.GetUID())] = item
		}
	}
}

func (c *Controller) toCastaiDelta(item deltaItem) *castaipb.KubernetesDeltaItem {
	obj := item.object
	objectUID := string(obj.GetUID())

	ownerUID := c.kubeClient.GetOwnerUID(obj)
	containers, status, err := getContainersAndStatus(obj)
	if err != nil {
		c.log.Errorf("getting object status json for `%s`: %v", objectUID, err)
	}

	spec, err := getObjectSpec(obj)
	if err != nil {
		c.log.Errorf("getting object spec json for `%s`: %v", objectUID, err)
	}

	gvr := obj.GetObjectKind().GroupVersionKind()

	return &castaipb.KubernetesDeltaItem{
		Event:             item.action,
		ObjectUid:         objectUID,
		ObjectName:        obj.GetName(),
		ObjectNamespace:   obj.GetNamespace(),
		ObjectKind:        gvr.Kind,
		ObjectApiVersion:  gvr.GroupVersion().String(),
		ObjectCreatedAt:   timestamppb.New(obj.GetCreationTimestamp().UTC()),
		ObjectContainers:  containers,
		ObjectOwnerUid:    ownerUID,
		ObjectLabels:      obj.GetLabels(),
		ObjectAnnotations: getAnnotations(obj),
		ObjectStatus:      status,
		ObjectSpec:        spec,
	}
}

type deltaItem struct {
	object kube.Object
	action castaipb.KubernetesDeltaItemEvent
}

func getContainersAndStatus(obj kube.Object) ([]*castaipb.Container, []byte, error) {
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

	res := make([]*castaipb.Container, len(containers))
	for i, cont := range containers {
		res[i] = &castaipb.Container{
			Name:      cont.Name,
			ImageName: cont.Image,
		}
	}
	return res, st, err
}

func getAnnotations(obj kube.Object) map[string]string {
	switch v := obj.(type) {
	case *corev1.Service, *networkingv1.Ingress:
		return v.GetAnnotations()
	default:
		return nil
	}
}

func getObjectSpec(obj kube.Object) ([]byte, error) {
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
