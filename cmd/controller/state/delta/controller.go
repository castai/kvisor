package delta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type castaiClient interface {
	KubernetesDeltaBatchIngest(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaBatchIngestClient, error)
}

type kubeClient interface {
	GetOwnerUID(obj kube.Object) string
}

type Config struct {
	Enabled        bool          `json:"enabled"`
	Interval       time.Duration `validate:"required" json:"interval"`
	InitialDeltay  time.Duration `json:"initialDeltay"`
	SendTimeout    time.Duration `validate:"required" json:"sendTimeout"`
	UseCompression bool          `json:"useCompression"`
	BatchSize      int           `validate:"required" json:"batchSize"`
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
		deltaSendMaxTries:     3,
		deltaItemSendMaxTries: 3,
		deltaRetryWait:        100 * time.Millisecond,
		firstDeltaReport:      true,
	}
}

type Controller struct {
	log          *logging.Logger
	cfg          Config
	castaiClient castaiClient
	kubeClient   kubeClient

	pendingItems          map[string]deltaItem
	deltasMu              sync.Mutex
	deltaSendMaxTries     uint64
	deltaItemSendMaxTries uint64
	deltaRetryWait        time.Duration
	firstDeltaReport      bool
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := c.process(ctx); err != nil {
				return err
			}
		}
	}
}

func (c *Controller) RequiredTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Namespace{}),
		reflect.TypeOf(&corev1.Service{}),
		reflect.TypeOf(&corev1.Node{}),
		reflect.TypeOf(&appsv1.Deployment{}),
		reflect.TypeOf(&appsv1.ReplicaSet{}),
		reflect.TypeOf(&appsv1.DaemonSet{}),
		reflect.TypeOf(&appsv1.StatefulSet{}),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
		reflect.TypeOf(&rbacv1.RoleBinding{}),
		reflect.TypeOf(&rbacv1.ClusterRole{}),
		reflect.TypeOf(&rbacv1.Role{}),
		reflect.TypeOf(&batchv1.Job{}),
		reflect.TypeOf(&batchv1.CronJob{}),
		reflect.TypeOf(&batchv1beta1.CronJob{}),
		reflect.TypeOf(&networkingv1.Ingress{}),
		reflect.TypeOf(&networkingv1.NetworkPolicy{}),
	}
}

func (c *Controller) OnAdd(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_ADD, obj)
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_UPDATE, obj)
}

func (c *Controller) OnDelete(obj kube.Object) {
	c.recordDeltaEvent(castaipb.KubernetesDeltaItemEvent_DELTA_REMOVE, obj)
}

func (c *Controller) process(ctx context.Context) error {
	pendingDeltas := c.popPendingItems()

	if err := withExponentialRetry(ctx, c.log, func() error {
		return c.sendDeltas(ctx, pendingDeltas)
	}, c.deltaSendMaxTries); err != nil {
		if c.firstDeltaReport {
			// If we fail to send initial delta controller if be terminated and start again.
			return fmt.Errorf("sending initial deltas: %w", err)
		}
		c.log.Errorf("sending deltas: %v", err)
		return nil
	}

	if c.firstDeltaReport {
		c.firstDeltaReport = false
	}
	return nil
}

func (c *Controller) sendDeltas(ctx context.Context, pendingDeltas []deltaItem) error {
	if len(pendingDeltas) == 0 {
		return nil
	}
	start := time.Now()

	// Cancel context to close stream after deltas are sent.
	ctx, cancel := context.WithTimeout(ctx, c.cfg.SendTimeout)
	defer cancel()

	deltaID := uuid.NewString()
	meta := []string{
		"x-delta-id", deltaID,
		"x-delta-count", strconv.Itoa(len(pendingDeltas)),
	}
	if c.firstDeltaReport {
		meta = append(meta, "x-delta-full-snapshot", "true")
	}

	ctx = metadata.AppendToOutgoingContext(ctx, meta...)
	var opts []grpc.CallOption
	if c.cfg.UseCompression {
		opts = append(opts, grpc.UseCompressor(gzip.Name))
	}
	deltaStream, err := c.castaiClient.KubernetesDeltaBatchIngest(ctx, opts...)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	defer func() {
		_ = deltaStream.CloseSend()
	}()

	var sentDeltasCount int
	for _, batch := range lo.Chunk(pendingDeltas, c.cfg.BatchSize) {
		pbItems := lo.Map(batch, c.toCastaiDelta)
		if err := c.sendDeltaItems(ctx, deltaStream, pbItems); err != nil {
			// Return any remaining items back to pending list.
			c.upsertPendingItems(pendingDeltas[sentDeltasCount:])
			return err
		}
		sentDeltasCount += len(batch)
	}
	c.log.Infof("sent deltas, id=%v, count=%d/%d, duration=%v", deltaID, len(pendingDeltas), sentDeltasCount, time.Since(start))
	return nil
}

func (c *Controller) sendDeltaItems(ctx context.Context, stream castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaBatchIngestClient, items []*castaipb.KubernetesDeltaItem) error {
	return withExponentialRetry(ctx, c.log, func() error {
		if err := stream.Send(&castaipb.KubernetesDeltaBatch{Items: items}); err != nil {
			if !isRetryableErr(err) {
				return backoff.Permanent(err)
			}
			return fmt.Errorf("sending delta items batch: %w", err)
		}
		if _, err := stream.Recv(); err != nil {
			if !isRetryableErr(err) {
				return backoff.Permanent(err)
			}
			return fmt.Errorf("receiving delta ack: %w", err)
		}
		return nil
	}, c.deltaItemSendMaxTries)
}

func withExponentialRetry(ctx context.Context, log *logging.Logger, fn func() error, max uint64) error {
	return backoff.RetryNotify(fn, backoff.WithContext(
		backoff.WithMaxRetries(
			backoff.NewExponentialBackOff(), max,
		), ctx,
	), func(err error, duration time.Duration) {
		if err != nil {
			log.Warnf("action failed, duration=%v: %v", duration, err)
		}
	})
}

func isRetryableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func (c *Controller) recordDeltaEvent(action castaipb.KubernetesDeltaItemEvent, obj kube.Object) {
	c.deltasMu.Lock()
	defer c.deltasMu.Unlock()

	c.pendingItems[string(obj.GetUID())] = deltaItem{
		object: obj,
		action: action,
	}
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
		key := string(item.object.GetUID())
		if v, ok := c.pendingItems[key]; ok {
			item.action = v.action
			c.pendingItems[key] = item
		} else {
			c.pendingItems[key] = item
		}
	}
}

func (c *Controller) toCastaiDelta(item deltaItem, _ int) *castaipb.KubernetesDeltaItem {
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
		ObjectAnnotations: obj.GetAnnotations(),
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

func getObjectSpec(obj kube.Object) ([]byte, error) {
	switch v := obj.(type) {
	case *networkingv1.Ingress:
		return json.Marshal(v.Spec)
	case *corev1.Service:
		return json.Marshal(v.Spec)
	case *appsv1.Deployment:
		return json.Marshal(v.Spec)
	case *appsv1.ReplicaSet:
		return json.Marshal(v.Spec)
	case *appsv1.StatefulSet:
		return json.Marshal(v.Spec)
	case *appsv1.DaemonSet:
		return json.Marshal(v.Spec)
	default:
		return nil, nil
	}
}
