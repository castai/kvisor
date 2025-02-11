package state

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"google.golang.org/grpc"
)

type containerEventMapper func(res *castpb.ContainerEvent, e *ebpftypes.Event, signatureEvent *castpb.SignatureEvent)

type containerEventsGroupConfig struct {
	batchSize       int
	flushInterval   time.Duration
	fingerprintSize int
}

type ebpfEventNameGetter interface {
	GetEventName(id events.ID) string
}

func newContainerEventsGroup(
	log *logging.Logger,
	eventsEnrichmentService eventsEnrichmentService,
	containerEventsSender ContainerEventsSender,
	batch *castpb.ContainerEventsBatch,
	cfg containerEventsGroupConfig,
	nowFunc func() time.Time,
	containerEventMapper containerEventMapper,
	ebpfEventNameGetter ebpfEventNameGetter,
) *containerEventsGroup {
	if cfg.fingerprintSize == 0 {
		cfg.fingerprintSize = 500
	}
	if cfg.batchSize == 0 {
		cfg.batchSize = 500
	}
	if cfg.flushInterval == 0 {
		cfg.flushInterval = 5 * time.Second
	}
	fingerprintSize := uint32(cfg.fingerprintSize) // nolint:gosec
	fingerprints, err := freelru.New[uint64, struct{}](fingerprintSize, func(k uint64) uint32 {
		return uint32(k) // nolint:gosec
	})
	if err != nil {
		panic(err)
	}
	fingerprints.SetLifetime(10 * time.Second)

	batch.Items = make([]*castpb.ContainerEvent, 0, cfg.batchSize)

	return &containerEventsGroup{
		log:                     log,
		cfg:                     cfg,
		containerEventMapper:    containerEventMapper,
		containerEventsSender:   containerEventsSender,
		eventsEnrichmentService: eventsEnrichmentService,
		ebpfEventNameGetter:     ebpfEventNameGetter,
		currentTimeFunc:         nowFunc,

		batch:              batch,
		fingerprintsDigest: xxhash.New(),
		fingerprints:       fingerprints,
		flushedAt:          time.Now(),
	}
}

type containerEventsGroup struct {
	log                     *logging.Logger
	cfg                     containerEventsGroupConfig
	containerEventMapper    containerEventMapper
	containerEventsSender   ContainerEventsSender
	eventsEnrichmentService eventsEnrichmentService
	ebpfEventNameGetter     ebpfEventNameGetter
	currentTimeFunc         func() time.Time

	mu                 sync.Mutex
	batch              *castpb.ContainerEventsBatch
	fingerprintsDigest *xxhash.Digest
	fingerprints       freelru.Cache[uint64, struct{}]
	flushedAt          time.Time
}

func (g *containerEventsGroup) handleEvent(ctx context.Context, e *ebpftypes.Event, signatureEvent *castpb.SignatureEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if e != nil {
		if !g.shouldAddEvent(e) {
			metrics.AgentSkippedEventsTotal.WithLabelValues(g.ebpfEventNameGetter.GetEventName(e.Context.EventID)).Inc()
			return
		}

		protoContainerEvent := &castpb.ContainerEvent{}
		// Set fields on final proto event and enrich if needed.
		g.containerEventMapper(protoContainerEvent, e, signatureEvent)
		g.eventsEnrichmentService.Enrich(ctx, e, protoContainerEvent)
		g.batch.Items = append(g.batch.Items, protoContainerEvent)
	}

	now := g.currentTimeFunc()
	if g.shouldSendBatch(now) {
		g.sendBatch(ctx, now)
	}
}

func (g *containerEventsGroup) shouldAddEvent(e *ebpftypes.Event) bool {
	fingerprint, ok := g.getEventFingerprint(e)
	if ok {
		if g.fingerprints.Contains(fingerprint) {
			return false
		}
		g.fingerprints.Add(fingerprint, struct{}{})
		return true
	}

	return true
}

func (g *containerEventsGroup) sendBatch(ctx context.Context, now time.Time) {
	if len(g.batch.Items) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := g.containerEventsSender.EnqueueAndWait(ctx, g.batch); err != nil {
		if g.log.IsEnabled(slog.LevelDebug) {
			g.log.Errorf("sending batch, container=%s(%s): %v", g.batch.ContainerName, g.batch.ContainerId, err)
		}
	} else {
		if g.log.IsEnabled(slog.LevelDebug) {
			g.log.Debugf("sent batch, size=%d, container=%s(%s)", len(g.batch.Items), g.batch.ContainerName, g.batch.ContainerId)
		}
	}
	g.flushedAt = now
	g.batch.Items = g.batch.Items[:0] // Clear items and reuse underlying slice.
}

func (g *containerEventsGroup) shouldSendBatch(now time.Time) (res bool) {
	currentBatchSize := len(g.batch.Items)
	if currentBatchSize == 0 {
		return false
	}
	// Send then batch size is reached.
	if currentBatchSize >= g.cfg.batchSize {
		return true
	}
	// Send then flush interval is reached.
	return g.flushedAt.Add(g.cfg.flushInterval).Before(now)
}

func (g *containerEventsGroup) getEventFingerprint(e *ebpftypes.Event) (uint64, bool) {
	g.fingerprintsDigest.Reset()

	switch v := e.Args.(type) {
	case ebpftypes.NetPacketDNSBaseArgs:
		_, _ = g.fingerprintsDigest.WriteString(v.Payload.DNSQuestionDomain)
		return g.fingerprintsDigest.Sum64(), true
	case ebpftypes.SockSetStateArgs:
		tupleBytes, err := v.Tuple.Dst.MarshalBinary()
		if err == nil {
			state := make([]byte, 4)
			binary.LittleEndian.PutUint32(state, v.OldState)
			_, _ = g.fingerprintsDigest.Write(state)
			binary.LittleEndian.PutUint32(state, v.NewState)
			_, _ = g.fingerprintsDigest.Write(state)
			_, _ = g.fingerprintsDigest.Write(tupleBytes)
			return g.fingerprintsDigest.Sum64(), true
		}
		return 0, false
	case ebpftypes.TtyWriteArgs:
		_, _ = g.fingerprintsDigest.WriteString(v.Path)
	case ebpftypes.MagicWriteArgs:
		_, _ = g.fingerprintsDigest.WriteString(v.Pathname)
	}
	return 0, false
}

type ContainerEventsSender interface {
	Run(ctx context.Context) error
	EnqueueAndWait(ctx context.Context, batch *castpb.ContainerEventsBatch) error
}

func NewCastaiContainerEventSender(ctx context.Context, log *logging.Logger, apiClient *castai.Client) *CastaiContainerEventSender {
	ws := castai.NewWriteStream[*castpb.ContainerEventsBatch, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return apiClient.GRPC.ContainerEventsBatchWriteStream(ctx, grpc.UseCompressor(apiClient.GetCompressionName()))
	})
	defer ws.Close()
	ws.ReopenDelay = 2 * time.Second

	return &CastaiContainerEventSender{
		log:   log,
		ws:    ws,
		queue: make(chan *containerBatchSendReq, 1000),
	}
}

type CastaiContainerEventSender struct {
	log   *logging.Logger
	ws    *castai.WriteStream[*castpb.ContainerEventsBatch, *castpb.WriteStreamResponse]
	queue chan *containerBatchSendReq
}

func (s *CastaiContainerEventSender) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-s.queue:
			err := s.send(req.batch)
			if err != nil {
				if s.log.IsEnabled(slog.LevelDebug) {
					s.log.Errorf("sending batch, container=%s(%s): %v", req.batch.ContainerName, req.batch.ContainerId, err)
				}
				metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_container_events").Inc()
			}
			// Notify caller about sent batch.
			select {
			case req.done <- struct{}{}:
			default:
			}
			metrics.AgentExporterSendTotal.WithLabelValues("container_events_batch").Inc()
			metrics.AgentExporterSendTotal.WithLabelValues("container_events_batch_items").Add(float64(len(req.batch.Items)))
		}
	}
}

type containerBatchSendReq struct {
	batch *castpb.ContainerEventsBatch
	done  chan struct{}
}

func (s *CastaiContainerEventSender) EnqueueAndWait(ctx context.Context, batch *castpb.ContainerEventsBatch) error {
	req := &containerBatchSendReq{batch: batch, done: make(chan struct{}, 1)}
	select {
	case s.queue <- req:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_container_events").Inc()
		return errors.New("queue is full")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-req.done:
		return nil
	}
}

func (s *CastaiContainerEventSender) send(batch *castpb.ContainerEventsBatch) error {
	var err error
	for range 2 {
		err = s.ws.Send(batch)
		if err != nil {
			continue
		}
		return nil
	}
	return err
}
