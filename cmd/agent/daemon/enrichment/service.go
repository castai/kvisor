package enrichment

import (
	"context"
	"runtime/debug"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
)

type EnrichRequest struct {
	Event        *castpb.Event
	EventContext *types.EventContext
	Args         types.Args
	Container    *containers.Container
}

type EventEnricher interface {
	// Enrich will add additional data to the provided Event.
	Enrich(context.Context, *EnrichRequest)

	// EventsTypes returns a slice of event types, this enricher reacts to.
	EventTypes() []castpb.EventType
}

type Config struct {
	WorkerCount    int
	EventEnrichers []EventEnricher
}

func NewService(log *logging.Logger, cfg Config) *Service {
	return &Service{
		log:            log.WithField("component", "enrichment"),
		eventsQueue:    make(chan *EnrichRequest, 1000),
		outQueue:       make(chan *castpb.Event, 1000),
		cfg:            cfg,
		eventEnrichers: groupEventEnrichers(cfg.EventEnrichers),
	}
}

func groupEventEnrichers(enrichers []EventEnricher) map[castpb.EventType][]EventEnricher {
	result := map[castpb.EventType][]EventEnricher{}

	for _, enricher := range enrichers {
		for _, t := range enricher.EventTypes() {
			result[t] = append(result[t], enricher)
		}
	}

	return result
}

type Service struct {
	log         *logging.Logger
	cfg         Config
	eventsQueue chan *EnrichRequest
	outQueue    chan *castpb.Event

	eventEnrichers map[castpb.EventType][]EventEnricher
}

func (s *Service) Events() chan *castpb.Event {
	return s.outQueue
}

func (s *Service) Enqueue(e *EnrichRequest) bool {
	if _, found := s.eventEnrichers[e.Event.EventType]; !found {
		return false
	}

	select {
	case s.eventsQueue <- e:
		return true
	default:
		metrics.AgentAnalyzersQueueDroppedEventsTotal.Inc()
		return false
	}
}

func (s *Service) Run(ctx context.Context) error {
	s.log.Infof("running, workers=%d", s.cfg.WorkerCount)
	defer s.log.Infof("stopping")

	// Events processing workers loops.
	for i := 0; i < s.cfg.WorkerCount; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-s.eventsQueue:
					s.processEvent(ctx, e)
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Service) processEvent(ctx context.Context, e *EnrichRequest) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			s.log.Errorf("panic while enriching event: %v, stack=%s", perr, stack)
		}
	}()

	enrichers := s.eventEnrichers[e.Event.EventType]

	for _, enricher := range enrichers {
		enricher.Enrich(ctx, e)
	}

	s.outQueue <- e.Event
}
