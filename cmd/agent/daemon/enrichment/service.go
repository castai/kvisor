package enrichment

import (
	"context"
	"runtime/debug"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

type EnrichRequest struct {
	Event *castpb.Event
}

type EventEnricher interface {
	// Enrich will add additional data to the provided Event.
	Enrich(ctx context.Context, in *types.Event, out *castpb.ContainerEvent)

	// EventsTypes returns a slice of event types, this enricher reacts to.
	EventTypes() []events.ID
}

type Config struct {
	EventEnrichers []EventEnricher
}

func NewService(log *logging.Logger, cfg Config) *Service {
	return &Service{
		log:            log.WithField("component", "enrichment"),
		cfg:            cfg,
		eventEnrichers: groupEventEnrichers(cfg.EventEnrichers),
	}
}

func groupEventEnrichers(enrichers []EventEnricher) map[events.ID][]EventEnricher {
	result := map[events.ID][]EventEnricher{}
	for _, enricher := range enrichers {
		for _, t := range enricher.EventTypes() {
			result[t] = append(result[t], enricher)
		}
	}
	return result
}

type Service struct {
	log *logging.Logger
	cfg Config

	eventEnrichers map[events.ID][]EventEnricher
}

func (s *Service) Enrich(ctx context.Context, in *types.Event, out *castpb.ContainerEvent) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			s.log.Errorf("panic while enriching event: %v, stack=%s", perr, stack)
		}
	}()

	enrichers := s.eventEnrichers[in.Context.EventID]
	for _, enricher := range enrichers {
		enricher.Enrich(ctx, in, out)
	}
}
