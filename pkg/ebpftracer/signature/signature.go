package signature

import (
	"context"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

type SignatureMetadata struct {
	ID           castpb.SignatureEventID
	Name         string
	Version      string
	TargetEvents []events.ID
}

type SignatureEngineConfig struct {
	InputChanSize          int                    `validate:"required" json:"inputChanSize"`
	OutputChanSize         int                    `validate:"required" json:"outputChanSize"`
	DefaultSignatureConfig DefaultSignatureConfig `json:"default_signature_config"`
}

// Event is final signature event with finding.
type Event struct {
	EbpfEvent      *types.Event
	SignatureEvent *castpb.SignatureEvent
}

type Signature interface {
	GetMetadata() SignatureMetadata

	OnEvent(event *types.Event) *castpb.SignatureFinding
}

type SignatureEngine struct {
	log         *logging.Logger
	inputEvents chan *types.Event
	eventsChan  chan Event
	signatures  []Signature
	// Map of precalculated singature metadata to reduce object churn in event handling loop
	signaturesMetadata      map[Signature]*castpb.SignatureMetadata
	eventsSignatureTriggers map[events.ID][]Signature
}

func NewEngine(signatures []Signature, log *logging.Logger, cfg SignatureEngineConfig) *SignatureEngine {
	eventsSignatureTriggers, signaturesMetadata := buildLookupMaps(signatures)

	return &SignatureEngine{
		log:                     log.WithField("component", "signature_engine"),
		inputEvents:             make(chan *types.Event, cfg.InputChanSize),
		eventsChan:              make(chan Event, cfg.OutputChanSize),
		signatures:              signatures,
		eventsSignatureTriggers: eventsSignatureTriggers,
		signaturesMetadata:      signaturesMetadata,
	}
}

func buildLookupMaps(signatures []Signature) (map[events.ID][]Signature, map[Signature]*castpb.SignatureMetadata) {
	signaturesByEvent := map[events.ID][]Signature{}
	signatureMetadata := map[Signature]*castpb.SignatureMetadata{}

	for _, signature := range signatures {
		metadata := signature.GetMetadata()
		signatureMetadata[signature] = &castpb.SignatureMetadata{
			Id:      metadata.ID,
			Version: metadata.Version,
		}

		for _, event := range metadata.TargetEvents {
			signaturesByEvent[event] = append(signaturesByEvent[event], signature)
		}
	}

	return signaturesByEvent, signatureMetadata
}

func (e *SignatureEngine) TargetEvents() []events.ID {
	result := make([]events.ID, 0, len(e.eventsSignatureTriggers))

	for event := range e.eventsSignatureTriggers {
		result = append(result, event)
	}

	return result
}

func (e *SignatureEngine) EventInput() chan<- *types.Event {
	return e.inputEvents
}

func (e *SignatureEngine) Events() <-chan Event {
	return e.eventsChan
}

func (e *SignatureEngine) QueueEvent(event *types.Event) {
	select {
	case e.inputEvents <- event:
	default:
	}
}

func (e *SignatureEngine) Run(ctx context.Context) error {
	e.log.Infof("running")
	defer e.log.Infof("stopping")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event := <-e.inputEvents:
			e.handleEvent(event)
		}
	}
}

func (e *SignatureEngine) handleEvent(event *types.Event) {
	signatures := e.eventsSignatureTriggers[event.Context.EventID]

	for _, signature := range signatures {
		finding := signature.OnEvent(event)
		if finding == nil {
			continue
		}

		metadata := e.signaturesMetadata[signature]

		e.eventsChan <- Event{
			EbpfEvent: event,
			SignatureEvent: &castpb.SignatureEvent{
				Metadata: metadata,
				Finding:  finding,
			},
		}
	}
}
