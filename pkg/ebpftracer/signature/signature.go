package signature

import (
	"bytes"
	"context"
	"time"

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
	Enabled                bool
	InputChanSize          int `validate:"required"`
	OutputChanSize         int `validate:"required"`
	DefaultSignatureConfig DefaultSignatureConfig
}

type Signature interface {
	GetMetadata() SignatureMetadata

	OnEvent(event *types.Event) *castpb.SignatureFinding
}

type SignatureEngine struct {
	log         *logging.Logger
	inputEvents chan *types.Event
	eventsChan  chan *castpb.Event
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
		eventsChan:              make(chan *castpb.Event, cfg.OutputChanSize),
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

func (e *SignatureEngine) Events() <-chan *castpb.Event {
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

		e.eventsChan <- &castpb.Event{
			EventType:     castpb.EventType_EVENT_SIGNATURE,
			Timestamp:     uint64(time.Now().UTC().UnixNano()),
			ProcessName:   string(bytes.Trim(event.Context.Comm[:], "\x00")),
			Namespace:     event.Container.PodNamespace,
			PodName:       event.Container.PodName,
			ContainerName: event.Container.Name,
			PodUid:        event.Container.PodUID,
			ContainerId:   event.Container.ID,
			CgroupId:      event.Context.CgroupID,
			HostPid:       event.Context.HostPid,
			Data: &castpb.Event_Signature{
				Signature: &castpb.SignatureEvent{
					Metadata: metadata,
					Finding:  finding,
				},
			},
		}
	}
}
