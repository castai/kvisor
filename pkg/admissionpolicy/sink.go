package admissionpolicy

import (
	"github.com/castai/kvisor/pkg/logging"
)

type EventSink struct {
	log *logging.Logger
}

func NewEventSink(log *logging.Logger) *EventSink {
	return &EventSink{log: log}
}

func (s *EventSink) Write(events []ValidationEvent) error {
	for _, e := range events {
		s.log.Infof("event: %s", e)
	}
	return nil
}
