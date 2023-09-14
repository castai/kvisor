package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
)

const telemetryInterval = time.Minute

type Observer func(response *castai.TelemetryResponse)

type Manager struct {
	log    logrus.FieldLogger
	client castai.Client

	observers []Observer
}

func NewManager(log logrus.FieldLogger, castaiClient castai.Client) *Manager {
	return &Manager{log: log, client: castaiClient}
}

func (s *Manager) AddObservers(observers ...Observer) {
	s.observers = append(s.observers, observers...)
}

// Run periodically gets latest telemetry response (config) and updates observers.
func (s *Manager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(telemetryInterval):
			resp, err := s.postTelemetry(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					s.log.Errorf("can not post telemetry: %v", err)
				}
				continue
			}

			for i := range s.observers {
				s.observers[i](resp)
			}
		}
	}
}

func (s *Manager) postTelemetry(ctx context.Context) (*castai.TelemetryResponse, error) {
	return s.client.PostTelemetry(ctx, false)
}
