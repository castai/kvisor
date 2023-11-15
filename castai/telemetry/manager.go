package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
)

type Observer func(response *castai.TelemetryResponse)

type Manager struct {
	log      logrus.FieldLogger
	client   castai.Client
	interval time.Duration

	observers []Observer
}

func NewManager(log logrus.FieldLogger, castaiClient castai.Client, interval time.Duration) *Manager {
	return &Manager{log: log, client: castaiClient, interval: interval}
}

func (s *Manager) AddObservers(observers ...Observer) {
	s.observers = append(s.observers, observers...)
}

func (s *Manager) NeedLeaderElection() bool {
	return true
}

// Start periodically gets latest telemetry response (config) and updates observers.
func (s *Manager) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.interval):
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
