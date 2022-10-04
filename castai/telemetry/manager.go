package telemetry

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/castai"
)

const telemetryInterval = time.Minute

type Observer func(response *castai.TelemetryResponse)

type Manager struct {
	log    logrus.FieldLogger
	client castai.Client

	ctx context.Context
}

func NewManager(ctx context.Context, log logrus.FieldLogger, castaiClient castai.Client) *Manager {
	return &Manager{log: log, client: castaiClient, ctx: ctx}
}

// Observe should be run as goroutine.
// It accepts Observer functions and calls them whenever new TelemetryResponse is received.
func (s *Manager) Observe(observers ...Observer) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(telemetryInterval):
			resp, err := s.postTelemetry()
			if err != nil {
				s.log.Errorf("can not post telemetry: %v", err)
				continue
			}

			for i := range observers {
				observers[i](resp)
			}
		}
	}
}

func (s *Manager) postTelemetry() (*castai.TelemetryResponse, error) {
	return s.client.PostTelemetry(s.ctx)
}
