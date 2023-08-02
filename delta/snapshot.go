package delta

import (
	"context"
	"sync"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/castai/telemetry"
)

func ResyncObserver(
	ctx context.Context,
	log logrus.FieldLogger,
	snaphotProvider SnapshotProvider,
	client castai.Client,
) telemetry.Observer {
	return func(response *castai.TelemetryResponse) {
		if response.FullResync {
			if err := client.SendDeltaReport(ctx, &castai.Delta{
				FullSnapshot: true,
				Items:        snaphotProvider.snapshot(),
			}); err != nil {
				log.Errorf("can not send full snapshot: %v", err)
			}
		}
	}
}

type SnapshotProvider interface {
	append(item castai.DeltaItem)

	snapshot() []castai.DeltaItem
}

func NewSnapshotProvider() SnapshotProvider {
	return &snapshotProvider{
		state: make(map[string]castai.DeltaItem),
		mutex: sync.RWMutex{},
	}
}

type snapshotProvider struct {
	state map[string]castai.DeltaItem
	mutex sync.RWMutex
}

func (s *snapshotProvider) append(item castai.DeltaItem) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	switch item.Event {
	case castai.EventAdd, castai.EventUpdate:
		// This is used for resync, always save with EventAdd.
		item.Event = castai.EventAdd

		if v, ok := s.state[item.ObjectUID]; ok && v.ObjectImagesChanged {
			item.ObjectImagesChanged = v.ObjectImagesChanged
		}

		s.state[item.ObjectUID] = item
	case castai.EventDelete:
		delete(s.state, item.ObjectUID)
	}
}

func (s *snapshotProvider) snapshot() []castai.DeltaItem {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return lo.Values(s.state)
}
