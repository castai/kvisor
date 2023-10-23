package delta

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/castai"
	mock_castai "github.com/castai/kvisor/castai/mock"
)

func TestSnapshotProvider(t *testing.T) {
	r := require.New(t)
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	now := time.Now()
	objectID := uuid.New()
	provider := NewSnapshotProvider()
	provider.append(castai.DeltaItem{
		Event:            castai.EventUpdate,
		ObjectUID:        objectID.String(),
		ObjectName:       "test_object",
		ObjectNamespace:  "test_namespace",
		ObjectKind:       "Pod",
		ObjectAPIVersion: "v1",
		ObjectCreatedAt:  now,
	})

	snapshot := provider.snapshot()
	r.Equal([]castai.DeltaItem{{
		Event:            castai.EventAdd,
		ObjectUID:        objectID.String(),
		ObjectName:       "test_object",
		ObjectNamespace:  "test_namespace",
		ObjectKind:       "Pod",
		ObjectAPIVersion: "v1",
		ObjectCreatedAt:  now,
	}}, snapshot)

	provider.append(castai.DeltaItem{
		Event:            castai.EventDelete,
		ObjectUID:        objectID.String(),
		ObjectName:       "test_object",
		ObjectNamespace:  "test_namespace",
		ObjectKind:       "Pod",
		ObjectAPIVersion: "v1",
		ObjectCreatedAt:  now,
	})

	r.Empty(provider.snapshot())
}

func TestResyncObserver(t *testing.T) {
	log := logrus.New()
	ctx := context.Background()
	log.SetLevel(logrus.DebugLevel)
	ctrl := gomock.NewController(t)
	castaiClient := mock_castai.NewMockClient(ctrl)
	castaiClient.EXPECT().SendDeltaReport(gomock.Any(), &castai.Delta{
		FullSnapshot: true,
		Items:        []castai.DeltaItem{},
	})
	observer := ResyncObserver(ctx, log, NewSnapshotProvider(), castaiClient)
	observer(&castai.TelemetryResponse{
		DisabledFeatures: nil,
		FullResync:       true,
	})
}
