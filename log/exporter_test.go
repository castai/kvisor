package log

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/castai"
	mock_castai "github.com/castai/kvisor/castai/mock"
)

func TestSetupLogExporter(t *testing.T) {
	logger, hook := test.NewNullLogger()
	defer hook.Reset()
	mockClusterID := uuid.New().String()
	ctrl := gomock.NewController(t)
	mockapi := mock_castai.NewMockClient(ctrl)
	e := NewExporter(logger, mockapi, logrus.AllLevels)
	logger.AddHook(e)

	t.Run("sends the log msg", func(t *testing.T) {
		r := require.New(t)

		mockapi.EXPECT().SendLogs(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *castai.LogEvent) error {
				fields := req.Fields
				r.Equal(mockClusterID, fields["cluster_id"])
				r.Equal("eks", fields["provider"])
				r.False(fields["sample_boolean_value"].(bool))
				r.Equal(3, fields["int_val"])
				r.Equal(1.000000004, fields["float_val"])
				return nil
			}).Times(1)

		log := logger.WithFields(logrus.Fields{
			"cluster_id": mockClusterID,
			"provider":   "eks",
			// log interface allows not just the strings - must make sure we correctly convert them to strings when sending
			"sample_boolean_value": false,
			"int_val":              3,
			"float_val":            1.000000004,
		})
		log.Log(logrus.ErrorLevel, "failed to discover account id")
		time.Sleep(1 * time.Second)
	})
}
