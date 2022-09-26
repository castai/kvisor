package kubelinter

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/controller"
	casttypes "github.com/castai/sec-agent/types"
)

func TestSubscriber(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("sends linter checks", func(t *testing.T) {
		r := require.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		castaiClient := mock_castai.NewMockClient(ctrl)

		linter := New(lo.Keys(casttypes.LinterRuleMap))

		subscriber := &Subscriber{
			ctx:    ctx,
			cancel: cancel,
			client: castaiClient,
			linter: linter,
			delta:  newDeltaState(),
			log:    log,
		}

		castaiClient.EXPECT().SendLinterChecks(gomock.Any(), gomock.Any())
		r.NoError(subscriber.lintObjects([]controller.Object{
			&corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_pod",
				},
			},
		}))
	})
}
