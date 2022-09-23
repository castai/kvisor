package kubelinter

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/controller"
)

func TestSubscriber(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("sends linter checks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		castaiClient := mock_castai.NewMockClient(ctrl)

		linter := New(rules)

		subscriber := &Subscriber{
			ctx:    ctx,
			cancel: cancel,
			client: castaiClient,
			linter: linter,
			delta:  newDeltaState(),
			log:    log,
		}

		castaiClient.EXPECT().SendLinterChecks(gomock.Any(), gomock.Any())
		subscriber.lintObjects([]controller.Object{
			&corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_pod",
				},
			},
		})
	})
}
