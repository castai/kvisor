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

	casttypes "github.com/castai/kvisor/castai"
	mock_castai "github.com/castai/kvisor/castai/mock"
	"github.com/castai/kvisor/kube"
)

func TestSubscriber(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("sends linter checks", func(t *testing.T) {
		r := require.New(t)
		mockctrl := gomock.NewController(t)
		defer mockctrl.Finish()
		castaiClient := mock_castai.NewMockClient(mockctrl)

		linter, err := New(lo.Keys(casttypes.LinterRuleMap))
		r.NoError(err)

		ctrl := &Controller{
			client: castaiClient,
			linter: linter,
			delta:  newDeltaState(),
			log:    log,
		}

		castaiClient.EXPECT().SendLinterChecks(gomock.Any(), gomock.Any())

		objects := []kube.Object{
			&corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_pod",
				},
			},
		}
		ctx := context.Background()
		r.NoError(ctrl.lintObjects(ctx, objects))
	})
}
