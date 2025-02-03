package kubelinter

import (
	"context"
	rbacv1 "k8s.io/api/rbac/v1"
	"testing"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSubscriber(t *testing.T) {
	log := logging.NewTestLog()

	t.Run("sends linter checks", func(t *testing.T) {
		r := require.New(t)
		castaiClient := &mockCastaiClient{}

		linter, err := New(lo.Keys(LinterRuleMap))
		r.NoError(err)

		ctrl := &Controller{
			client: castaiClient,
			linter: linter,
			delta:  newDeltaState(),
			log:    log,
		}

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
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test_role_binding",
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRoleBinding",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "Group",
						Name: "system:authenticated",
					},
				},
				RoleRef: rbacv1.RoleRef{
					Kind: "Role",
					Name: "testrole",
				},
			},
		}
		ctx := context.Background()
		r.NoError(ctrl.lintObjects(ctx, objects))
		r.Len(castaiClient.reports, 1)
	})
}

type mockCastaiClient struct {
	reports []*castaipb.KubeLinterReport
}

func (m *mockCastaiClient) KubeLinterReportIngest(ctx context.Context, in *castaipb.KubeLinterReport, opts ...grpc.CallOption) (*castaipb.KubeLinterReportIngestResponse, error) {
	m.reports = append(m.reports, in)
	return &castaipb.KubeLinterReportIngestResponse{}, nil
}
