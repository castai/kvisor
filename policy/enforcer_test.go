package policy

import (
	"context"
	"encoding/json"
	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/linters/kubelinter"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"testing"
)

func TestEnforcer(t *testing.T) {
	r := require.New(t)
	linter, err := kubelinter.New(lo.Keys(castai.LinterRuleMap))
	r.NoError(err)

	t.Run("denies deployment", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		e := NewEnforcer(linter)
		var req admission.Request
		b, err := os.ReadFile("../testdata/admission/sample-deployment.json")
		r.NoError(err)
		r.NoError(json.Unmarshal(b, &req))
		response := e.Handle(ctx, req)
		r.Equal(admission.Response{
			AdmissionResponse: v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Reason: "Deployment did not pass these checks: [default-service-account has-security-context no-anti-affinity no-liveness-probe no-read-only-root-fs no-readiness-probe privileged-ports run-as-non-root sa-token-automount unset-memory-requirements]",
					Code:   http.StatusForbidden,
				},
			},
		}, response)
	})

	t.Run("allows pod", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		e := NewEnforcer(linter)
		var req admission.Request
		b, err := os.ReadFile("../testdata/admission/sample-pod.json")
		r.NoError(err)
		r.NoError(json.Unmarshal(b, &req))
		response := e.Handle(ctx, req)
		r.Equal(admission.Response{
			AdmissionResponse: v1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Reason: "object of kind \"Pod\" passed all checks",
					Code:   http.StatusOK,
				},
			},
		}, response)
	})

	t.Run("denies pod with owners", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		e := NewEnforcer(linter)
		var req admission.Request
		b, err := os.ReadFile("../testdata/admission/sample-pod-with-owners.json")
		r.NoError(err)
		r.NoError(json.Unmarshal(b, &req))
		response := e.Handle(ctx, req)
		r.Equal(admission.Response{
			AdmissionResponse: v1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Reason: "obj \"kube-bench-2728638862-xbgwm\" is not validated because it has 1 owner(s)",
					Code:   http.StatusOK,
				},
			},
		}, response)
	})
}
