package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/kvisor/cmd/controller/kube"
	noop "github.com/castai/kvisor/pkg/cloudprovider/noop"
	"github.com/castai/logging"
)

func TestVolumeStateController(t *testing.T) {
	log := logging.New()
	k8sClient := fake.NewSimpleClientset()
	kubeClient := kube.NewClient(log, "agent", "ns", kube.Version{}, k8sClient, "")

	t.Run("stops on context cancellation", func(t *testing.T) {
		r := require.New(t)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		provider := noop.NewProvider()

		cfg := VolumeStateControllerConfig{
			RefreshInterval: 1 * time.Hour,
		}

		ctrl := NewVolumeStateController(log, cfg, provider, kubeClient)

		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
	})

	t.Run("sets default refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		cfg := VolumeStateControllerConfig{
			RefreshInterval: 0,
		}

		ctrl := NewVolumeStateController(log, cfg, provider, kubeClient)
		r.Equal(5*time.Minute, ctrl.cfg.RefreshInterval)
	})

	t.Run("uses configured refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		customInterval := 10 * time.Minute
		cfg := VolumeStateControllerConfig{
			RefreshInterval: customInterval,
		}

		ctrl := NewVolumeStateController(log, cfg, provider, kubeClient)
		r.Equal(customInterval, ctrl.cfg.RefreshInterval)
	})
}

func TestExtractInstanceIDFromProviderID(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		want       string
	}{
		{
			name:       "empty provider ID",
			providerID: "",
			want:       "",
		},
		{
			name:       "AWS format with zone",
			providerID: "aws:///us-east-1a/i-1234567890abcdef0",
			want:       "i-1234567890abcdef0",
		},
		{
			name:       "AWS format with account and zone",
			providerID: "aws://123456789012/us-east-1a/i-1234567890abcdef0",
			want:       "i-1234567890abcdef0",
		},
		{
			name:       "GCP format",
			providerID: "gce://my-project/us-central1-a/instance-name",
			want:       "my-project/us-central1-a/instance-name",
		},
		{
			name:       "GCP format with missing zone",
			providerID: "gce://my-project/instance-name",
			want:       "",
		},
		{
			name:       "Azure format",
			providerID: "azure:///subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-name",
			want:       "vm-name",
		},
		{
			name:       "invalid format",
			providerID: "invalid",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInstanceIDFromProviderID(tt.providerID)
			require.Equal(t, tt.want, got)
		})
	}
}
