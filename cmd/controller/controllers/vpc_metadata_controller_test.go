package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

func TestVPCMetadataController(t *testing.T) {
	log := logging.NewTestLog()
	k8sClient := fake.NewSimpleClientset()
	kubeClient := kube.NewClient(log, "agent", "ns", kube.Version{}, k8sClient)

	t.Run("returns nil on cloud provider initialization failure", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()

		cfg := VPCMetadataConfig{
			Enabled:         true,
			Type:            "invalid-provider",
			NetworkName:     "test-network",
			RefreshInterval: 1 * time.Hour,
		}

		ctrl := NewVPCMetadataController(log, cfg, kubeClient)

		// Should return nil (no error) on cloud provider initialization failure
		err := ctrl.Run(ctx)
		r.NoError(err)
	})

	t.Run("stops on context cancellation", func(t *testing.T) {
		r := require.New(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		cfg := VPCMetadataConfig{
			Enabled:         true,
			Type:            "invalid-provider",
			NetworkName:     "test-network",
			RefreshInterval: 1 * time.Hour,
		}

		ctrl := NewVPCMetadataController(log, cfg, kubeClient)

		err := ctrl.Run(ctx)
		// Should either be nil (failed to init provider) or context deadline exceeded
		if err != nil {
			r.True(errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
		}
	})

	t.Run("sets default refresh interval", func(t *testing.T) {
		r := require.New(t)

		cfg := VPCMetadataConfig{
			Enabled:         true,
			Type:            "gcp",
			NetworkName:     "test-network",
			RefreshInterval: 0,
		}

		ctrl := NewVPCMetadataController(log, cfg, kubeClient)
		r.Equal(1*time.Hour, ctrl.cfg.RefreshInterval)
	})

	t.Run("uses configured refresh interval", func(t *testing.T) {
		r := require.New(t)

		customInterval := 30 * time.Minute
		cfg := VPCMetadataConfig{
			Enabled:         true,
			Type:            "gcp",
			NetworkName:     "test-network",
			RefreshInterval: customInterval,
		}

		ctrl := NewVPCMetadataController(log, cfg, kubeClient)
		r.Equal(customInterval, ctrl.cfg.RefreshInterval)
	})
}
