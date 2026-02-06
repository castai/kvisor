package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	noop "github.com/castai/kvisor/pkg/cloudprovider/noop"
	"github.com/castai/logging"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

func TestVPCStateController(t *testing.T) {
	log := logging.New()
	k8sClient := fake.NewSimpleClientset()
	kubeClient := kube.NewClient(log, "agent", "ns", kube.Version{}, k8sClient, "")

	t.Run("stops on context cancellation", func(t *testing.T) {
		r := require.New(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		provider := noop.NewProvider()

		cfg := VPCStateControllerConfig{
			NetworkName:     "test-network",
			RefreshInterval: 1 * time.Hour,
		}

		ctrl := NewVPCStateController(log, cfg, provider, kubeClient)

		err := ctrl.Run(ctx)
		// Should either be nil (failed to init provider) or context deadline exceeded
		if err != nil {
			r.True(errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
		}
	})

	t.Run("sets default refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		cfg := VPCStateControllerConfig{
			NetworkName:     "test-network",
			RefreshInterval: 0,
		}

		ctrl := NewVPCStateController(log, cfg, provider, kubeClient)
		r.Equal(1*time.Hour, ctrl.cfg.RefreshInterval)
	})

	t.Run("uses configured refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		customInterval := 30 * time.Minute
		cfg := VPCStateControllerConfig{
			NetworkName:     "test-network",
			RefreshInterval: customInterval,
		}

		ctrl := NewVPCStateController(log, cfg, provider, kubeClient)
		r.Equal(customInterval, ctrl.cfg.RefreshInterval)
	})
}
