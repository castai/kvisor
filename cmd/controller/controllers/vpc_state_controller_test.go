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
)

func TestVPCStateController(t *testing.T) {
	log := logging.New()

	t.Run("stops on context cancellation", func(t *testing.T) {
		r := require.New(t)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		provider := noop.NewProvider()

		cfg := NetworkStateControllerConfig{
			NetworkName:            "test-network",
			NetworkRefreshInterval: 1 * time.Hour,
		}

		vpcIndex := kube.NewVPCIndex(log, kube.VPCConfig{RefreshInterval: time.Hour, CacheSize: 1000})
		ctrl := NewVPCStateController(log, cfg, provider, vpcIndex)

		err := ctrl.Run(ctx)
		// Should either be nil (failed to init provider) or context deadline exceeded
		if err != nil {
			r.True(errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
		}
	})

	t.Run("sets default refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		cfg := NetworkStateControllerConfig{
			NetworkName:            "test-network",
			NetworkRefreshInterval: 0,
		}

		vpcIndex := kube.NewVPCIndex(log, kube.VPCConfig{RefreshInterval: time.Hour, CacheSize: 1000})
		ctrl := NewVPCStateController(log, cfg, provider, vpcIndex)
		r.Equal(1*time.Hour, ctrl.cfg.NetworkRefreshInterval)
	})

	t.Run("uses configured refresh interval", func(t *testing.T) {
		r := require.New(t)

		provider := noop.NewProvider()

		customInterval := 30 * time.Minute
		cfg := NetworkStateControllerConfig{
			NetworkName:            "test-network",
			NetworkRefreshInterval: customInterval,
		}

		vpcIndex := kube.NewVPCIndex(log, kube.VPCConfig{RefreshInterval: time.Hour, CacheSize: 1000})
		ctrl := NewVPCStateController(log, cfg, provider, vpcIndex)
		r.Equal(customInterval, ctrl.cfg.NetworkRefreshInterval)
	})
}
