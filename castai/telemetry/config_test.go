package telemetry

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

func TestModifyConfig(t *testing.T) {
	r := require.New(t)

	oldCfg := config.Config{
		ImageScan: config.ImageScan{
			Enabled: true,
		},
		Linter: config.Linter{
			Enabled: true,
		},
		KubeBench: config.KubeBench{
			Enabled: true,
		},
	}

	newCfg := ModifyConfig(oldCfg, &castai.TelemetryResponse{
		DisabledFeatures: []string{"linter", "imagescan", "kubebench"},
		FullResync:       false,
	})

	r.Equal(config.Config{
		ImageScan: config.ImageScan{
			Enabled: false,
		},
		Linter: config.Linter{
			Enabled: false,
		},
		KubeBench: config.KubeBench{
			Enabled: false,
		},
	}, newCfg)
}

func TestObserveDisabledFeatures(t *testing.T) {
	r := require.New(t)
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	cfg := config.Config{
		ImageScan: config.ImageScan{
			Enabled: true,
		},
		Linter: config.Linter{
			Enabled: true,
		},
		KubeBench: config.KubeBench{
			Enabled: true,
		},
	}

	observer, ctx := ObserveDisabledFeatures(context.Background(), cfg, log)
	observer(&castai.TelemetryResponse{
		DisabledFeatures: []string{"imagescan"},
		FullResync:       false,
	})

	r.ErrorIs(ctx.Err(), context.Canceled)
}
