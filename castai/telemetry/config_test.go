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
		Features: config.Features{
			ImageScan: config.ImageScan{
				Enabled: true,
			},
			KubeLinter: config.KubeLinter{
				Enabled: true,
			},
			KubeBench: config.KubeBench{
				Enabled: true,
			},
		},
	}

	newCfg := ModifyConfig(oldCfg, &castai.TelemetryResponse{
		DisabledFeatures: []string{"kubelinter", "imagescan", "kubebench"},
		FullResync:       false,
	})

	r.Equal(config.Config{
		Features: config.Features{
			ImageScan: config.ImageScan{
				Enabled: false,
			},
			KubeLinter: config.KubeLinter{
				Enabled: false,
			},
			KubeBench: config.KubeBench{
				Enabled: false,
			},
		},
	}, newCfg)
}

func TestObserveDisabledFeatures(t *testing.T) {
	r := require.New(t)
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	cfg := config.Config{
		Features: config.Features{
			ImageScan: config.ImageScan{
				Enabled: true,
			},
			KubeLinter: config.KubeLinter{
				Enabled: true,
			},
			KubeBench: config.KubeBench{
				Enabled: true,
			},
		},
	}

	observer, ctx := ObserveDisabledFeatures(context.Background(), cfg, log)
	observer(&castai.TelemetryResponse{
		DisabledFeatures: []string{"imagescan"},
		FullResync:       false,
	})

	r.ErrorIs(ctx.Err(), context.Canceled)
}
