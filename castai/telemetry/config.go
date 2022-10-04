package telemetry

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

type feature string

const (
	linter    feature = "linter"
	kubeBench feature = "kubebench"
	imageScan feature = "imagescan"
)

// ModifyConfig takes config.Config and castai.TelemetryResponse as arguments
// and returns new config.Config with modifications requested by backend.
func ModifyConfig(cfg config.Config, response *castai.TelemetryResponse) config.Config {
	for _, disabledFeature := range response.DisabledFeatures {
		switch feature(disabledFeature) {
		case linter:
			cfg.Features.KubeLinter.Enabled = false
		case kubeBench:
			cfg.Features.KubeBench.Enabled = false
		case imageScan:
			cfg.Features.ImageScan.Enabled = false
		}
	}

	return cfg
}

// ObserveDisabledFeatures returns context.Context and telemetry.Observer.
// Context is cancelled whenever telemetry response sends new disabled feature.
func ObserveDisabledFeatures(ctx context.Context, cfg config.Config, log logrus.FieldLogger) (Observer, context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	return func(resp *castai.TelemetryResponse) {
		if featuresHaveChanged(&cfg, resp) {
			log.Info("features have changed, restarting agent")
			cancel()
		}
	}, ctx
}

func featuresHaveChanged(cfg *config.Config, response *castai.TelemetryResponse) bool {
	for _, disabledFeature := range response.DisabledFeatures {
		switch feature(disabledFeature) {
		case linter:
			if cfg.Features.KubeLinter.Enabled {
				return true
			}
		case kubeBench:
			if cfg.Features.KubeBench.Enabled {
				return true
			}
		case imageScan:
			if cfg.Features.ImageScan.Enabled {
				return true
			}
		}
	}

	return false
}
