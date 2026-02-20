package app

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/castai/kvisor/cmd/agent/collector/components"
	"github.com/castai/kvisor/cmd/agent/collector/config"
)

// App is the collector application.
type App struct {
	cfg     *config.Config
	version string
}

// New creates a new App.
func New(cfg *config.Config, version string) *App {
	return &App{cfg: cfg, version: version}
}

// Run starts the OTel collector and blocks until ctx is cancelled or an error occurs.
func (a *App) Run(ctx context.Context) error {
	if err := a.cfg.Validate(); err != nil {
		return fmt.Errorf("invalid collector configuration: %w", err)
	}

	factories, err := components.Build(ctx)
	if err != nil {
		return fmt.Errorf("building component factories: %w", err)
	}

	settings := otelcol.CollectorSettings{
		BuildInfo: component.BuildInfo{
			Command:     "kvisor-collector",
			Description: "kvisor OpenTelemetry Collector",
			Version:     a.version,
		},
		Factories: func() (otelcol.Factories, error) { return factories, nil },
		ConfigProviderSettings: otelcol.ConfigProviderSettings{
			ResolverSettings: confmap.ResolverSettings{
				URIs:              []string{"kvisor:"},
				ProviderFactories: []confmap.ProviderFactory{config.NewStaticProviderFactory(a.cfg)},
			},
		},
	}

	col, err := otelcol.NewCollector(settings)
	if err != nil {
		return fmt.Errorf("creating collector: %w", err)
	}

	return col.Run(ctx)
}
