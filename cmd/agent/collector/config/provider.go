package config

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/confmap"
)

const providerScheme = "kvisor"

// NewStaticProviderFactory returns a confmap.ProviderFactory that serves the
// hardcoded OTel collector pipeline configuration built from cfg.
func NewStaticProviderFactory(cfg *Config) confmap.ProviderFactory {
	return confmap.NewProviderFactory(func(_ confmap.ProviderSettings) confmap.Provider {
		return &staticProvider{cfg: cfg}
	})
}

type staticProvider struct {
	cfg *Config
}

func (p *staticProvider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if uri != providerScheme+":" {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, providerScheme)
	}
	return confmap.NewRetrieved(Build(p.cfg))
}

func (p *staticProvider) Scheme() string { return providerScheme }

func (p *staticProvider) Shutdown(_ context.Context) error { return nil }
