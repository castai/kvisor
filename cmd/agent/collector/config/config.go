package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
)

// Config holds the collector application configuration.
// The OTel pipeline (receivers, processors, exporters) is built from these
// values at startup; see Build for the generated pipeline config.
type Config struct {
	// OTLPHTTPEndpoint is the endpoint for the OTLP HTTP receiver.
	OTLPHTTPEndpoint string

	// MetricsExporterPort is the port used by the metrics export pipeline.
	// Once prometheusexporter is available (requires updating the prometheus/prometheus
	// replace in go.mod past v0.54.0), this will become the Prometheus scrape port.
	MetricsExporterPort int

	// HealthCheckEndpoint is the address for the health-check extension.
	HealthCheckEndpoint string

	// ClickHouseEnabled enables the ClickHouse exporter pipeline.
	ClickHouseEnabled bool

	// ClickHouseAddr is the ClickHouse TCP connection string.
	// Example: tcp://clickhouse:9000?dial_timeout=10s&compress=lz4
	ClickHouseAddr string

	// ClickHouseDatabase is the ClickHouse target database.
	ClickHouseDatabase string

	// ClickHouseUsername is the ClickHouse username.
	ClickHouseUsername string

	// ClickHousePassword is the ClickHouse password.
	ClickHousePassword string

	// ClickHouseBatchTimeout overrides the default 30s ClickHouse pipeline batch
	// flush timeout. Useful for testing. If empty, defaults to "30s".
	ClickHouseBatchTimeout string
}

// Validate checks that all required Config fields are populated. It returns the
// first validation error encountered so the caller gets a readable message
// instead of a cryptic error from deep inside the OTel framework.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.OTLPHTTPEndpoint); err != nil {
		return fmt.Errorf("OTLPHTTPEndpoint %q is not a valid host:port address: %w", c.OTLPHTTPEndpoint, err)
	}
	if c.MetricsExporterPort <= 0 || c.MetricsExporterPort > 65535 {
		return fmt.Errorf("MetricsExporterPort %d is not a valid port number", c.MetricsExporterPort)
	}
	if _, _, err := net.SplitHostPort(c.HealthCheckEndpoint); err != nil {
		return fmt.Errorf("HealthCheckEndpoint %q is not a valid host:port address: %w", c.HealthCheckEndpoint, err)
	}
	if c.ClickHouseEnabled {
		u, err := url.Parse(c.ClickHouseAddr)
		if err != nil || u.Scheme != "tcp" || u.Host == "" {
			return fmt.Errorf("ClickHouseAddr %q must be a valid tcp:// URI (e.g. tcp://host:9000)", c.ClickHouseAddr)
		}
		if c.ClickHouseDatabase == "" {
			return errors.New("ClickHouseDatabase must not be empty when ClickHouseEnabled is true")
		}
	}
	return nil
}
