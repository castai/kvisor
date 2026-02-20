package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/castai/kvisor/cmd/agent/collector/app"
	"github.com/castai/kvisor/cmd/agent/collector/config"
)

var Version = "local"

func main() {
	root := cobra.Command{
		Use:          "kvisor-collector",
		SilenceErrors: true, // errors are logged via slog below, not by cobra
		SilenceUsage:  true, // don't print usage on runtime errors
	}

	root.AddCommand(NewRunCommand(Version))

	if err := root.Execute(); err != nil {
		slog.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

func NewRunCommand(version string) *cobra.Command {
	command := &cobra.Command{
		Use:   "run",
		Short: "Run the OTel collector",
	}

	var (
		otlpHTTPEndpoint    = command.Flags().String("otlp-http-endpoint", "0.0.0.0:4318", "OTLP HTTP receiver endpoint")
		metricsExporterPort = command.Flags().Int("metrics-exporter-port", 9090, "Metrics exporter port (otlphttp for now; will become prometheus scrape port)")
		healthCheckEndpoint = command.Flags().String("health-check-endpoint", "0.0.0.0:13133", "Health check extension endpoint")

		clickhouseEnabled  = command.Flags().Bool("clickhouse-enabled", false, "Enable ClickHouse exporter pipeline")
		clickhouseAddr     = command.Flags().String("clickhouse-addr", "", "ClickHouse TCP connection string (e.g. tcp://host:9000?dial_timeout=10s&compress=lz4)")
		clickhouseDatabase = command.Flags().String("clickhouse-database", "otel", "ClickHouse database name")
		clickhouseUsername = command.Flags().String("clickhouse-username", "", "ClickHouse username")
		clickhousePassword = command.Flags().String("clickhouse-password", "", "ClickHouse password")
	)

	command.RunE = func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		cfg := &config.Config{
			OTLPHTTPEndpoint:    *otlpHTTPEndpoint,
			MetricsExporterPort: *metricsExporterPort,
			HealthCheckEndpoint: *healthCheckEndpoint,
			ClickHouseEnabled:   *clickhouseEnabled,
			ClickHouseAddr:      *clickhouseAddr,
			ClickHouseDatabase:  *clickhouseDatabase,
			ClickHouseUsername:  *clickhouseUsername,
			ClickHousePassword:  *clickhousePassword,
		}

		if err := app.New(cfg, version).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
	return command
}
