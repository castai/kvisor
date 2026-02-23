package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
)

var Version = "local"

//go:embed migrations/otel/*.sql
var otelMigrations embed.FS

func main() {
	root := newMigrateCommand()
	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func newMigrateCommand() *cobra.Command {
	var (
		clickhouseAddr     string
		clickhouseDatabase string
		clickhouseUsername string
		migrationType      string
	)

	command := &cobra.Command{
		Use:   "clickhouse-migrate",
		Short: "Run ClickHouse schema migrations for OTEL reliability metrics",
		Long: `Applies database migrations to ClickHouse for the OTEL reliability metrics pipeline.

Migrations are versioned and tracked in a goose_db_version table. The command
is idempotent - running it multiple times will only apply new migrations.

Migration types:
  otel    - Bronze/Silver/Gold medallion schema for reliability metrics (default)

Examples:
  # Run all pending OTEL migrations
  clickhouse-migrate --clickhouse-addr=localhost:9000 up

  # Check migration status
  clickhouse-migrate --clickhouse-addr=localhost:9000 status
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			subcommand := "up"
			if len(args) > 0 {
				subcommand = args[0]
			}

			return runMigrations(ctx, migrateConfig{
				addr:       clickhouseAddr,
				database:   clickhouseDatabase,
				username:   clickhouseUsername,
				password:   os.Getenv("CLICKHOUSE_PASSWORD"),
				migrations: migrationType,
				command:    subcommand,
			})
		},
	}

	command.Flags().StringVar(&clickhouseAddr, "clickhouse-addr", "localhost:9000", "ClickHouse address (host:port)")
	command.Flags().StringVar(&clickhouseDatabase, "clickhouse-database", "otel", "ClickHouse database name")
	command.Flags().StringVar(&clickhouseUsername, "clickhouse-username", "default", "ClickHouse username")
	command.Flags().StringVar(&migrationType, "migrations", "otel", "Migration type: otel")

	return command
}

type migrateConfig struct {
	addr       string
	database   string
	username   string
	password   string
	migrations string
	command    string
}

func runMigrations(ctx context.Context, cfg migrateConfig) error {
	goose.SetBaseFS(otelMigrations)
	if err := goose.SetDialect("clickhouse"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}

	// First connect without a database to create it if it doesn't exist.
	var bootstrapDB *sql.DB
	var err error

	for i := 0; i < 30; i++ {
		bootstrapCfg := cfg
		bootstrapCfg.database = "" // connect to default
		bootstrapDB, err = openClickHouseDB(bootstrapCfg)
		if err == nil {
			if pingErr := bootstrapDB.PingContext(ctx); pingErr == nil {
				break
			} else {
				err = pingErr
			}
		}

		slog.Warn("failed to connect to ClickHouse", "attempt", i+1, "max", 30, "error", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			continue
		}
	}

	if err != nil {
		return fmt.Errorf("connecting to ClickHouse after 30 attempts: %w", err)
	}

	// Create the target database if it doesn't exist.
	slog.Info("ensuring database exists", "database", cfg.database)
	if _, err := bootstrapDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", cfg.database)); err != nil {
		bootstrapDB.Close()
		return fmt.Errorf("creating database %s: %w", cfg.database, err)
	}
	bootstrapDB.Close()

	// Now connect to the target database.
	db, err := openClickHouseDB(cfg)
	if err != nil {
		return fmt.Errorf("connecting to database %s: %w", cfg.database, err)
	}
	defer db.Close()

	slog.Info("connected to ClickHouse", "addr", cfg.addr, "database", cfg.database)

	migrationsDir := "migrations/otel"
	if cfg.migrations != "otel" {
		return fmt.Errorf("unknown migration type: %s (supported: otel)", cfg.migrations)
	}

	switch cfg.command {
	case "up":
		slog.Info("running migrations: up")
		if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
		slog.Info("migrations completed successfully")

	case "up-one":
		slog.Info("running migrations: up-one")
		if err := goose.UpByOneContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("running migration: %w", err)
		}

	case "down":
		slog.Info("running migrations: down")
		if err := goose.DownContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("running migration down: %w", err)
		}

	case "status":
		slog.Info("checking migration status")
		if err := goose.StatusContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("getting migration status: %w", err)
		}

	case "version":
		slog.Info("getting current version")
		if err := goose.VersionContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("getting version: %w", err)
		}

	case "reset":
		slog.Warn("resetting all migrations (down to 0, then up)")
		if err := goose.ResetContext(ctx, db, migrationsDir); err != nil {
			return fmt.Errorf("resetting migrations: %w", err)
		}

	default:
		return fmt.Errorf("unknown command: %s (supported: up, up-one, down, status, version, reset)", cfg.command)
	}

	return nil
}

func openClickHouseDB(cfg migrateConfig) (*sql.DB, error) {
	opts := &clickhouse.Options{
		Addr: []string{cfg.addr},
		Auth: clickhouse.Auth{
			Database: cfg.database,
			Username: cfg.username,
			Password: cfg.password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout: 10 * time.Second,
	}

	return clickhouse.OpenDB(opts), nil
}
