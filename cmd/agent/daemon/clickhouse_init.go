package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	clickhouseexport "github.com/castai/kvisor/cmd/agent/daemon/export/clickhouse"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/spf13/cobra"
)

func NewClickhouseInitCommand() *cobra.Command {
	var (
		clickhouseAddr     string
		clickhouseDatabase string
		clickhouseUsername string
	)

	command := &cobra.Command{
		Use: "clickhouse-init",
		Run: func(cmd *cobra.Command, args []string) {
			log := logging.New(&logging.Config{})

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			run := func(ctx context.Context) error {
				conn, err := clickhouse.Open(&clickhouse.Options{
					Addr: []string{clickhouseAddr},
					Auth: clickhouse.Auth{
						Database: clickhouseDatabase,
						Username: clickhouseUsername,
						Password: os.Getenv("CLICKHOUSE_PASSWORD"),
					},
					Settings: clickhouse.Settings{
						"allow_experimental_object_type": "1",
					},
					MaxOpenConns: 20,
				})
				if err != nil {
					return err
				}
				defer conn.Close()

				if err := conn.Exec(ctx, clickhouseexport.ClickhouseContainerEventsSchema()); err != nil {
					return fmt.Errorf("creating clickhouse container events schema: %w", err)
				}
				if err := conn.Exec(ctx, clickhouseexport.ClickhouseNetflowSchema()); err != nil {
					return fmt.Errorf("creating clickhouse netflow schema: %w", err)
				}
				if err := conn.Exec(ctx, clickhouseexport.ClickhouseProcessTreeSchema()); err != nil {
					return fmt.Errorf("creating clickhouse process tree schema: %w", err)
				}
				if err := conn.Exec(ctx, clickhouseexport.ClickhouseSustainabilityStatsSchema()); err != nil {
					return fmt.Errorf("creating clickhouse sustainability stats schema: %w", err)
				}
				return nil
			}

			for i := 0; i < 10; i++ {
				if err := run(ctx); err != nil {
					log.Warnf("init failed, will retry: %v", err)
					time.Sleep(3 * time.Second)
					continue
				}

				<-ctx.Done()
			}

			log.Fatal("init failed after 10 attempts")
		},
	}

	command.Flags().StringVar(&clickhouseAddr, "clickhouse-addr", "", "clickhouse address")
	command.Flags().StringVar(&clickhouseDatabase, "clickhouse-database", "", "clickhouse database")
	command.Flags().StringVar(&clickhouseUsername, "clickhouse-username", "", "clickhouse username")
	return command
}
