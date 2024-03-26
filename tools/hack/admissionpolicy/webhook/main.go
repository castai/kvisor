package main

import (
	"context"
	"log/slog"

	"github.com/castai/kvisor/pkg/admissionpolicy"
	"github.com/castai/kvisor/pkg/logging"
)

func main() {
	log := logging.New(&logging.Config{
		Level:     slog.LevelInfo,
		AddSource: true,
	})

	eventSource := admissionpolicy.NewWebhookSource(log, admissionpolicy.WebhookConfig{
		ListenAddress: ":8080",
		EventBuffer:   100,
	})
	eventSink := admissionpolicy.NewEventSink(log)

	go func() {
		if err := eventSource.Start(context.Background()); err != nil {
			panic(err)
		}
	}()

	for batch := range eventSource.Events() {
		if err := eventSink.Write(batch); err != nil {
			panic(err)
		}
	}
}
