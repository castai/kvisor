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

	eventSource := admissionpolicy.NewWebhookSource(log, "0.0.0.0:8080")
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
