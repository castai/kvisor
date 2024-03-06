package logging

import (
	"context"
	"log/slog"
)

type ExportFunc func(ctx context.Context, record slog.Record)

func NewExportHandler(ctx context.Context, next slog.Handler, cfg ExportConfig) slog.Handler {
	handler := &ExportHandler{
		next: next,
		cfg:  cfg,
		ch:   make(chan slog.Record, 1000),
	}
	go handler.run(ctx)

	return handler
}

type ExportHandler struct {
	next slog.Handler
	cfg  ExportConfig

	ch chan slog.Record
}

func (e *ExportHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return e.next.Enabled(ctx, level)
}

func (e *ExportHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= e.cfg.MinLevel {
		e.cfg.ExportFunc(ctx, record)
	}

	return e.next.Handle(ctx, record)
}

func (e *ExportHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ExportHandler{
		next: e.next.WithAttrs(attrs),
		cfg:  e.cfg,
		ch:   e.ch,
	}
}

func (e *ExportHandler) WithGroup(name string) slog.Handler {
	return &ExportHandler{
		next: e.next.WithGroup(name),
		cfg:  e.cfg,
		ch:   e.ch,
	}
}

func (e *ExportHandler) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case record := <-e.ch:
			e.cfg.ExportFunc(ctx, record)
		}
	}
}
