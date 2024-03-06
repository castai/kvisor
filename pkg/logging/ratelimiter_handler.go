package logging

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

func NewRateLimiterHandler(ctx context.Context, next slog.Handler, cfg RateLimiterConfig) slog.Handler {
	droppedLogsCounters := map[slog.Level]*atomic.Uint64{
		slog.LevelDebug: {},
		slog.LevelInfo:  {},
		slog.LevelWarn:  {},
		slog.LevelError: {},
	}
	logsRate := cfg.Limit
	burst := cfg.Burst
	if cfg.Inform {
		go printDroppedLogsCounter(ctx, droppedLogsCounters)
	}
	return &RateLimiterHandler{
		next: next,
		rt: map[slog.Level]*rate.Limiter{
			slog.LevelDebug: rate.NewLimiter(logsRate, burst),
			slog.LevelInfo:  rate.NewLimiter(logsRate, burst),
			slog.LevelWarn:  rate.NewLimiter(logsRate, burst),
			slog.LevelError: rate.NewLimiter(logsRate, burst),
		},
		droppedLogsCounters: droppedLogsCounters,
	}
}

type RateLimiterHandler struct {
	next                slog.Handler
	rt                  map[slog.Level]*rate.Limiter
	droppedLogsCounters map[slog.Level]*atomic.Uint64
}

func (s *RateLimiterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if !s.next.Enabled(ctx, level) {
		return false
	}
	if !s.rt[level].Allow() {
		s.droppedLogsCounters[level].Add(1)
		return false
	}
	return true
}

func (s *RateLimiterHandler) Handle(ctx context.Context, record slog.Record) error {
	return s.next.Handle(ctx, record)
}

func (s *RateLimiterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &RateLimiterHandler{
		next:                s.next.WithAttrs(attrs),
		rt:                  s.rt,
		droppedLogsCounters: s.droppedLogsCounters,
	}
}

func (s *RateLimiterHandler) WithGroup(name string) slog.Handler {
	return &RateLimiterHandler{
		next:                s.next.WithGroup(name),
		rt:                  s.rt,
		droppedLogsCounters: s.droppedLogsCounters,
	}
}

func printDroppedLogsCounter(ctx context.Context, droppedLogsCounters map[slog.Level]*atomic.Uint64) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for level, val := range droppedLogsCounters {
				count := val.Load()
				if count > 0 {
					slog.Warn(fmt.Sprintf("logs rate limit, dropped %d lines for level %s", count, level.String()))
					val.Store(0)
				}
			}
		}
	}
}
