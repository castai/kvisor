package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/time/rate"
)

type Config struct {
	Ctx         context.Context
	RateLimiter RateLimiterConfig
	Level       slog.Level
	AddSource   bool
	Output      io.Writer
	Export      ExportConfig
}

type RateLimiterConfig struct {
	Limit  rate.Limit
	Burst  int
	Inform bool
}

type ExportConfig struct {
	ExportFunc ExportFunc
	MinLevel   slog.Level
}

func MustParseLevel(lvlStr string) slog.Level {
	var lvl slog.Level
	err := lvl.UnmarshalText([]byte(lvlStr))
	if err != nil {
		panic("parsing log level from level string " + lvlStr)
	}
	return lvl
}

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{})))
}

func New(cfg *Config) *Logger {
	out := cfg.Output
	if out == nil {
		out = os.Stdout
	}
	if cfg.Ctx == nil {
		cfg.Ctx = context.Background()
	}
	var replace func(groups []string, a slog.Attr) slog.Attr
	if cfg.AddSource {
		replace = func(groups []string, a slog.Attr) slog.Attr {
			// Remove the directory from the source's filename.
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)
			}
			return a
		}
	}

	// Initial logger.
	var handler slog.Handler = slog.NewTextHandler(out, &slog.HandlerOptions{
		AddSource:   cfg.AddSource,
		Level:       cfg.Level,
		ReplaceAttr: replace,
	})

	// Export logs handler.
	if cfg.Export.ExportFunc != nil {
		handler = NewExportHandler(cfg.Ctx, handler, cfg.Export)
	}

	// Rate limiter handler.
	if cfg.RateLimiter.Limit != 0 {
		handler = NewRateLimiterHandler(cfg.Ctx, handler, cfg.RateLimiter)
	}

	log := slog.New(handler)
	return &Logger{log: log}
}

func NewTestLog() *Logger {
	return New(&Config{Level: slog.LevelDebug})
}

type Logger struct {
	log *slog.Logger
}

func (l *Logger) Error(msg string) {
	l.doLog(slog.LevelError, msg) //nolint:govet
}

func (l *Logger) Errorf(format string, a ...any) {
	l.doLog(slog.LevelError, format, a...)
}

func (l *Logger) Infof(format string, a ...any) {
	l.doLog(slog.LevelInfo, format, a...)
}

func (l *Logger) Info(msg string) {
	l.doLog(slog.LevelInfo, msg) //nolint:govet
}

func (l *Logger) Debug(msg string) {
	l.doLog(slog.LevelDebug, msg) //nolint:govet
}

func (l *Logger) Debugf(format string, a ...any) {
	l.doLog(slog.LevelDebug, format, a...)
}

func (l *Logger) Warn(msg string) {
	l.doLog(slog.LevelWarn, msg) //nolint:govet
}

func (l *Logger) Warnf(format string, a ...any) {
	l.doLog(slog.LevelWarn, format, a...)
}

func (l *Logger) Fatal(msg string) {
	l.doLog(slog.LevelError, msg) //nolint:govet
	os.Exit(1)
}

func (l *Logger) IsEnabled(lvl slog.Level) bool {
	ctx := context.Background()
	return l.log.Handler().Enabled(ctx, lvl)
}

func (l *Logger) doLog(lvl slog.Level, msg string, args ...any) {
	ctx := context.Background()
	if !l.log.Handler().Enabled(ctx, lvl) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	if len(args) > 0 {
		r := slog.NewRecord(time.Now(), lvl, fmt.Sprintf(msg, args...), pcs[0])
		_ = l.log.Handler().Handle(ctx, r) //nolint:contextcheck
	} else {
		r := slog.NewRecord(time.Now(), lvl, msg, pcs[0])
		_ = l.log.Handler().Handle(ctx, r) //nolint:contextcheck
	}
}

func (l *Logger) With(args ...any) *Logger {
	return &Logger{log: l.log.With(args...)}
}

func (l *Logger) WithField(k, v string) *Logger {
	return &Logger{log: l.log.With(slog.String(k, v))}
}
