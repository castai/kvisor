package logging_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestLogger(t *testing.T) {
	t.Run("print long", func(t *testing.T) {
		log := logging.New(&logging.Config{
			Level:     logging.MustParseLevel("DEBUG"),
			AddSource: true,
		})

		log.Errorf("something wrong: %v", errors.New("ups"))
		serverLog := log.WithField("component", "server")
		serverLog.Info("with component")
		serverLog.Info("more server logs")
	})

	t.Run("rate limit", func(t *testing.T) {
		var out bytes.Buffer
		log := logging.New(&logging.Config{
			Output: &out,
			Level:  logging.MustParseLevel("DEBUG"),
			RateLimiter: logging.RateLimiterConfig{
				Limit: rate.Every(10 * time.Millisecond),
				Burst: 1,
			},
		})

		for i := 0; i < 10; i++ {
			log.WithField("component", "test").Info("test")
			time.Sleep(8 * time.Millisecond)
		}

		require.GreaterOrEqual(t, countLogLines(&out), 5)
	})

	t.Run("export logs", func(t *testing.T) {
		exportedLogs := make(chan slog.Record, 1)
		log := logging.New(&logging.Config{
			Level: logging.MustParseLevel("DEBUG"),
			Export: logging.ExportConfig{
				ExportFunc: func(ctx context.Context, record slog.Record) {
					exportedLogs <- record
				},
				MinLevel: slog.LevelInfo,
			},
		})

		//log.Debug("should not export debug")
		log.WithField("component", "test").Error("should export error")

		select {
		case logRecord := <-exportedLogs:
			require.Equal(t, logRecord.Message, "should export error")
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})
}

func countLogLines(buf *bytes.Buffer) int {
	var n int
	for _, b := range buf.Bytes() {
		if b == '\n' {
			n++
		}
	}
	return n
}
