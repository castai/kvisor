package castai

import (
	"context"
	"log/slog"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
)

func NewLogsExporter(client *Client) *LogsExporter {
	return &LogsExporter{
		client:   client,
		logsChan: make(chan *castaipb.LogEvent, 1000),
	}
}

type LogsExporter struct {
	client   *Client
	logsChan chan *castaipb.LogEvent
}

func (l *LogsExporter) Run(ctx context.Context) error {
	ws := NewWriteStream[*castaipb.LogEvent, *castaipb.SendLogsResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return l.client.GRPC.LogsWriteStream(ctx)
	})
	defer ws.Close()
	ws.ReopenDelay = 1 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-l.logsChan:
			_ = ws.Send(e)
		}
	}
}

func (l *LogsExporter) ExportFunc() logging.ExportFunc {
	return func(ctx context.Context, record slog.Record) {
		select {
		case l.logsChan <- &castaipb.LogEvent{
			Level: int32(record.Level),
			Msg:   record.Message,
		}:
		default:
		}
	}
}

func (l *LogsExporter) AddLogEvent(e *castaipb.LogEvent) {
	select {
	case l.logsChan <- e:
	default:
	}
}
