package castai

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
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
	var writeStream castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamClient
	var err error

	defer func() {
		if writeStream != nil {
			_ = writeStream.CloseSend()
		}
	}()

	for {
		if writeStream == nil {
			writeStream, err = l.client.GRPC.LogsWriteStream(ctx)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-l.logsChan:
			if err := writeStream.Send(e); err != nil {
				if errors.Is(err, io.EOF) {
					writeStream = nil
				}
			}
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
