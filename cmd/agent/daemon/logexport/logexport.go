package logexport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
)

func New(client castpb.RuntimeSecurityAgentAPIClient) *Exporter {
	return &Exporter{
		client:   client,
		logsChan: make(chan slog.Record, 1000),
	}
}

type Exporter struct {
	client   castpb.RuntimeSecurityAgentAPIClient
	logsChan chan slog.Record
}

func (l *Exporter) Run(ctx context.Context) error {
	var writeStream castpb.RuntimeSecurityAgentAPI_LogsWriteStreamClient
	var err error

	defer func() {
		if writeStream != nil {
			_ = writeStream.CloseSend()
		}
	}()

	for {
		if writeStream == nil {
			writeStream, err = l.client.LogsWriteStream(ctx)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-l.logsChan:
			if err := writeStream.Send(&castpb.LogEvent{
				Level: int32(e.Level),
				Msg:   e.Message,
			}); err != nil {
				if errors.Is(err, io.EOF) {
					writeStream = nil
				}
			}
		}
	}
}

func (l *Exporter) ExportFunc() logging.ExportFunc {
	return func(ctx context.Context, record slog.Record) {
		select {
		case l.logsChan <- record:
		default:
		}
	}
}
