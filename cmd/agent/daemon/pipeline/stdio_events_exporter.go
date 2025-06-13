package pipeline

import (
	"context"
	"fmt"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
)

func NewStdioEventsExporter(log *logging.Logger) *StdioEventsExporter {
	return &StdioEventsExporter{
		log:   log.WithField("component", "stdio_events_exporter"),
		queue: make(chan *castpb.Event, 1000),
	}
}

type StdioEventsExporter struct {
	log   *logging.Logger
	queue chan *castpb.Event
}

func (c *StdioEventsExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			fmt.Printf("event: %+v\n", e)
		}
	}
}

func (c *StdioEventsExporter) Enqueue(e *castpb.Event) {
	select {
	case c.queue <- e:
	default:
	}
}
