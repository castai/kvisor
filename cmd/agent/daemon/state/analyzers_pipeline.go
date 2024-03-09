package state

import (
	"context"
)

func (c *Controller) runAnalyzersLoop(ctx context.Context) error {
	c.log.Info("running analyzers loop")
	defer c.log.Info("analyzers loop done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.analyzersService.Results():
			c.eventsExportQueue <- e
		}
	}
}
