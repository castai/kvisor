package state

import "context"

func (c *Controller) runProcessTreePipeline(ctx context.Context) error {
	c.log.Info("running events pipeline")
	defer c.log.Info("events pipeline done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.processTreeCollector.Events():
			for _, exporter := range c.exporters.ProcessTree {
				exporter.Enqueue(e)
			}
		}
	}
}
