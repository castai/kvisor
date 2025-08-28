package pipeline

import (
	"context"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/cmd/agent/daemon/sustainability"
)

func (c *Controller) runSustainabilityPipeline(ctx context.Context) error {
	c.log.Info("running sustainability pipeline")
	defer c.log.Info("sustainability pipeline done")

	scraper := sustainability.NewScraper(c.cfg.Sustainability.KeplerEndpoint)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			start := time.Now()
			stats, err := scraper.ScrapeMetrics()
			if err != nil {
				c.log.Warnf("failed to scrape sustainability metrics: %v", err)
				continue
			}

			if len(stats) == 0 {
				c.log.Debug("no sustainability stats scraped")
				continue
			}

			items := make([]*castaipb.DataBatchItem, 0, len(stats))
			for _, stat := range stats {
				items = append(items, &castaipb.DataBatchItem{
					Data: &castaipb.DataBatchItem_SustainabilityStats{
						SustainabilityStats: stat,
					},
				})
			}

			c.sendDataBatch("sustainability stats scrape", metrics.PipelineSustainability, items)
			c.log.Debugf("sustainability stats exported, count=%d, duration=%v", len(stats), time.Since(start))
		}
	}
}
