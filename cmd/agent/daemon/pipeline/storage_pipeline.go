package pipeline

import (
	"context"
	"fmt"
	"time"
)

func (c *Controller) runStoragePipeline(ctx context.Context) error {
	c.log.Info("running storage stats pipeline")
	defer c.log.Info("storage stats pipeline done")

	ticker := time.NewTicker(c.cfg.Stats.ScrapeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			start := time.Now()
			c.collectStorageMetrics(ctx)
			c.collectNodeStatsSummary(ctx)
			c.log.Debugf("storage stats exported, duration=%v", time.Since(start))
		}
	}
}

func (c *Controller) collectStorageMetrics(ctx context.Context) {
	start := time.Now()
	c.log.Debug("starting storage stats collection")

	timestamp := time.Now().UTC()
	if err := c.processBlockDeviceMetrics(timestamp); err != nil {
		c.log.Errorf("failed to collect block device metrics: %v", err)
	}

	if err := c.processFilesystemMetrics(timestamp); err != nil {
		c.log.Errorf("failed to collect filesystem metrics: %v", err)
	}

	if err := c.processPodVolumeMetrics(ctx); err != nil {
		c.log.Errorf("failed to collect pod volume metrics: %v", err)
	}

	c.log.Debugf("storage stats collection completed in %v", time.Since(start))
}

func (c *Controller) processBlockDeviceMetrics(timestamp time.Time) error {
	if c.blockDeviceMetricsWriter == nil {
		return fmt.Errorf("block device metrics writer not initialized")
	}

	blockMetrics, err := c.storageInfoProvider.BuildBlockDeviceMetrics(timestamp)
	if err != nil {
		return fmt.Errorf("failed to collect block device metrics: %w", err)
	}

	c.log.Infof("collected %d block device metrics", len(blockMetrics))

	if err := c.blockDeviceMetricsWriter.Write(blockMetrics...); err != nil {
		return fmt.Errorf("failed to write block device metrics: %w", err)
	}

	return nil
}

func (c *Controller) processFilesystemMetrics(timestamp time.Time) error {
	if c.filesystemMetricsWriter == nil {
		return fmt.Errorf("filesystem metrics writer not initialized")
	}

	fsMetrics, err := c.storageInfoProvider.BuildFilesystemMetrics(timestamp)
	if err != nil {
		return fmt.Errorf("failed to collect filesystem metrics: %w", err)
	}

	c.log.Infof("collected %d filesystem metrics", len(fsMetrics))

	if err := c.filesystemMetricsWriter.Write(fsMetrics...); err != nil {
		return fmt.Errorf("failed to write filesystem metric: %w", err)
	}

	return nil
}

func (c *Controller) processPodVolumeMetrics(ctx context.Context) error {
	if c.podVolumeMetricsWriter == nil {
		return nil // Pod volume metrics writer not configured, skip
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	metrics, err := c.storageInfoProvider.CollectPodVolumeMetrics(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect pod volume metrics: %w", err)
	}

	if len(metrics) == 0 {
		return nil
	}

	c.log.Infof("collected %d pod volume metrics", len(metrics))

	if err := c.podVolumeMetricsWriter.Write(metrics...); err != nil {
		return fmt.Errorf("failed to write pod volume metrics: %w", err)
	}

	return nil
}

func (c *Controller) collectNodeStatsSummary(ctx context.Context) {
	if c.nodeStatsSummaryWriter == nil || c.storageInfoProvider == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	metric, err := c.storageInfoProvider.CollectNodeStatsSummary(ctx)
	if err != nil {
		c.log.Errorf("failed to collect node stats summary: %v", err)
		return
	}

	c.log.Info("collected node stats summary")

	if err := c.nodeStatsSummaryWriter.Write(*metric); err != nil {
		c.log.Errorf("failed to write node stats summary: %v", err)
	}
}
