package pipeline

import "time"

func newDataBatchStats() *dataBatchStats {
	return &dataBatchStats{}
}

type dataBatchStats struct {
	sizeBytes  int
	totalItems int
	lastSentAt time.Time
}

func (d *dataBatchStats) reset() {
	d.sizeBytes = 0
	d.totalItems = 0
	d.lastSentAt = time.Now()
}
