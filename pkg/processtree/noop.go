package processtree

import "time"

type NoopProcessTreeCollector struct {
	dummyChan chan ProcessTreeEvent
}

func NewNoop() *NoopProcessTreeCollector {
	return &NoopProcessTreeCollector{
		dummyChan: make(chan ProcessTreeEvent),
	}
}

func (d *NoopProcessTreeCollector) Events() <-chan ProcessTreeEvent {
	return d.dummyChan
}

func (d *NoopProcessTreeCollector) ProcessExited(eventTime time.Time, containerID string, processKey ProcessKey, parent ProcessKey, exitTime uint64) {
}

func (d *NoopProcessTreeCollector) ProcessForked(eventTime time.Time, containerID string, parent ProcessKey, processKey ProcessKey) {
}

func (d *NoopProcessTreeCollector) ProcessStarted(eventTime time.Time, containerID string, p Process) {
}
