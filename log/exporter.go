package log

import (
	"context"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/castai"
)

const (
	sendTimeout = 15 * time.Second
)

type Exporter interface {
	logrus.Hook
	Wait()
}

func NewExporter(logger *logrus.Logger, client castai.Client, levels []logrus.Level) Exporter {
	return &exporter{
		logger: logger,
		client: client,
		wg:     sync.WaitGroup{},
		levels: levels,
	}
}

type exporter struct {
	logger *logrus.Logger
	client castai.Client
	wg     sync.WaitGroup
	levels []logrus.Level
}

func (e *exporter) Levels() []logrus.Level {
	return e.levels
}

func (ex *exporter) Fire(entry *logrus.Entry) error {
	ex.wg.Add(1)

	go func(entry *logrus.Entry) {
		defer ex.wg.Done()
		ex.sendLogEvent(entry)
	}(entry)

	return nil
}

func (ex *exporter) Wait() {
	ex.wg.Wait()
}

func (e *exporter) sendLogEvent(log *logrus.Entry) {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	req := &castai.LogEvent{
		Level:   log.Level.String(),
		Time:    log.Time,
		Message: log.Message,
		Fields:  log.Data,
	}

	b := backoff.WithContext(backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3), ctx)
	err := backoff.Retry(func() error {
		return e.client.SendLogs(ctx, req)
	}, b)

	if err != nil {
		e.logger.Debugf("sending logs: %v", err)
	}
}
