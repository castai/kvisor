package castai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
)

type logsExporter interface {
	AddLogEvent(e *castaipb.LogEvent)
}

type PromMetricsExporterConfig struct {
	MetricsPrefix  string
	ExportInterval time.Duration
}

func NewPromMetricsExporter(log *logging.Logger, logsExporter logsExporter, gatherer prometheus.Gatherer, cfg PromMetricsExporterConfig) *PromMetricsExporter {
	return &PromMetricsExporter{
		log:          log,
		logsExporter: logsExporter,
		gatherer:     gatherer,
		cfg:          cfg,
	}
}

type PromMetricsExporter struct {
	log          *logging.Logger
	logsExporter logsExporter
	gatherer     prometheus.Gatherer
	cfg          PromMetricsExporterConfig
}

func (e *PromMetricsExporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(e.cfg.ExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := e.export(); err != nil {
				e.log.Errorf("exporting prom metrics: %v", err)
			}
		}
	}
}

func (e *PromMetricsExporter) export() error {
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return err
	}
	var msgs []string
	for _, metric := range metrics {
		name := metric.GetName()
		if e.cfg.MetricsPrefix != "" && !strings.HasPrefix(name, e.cfg.MetricsPrefix) {
			continue
		}
		for _, m := range metric.Metric {
			var labels []string
			for _, pair := range m.GetLabel() {
				pair.GetName()
				labels = append(labels, fmt.Sprintf("%s=%s", pair.GetName(), pair.GetValue()))
			}
			var val float64
			if v := m.GetCounter(); v != nil {
				val = v.GetValue()
			} else if v := m.GetGauge(); v != nil {
				val = v.GetValue()
			} else {
				continue
			}
			msgs = append(msgs, fmt.Sprintf("%s %s %d", name, strings.Join(labels, " "), int(val)))
		}
	}
	e.logsExporter.AddLogEvent(&castaipb.LogEvent{
		Level: int32(slog.LevelInfo),
		Msg:   fmt.Sprintf("kvisor metrics:\n%s", strings.Join(msgs, "\n")),
	})
	return nil
}
