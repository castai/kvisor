package castai

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/stretchr/testify/require"
)

func TestPrometheusExporter(t *testing.T) {
	r := require.New(t)

	// Add test metric to default prometheus.DefaultGatherer.
	testMetric1 := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_test_counter",
	}, []string{"event_type"})
	testMetric1.WithLabelValues("exec").Add(10)

	testMetric2 := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kvisor_test_gauge",
	}, []string{"event_type", "event_name"})
	testMetric2.WithLabelValues("tcp_connect", "Connect").Add(15)

	testMetric3 := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "other_non_kvisor_metric",
	}, []string{"event_type"})
	testMetric3.WithLabelValues("other").Add(15)

	log := logging.NewTestLog()
	logsExp := &mockLogsExporter{}
	exp := NewPromMetricsExporter(log, logsExp, prometheus.DefaultGatherer, PromMetricsExporterConfig{
		MetricsPrefix:  "kvisor_test",
		PodName:        "pod1",
		ExportInterval: time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go exp.Run(ctx)

	r.Eventually(func() bool {
		logsExp.mu.Lock()
		defer logsExp.mu.Unlock()
		return len(logsExp.logs) == 2
	}, time.Second, time.Millisecond)

	cancel()

	r.Len(logsExp.logs, 2)
	r.Equal(`kvisor metrics, pod=pod1:
kvisor_test_counter event_type=exec 10
kvisor_test_gauge event_name=Connect event_type=tcp_connect 15`, logsExp.logs[0].Msg)
}

type mockLogsExporter struct {
	logs []*v1.LogEvent
	mu   sync.Mutex
}

func (m *mockLogsExporter) AddLogEvent(e *v1.LogEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logs = append(m.logs, e)
}
