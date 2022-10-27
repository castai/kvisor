package metrics

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	ScanTypeImage     = "image"
	ScanTypeKubeBench = "kube-bench"
	ScanTypeLinter    = "linter"
	ScanTypeCloud     = "cloud"

	ScanStatusOK    = "ok"
	ScanStatusError = "error"
)

var (
	ScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castai_sec_agent_scans_total",
		Help: "Counter tracking scans and statuses",
	}, []string{"scan_type", "scan_status"})

	ScansDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "castai_sec_agent_scans_duration",
		Help:    "Histogram tracking scan durations in milliseconds",
		Buckets: nil,
	}, []string{"scan_type"})

	DeltasSentTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castai_sec_agent_deltas_sent_total",
		Help: "Counter tracking deltas sent",
	})
)

func init() {
	prometheus.MustRegister(
		ScansTotal,
		ScansDuration,
		DeltasSentTotal,
	)
}

func ScanStatus(err error) string {
	if err != nil && !errors.Is(err, context.Canceled) {
		return ScanStatusError
	}
	return ScanStatusOK
}
