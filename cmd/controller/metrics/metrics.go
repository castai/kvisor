package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	EventTypeLabel   string = "event_type"
	ExporterName     string = "exporter"
	MetricLabel      string = "metric"
	EBPFProgramLabel string = "program"
)

var (
	ControllerImagesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kvisor_controller_images_count",
	})

	ControllerPendingImagesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kvisor_controller_pending_images_count",
	})
)
