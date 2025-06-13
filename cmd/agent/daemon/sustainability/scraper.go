package sustainability

import (
	"context"
	"fmt"
	dto "github.com/prometheus/client_model/go"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/expfmt"
)

const (
	DefaultKeplerEndpoint = "http://localhost:8888/metrics"
	DefaultScrapeInterval = 30 * time.Second
	ScrapeTimeout         = 15 * time.Second
	KeplerMetricName      = "kepler_container_joules_total"
)

// Config holds configuration for the sustainability scraper
type Config struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	KeplerEndpoint string        `yaml:"keplerEndpoint" json:"keplerEndpoint"`
	ScrapeInterval time.Duration `yaml:"scrapeInterval" json:"scrapeInterval"`
	NodeName       string        `yaml:"nodeName" json:"nodeName"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig(nodeName string) *Config {
	return &Config{
		Enabled:        true,
		KeplerEndpoint: DefaultKeplerEndpoint,
		ScrapeInterval: DefaultScrapeInterval,
		NodeName:       nodeName,
	}
}

// Scraper collects sustainability metrics from local Kepler sidecar
type Scraper struct {
	log    *logging.Logger
	cfg    *Config
	client *http.Client
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Prometheus metrics using promauto pattern
	containerEnergyJoules *prometheus.GaugeVec

	// Internal metrics for monitoring the scraper itself
	scrapeDuration    prometheus.Histogram
	scrapeErrors      prometheus.Counter
	lastScrapeSuccess prometheus.Gauge
}

// NewScraper creates a new sustainability scraper following kvisor patterns
func NewScraper(log *logging.Logger, cfg *Config, registry prometheus.Registerer) *Scraper {
	factory := promauto.With(registry)

	return &Scraper{
		log:    log.WithField("component", "sustainability"),
		cfg:    cfg,
		client: &http.Client{Timeout: ScrapeTimeout},
		stopCh: make(chan struct{}),

		// Main sustainability metric
		containerEnergyJoules: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "kvisor",
				Subsystem: "sustainability",
				Name:      "container_joules_total",
				Help:      "Total energy consumption in Joules per container, sourced from Kepler",
			},
			[]string{"node_name", "namespace", "pod_name", "container_name"},
		),

		// Internal metrics for monitoring
		scrapeDuration: factory.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "kvisor",
				Subsystem: "sustainability",
				Name:      "scrape_duration_seconds",
				Help:      "Duration of sustainability metrics scrape operations",
				Buckets:   prometheus.DefBuckets,
			},
		),
		scrapeErrors: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: "kvisor",
				Subsystem: "sustainability",
				Name:      "scrape_errors_total",
				Help:      "Total number of scrape errors",
			},
		),
		lastScrapeSuccess: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "kvisor",
				Subsystem: "sustainability",
				Name:      "last_scrape_timestamp_seconds",
				Help:      "Timestamp of the last successful scrape",
			},
		),
	}
}

// Start begins the scraper main loop
func (s *Scraper) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info("Sustainability scraper disabled in configuration")
		return nil
	}

	s.log.Infof("Starting sustainability scraper, endpoint=%s, interval=%v",
		s.cfg.KeplerEndpoint, s.cfg.ScrapeInterval)

	s.wg.Add(1)
	go s.run(ctx)

	return nil
}

// Stop gracefully stops the scraper
func (s *Scraper) Stop() {
	s.log.Info("Stopping sustainability scraper")
	close(s.stopCh)
	s.wg.Wait()
}

// run is the main scraper loop
func (s *Scraper) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.ScrapeInterval)
	defer ticker.Stop()

	// Perform initial scrape
	s.scrapeKepler(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scrapeKepler(ctx)
		}
	}
}

// scrapeKepler performs a single scrape operation
func (s *Scraper) scrapeKepler(ctx context.Context) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		s.scrapeDuration.Observe(duration.Seconds())
		s.log.Debugf("Kepler scrape completed in %v", duration)
	}()

	// Create request with context timeout
	scrapeCtx, cancel := context.WithTimeout(ctx, ScrapeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(scrapeCtx, "GET", s.cfg.KeplerEndpoint, nil)
	if err != nil {
		s.log.Errorf("Failed to create scrape request: %v", err)
		s.scrapeErrors.Inc()
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Errorf("Failed to scrape Kepler endpoint: %v", err)
		s.scrapeErrors.Inc()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.log.Errorf("Kepler endpoint returned status %d", resp.StatusCode)
		s.scrapeErrors.Inc()
		return
	}

	// Parse metrics
	metrics, err := s.parseKeplerMetrics(resp.Body)
	if err != nil {
		s.log.Errorf("Failed to parse Kepler metrics: %v", err)
		s.scrapeErrors.Inc()
		return
	}

	// Update Prometheus metrics
	s.updateMetrics(metrics)
	s.lastScrapeSuccess.SetToCurrentTime()

	s.log.Debugf("Successfully processed %d Kepler metrics", len(metrics))
}

// parseKeplerMetrics parses Prometheus text format from Kepler
func (s *Scraper) parseKeplerMetrics(reader io.Reader) ([]*KeplerMetric, error) {
	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse prometheus metrics: %w", err)
	}

	var metrics []*KeplerMetric

	// Look for the kepler_container_joules_total metric family
	metricFamily, found := metricFamilies[KeplerMetricName]
	if !found {
		s.log.Debugf("Metric family %s not found in Kepler response", KeplerMetricName)
		return metrics, nil
	}

	// Process each metric in the family
	for _, metric := range metricFamily.GetMetric() {
		keplerMetric, err := s.convertToKeplerMetric(metric)
		if err != nil {
			s.log.Warnf("Failed to convert metric: %v", err)
			continue
		}

		if keplerMetric != nil {
			metrics = append(metrics, keplerMetric)
		}
	}

	return metrics, nil
}

// convertToKeplerMetric converts a protobuf metric to our internal format
func (s *Scraper) convertToKeplerMetric(metric *dto.Metric) (*KeplerMetric, error) {
	// Extract required labels
	containerNamespace, err := s.findLabelValue(metric.GetLabel(), "container_namespace")
	if err != nil {
		return nil, err
	}

	podName, err := s.findLabelValue(metric.GetLabel(), "pod_name")
	if err != nil {
		return nil, err
	}

	containerName, err := s.findLabelValue(metric.GetLabel(), "container_name")
	if err != nil {
		return nil, err
	}

	// Get the metric value
	var value float64
	if metric.GetCounter() != nil {
		value = metric.GetCounter().GetValue()
	} else if metric.GetGauge() != nil {
		value = metric.GetGauge().GetValue()
	} else {
		return nil, fmt.Errorf("unsupported metric type")
	}

	return &KeplerMetric{
		NodeName:           s.cfg.NodeName,
		ContainerNamespace: containerNamespace,
		PodName:            podName,
		ContainerName:      containerName,
		Value:              value,
	}, nil
}

// findLabelValue extracts a label value by name
func (s *Scraper) findLabelValue(labels []*dto.LabelPair, labelName string) (string, error) {
	for _, label := range labels {
		if label.GetName() == labelName {
			return label.GetValue(), nil
		}
	}
	return "", fmt.Errorf("missing %s label", labelName)
}

// updateMetrics updates Prometheus metrics with scraped data
func (s *Scraper) updateMetrics(metrics []*KeplerMetric) {
	for _, metric := range metrics {
		s.containerEnergyJoules.WithLabelValues(
			metric.NodeName,
			metric.ContainerNamespace,
			metric.PodName,
			metric.ContainerName,
		).Set(metric.Value)
	}
}

// KeplerMetric represents a parsed Kepler energy metric
type KeplerMetric struct {
	NodeName           string
	ContainerNamespace string
	PodName            string
	ContainerName      string
	Value              float64
}
