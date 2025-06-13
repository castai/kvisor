package sustainability

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

const (
	DefaultWorkerCount = 10
	ScrapeTimeout      = 15 * time.Second
	KeplerMetricName   = "kepler_container_joules_total"
)

type ScrapeTarget struct {
	PodName   string
	PodIP     string
	NodeName  string
	Namespace string
}

type ScrapeResult struct {
	Target  *ScrapeTarget
	Metrics []*KeplerMetric
	Error   error
}

type KeplerMetric struct {
	ContainerNamespace string
	PodName            string
	ContainerName      string
	Value              float64
}

type Scraper struct {
	log         *logging.Logger
	client      *http.Client
	workerCount int
	port        int
}

func NewScraper(log *logging.Logger, port int) *Scraper {
	return &Scraper{
		log:         log.WithField("component", "scraper"),
		client:      &http.Client{Timeout: ScrapeTimeout},
		workerCount: DefaultWorkerCount,
		port:        port,
	}
}

func (s *Scraper) ScrapeAll(targets []*ScrapeTarget) []*ScrapeResult {
	if len(targets) == 0 {
		return nil
	}

	jobs := make(chan *ScrapeTarget, len(targets))
	results := make(chan *ScrapeResult, len(targets))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go s.worker(jobs, results, &wg)
	}

	// Send all targets to the jobs channel
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var allResults []*ScrapeResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}

func (s *Scraper) worker(jobs <-chan *ScrapeTarget, results chan<- *ScrapeResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for target := range jobs {
		result := &ScrapeResult{Target: target}

		metrics, err := s.scrapeTarget(target)
		if err != nil {
			result.Error = err
			s.log.Errorf("Failed to scrape target %s (%s): %v", target.PodName, target.PodIP, err)
		} else {
			result.Metrics = metrics
			s.log.Debugf("Successfully scraped %d metrics from %s", len(metrics), target.PodName)
		}

		results <- result
	}
}

func (s *Scraper) scrapeTarget(target *ScrapeTarget) ([]*KeplerMetric, error) {
	url := fmt.Sprintf("http://%s:%d/metrics", target.PodIP, s.port)

	resp, err := s.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	return s.parsePrometheusMetrics(resp.Body)
}

func (s *Scraper) parsePrometheusMetrics(reader io.Reader) ([]*KeplerMetric, error) {
	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse prometheus metrics: %w", err)
	}

	var metrics []*KeplerMetric

	// Look for the kepler_container_joules_total metric family
	metricFamily, found := metricFamilies[KeplerMetricName]
	if !found {
		s.log.Debugf("Metric family %s not found in response", KeplerMetricName)
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
		ContainerNamespace: containerNamespace,
		PodName:            podName,
		ContainerName:      containerName,
		Value:              value,
	}, nil
}

func (s *Scraper) findLabelValue(labels []*dto.LabelPair, labelName string) (string, error) {
	for _, label := range labels {
		if label.GetName() == labelName {
			return label.GetValue(), nil
		}
	}
	return "", fmt.Errorf("missing %s label", labelName)
}
