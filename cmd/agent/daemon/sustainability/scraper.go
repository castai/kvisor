package sustainability

import (
	"fmt"
	"io"
	"net/http"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	prom "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

type Scraper struct {
	keplerEndpoint string
	httpClient     *http.Client
}

func NewScraper(keplerEndpoint string) *Scraper {
	return &Scraper{
		keplerEndpoint: keplerEndpoint,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *Scraper) ScrapeMetrics() ([]*castaipb.SustainabilityStats, error) {
	resp, err := s.httpClient.Get(s.keplerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch kepler metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kepler endpoint returned status %d", resp.StatusCode)
	}

	return s.parsePrometheusMetrics(resp.Body)
}

func (s *Scraper) parsePrometheusMetrics(r io.Reader) ([]*castaipb.SustainabilityStats, error) {
	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	var stats []*castaipb.SustainabilityStats
	timestamp := time.Now().UnixNano()

	energyFamily, exists := metricFamilies[KeplerContainerEnergyJoulesMetric]
	if !exists {
		return stats, nil
	}

	for _, metric := range energyFamily.GetMetric() {
		stat, err := s.convertMetricToSustainabilityStats(metric, timestamp)
		if err != nil {
			continue
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

func (s *Scraper) convertMetricToSustainabilityStats(metric *prom.Metric, timestamp int64) (*castaipb.SustainabilityStats, error) {
	labels := make(map[string]string)
	for _, label := range metric.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}

	namespace := labels["container_namespace"]
	podName := labels["pod_name"]
	containerName := labels["container_name"]
	nodeName := labels["instance"]

	if namespace == "" || podName == "" || containerName == "" {
		return nil, fmt.Errorf("missing required labels")
	}

	var value float64
	if metric.GetCounter() != nil {
		value = metric.GetCounter().GetValue()
	} else if metric.GetGauge() != nil {
		value = metric.GetGauge().GetValue()
	} else {
		return nil, fmt.Errorf("unsupported metric type")
	}

	carbonGramsCo2E := CalculateCarbonEmissions(value, DefaultCarbonIntensityGCO2PerKWh)
	costUsd := CalculateEnergyCost(value, DefaultEnergyPriceUSDPerKWh)

	return &castaipb.SustainabilityStats{
		Namespace:                 namespace,
		PodName:                   podName,
		ContainerName:             containerName,
		NodeName:                  nodeName,
		EnergyJoules:              value,
		CarbonGramsCo2E:           carbonGramsCo2E,
		CostUsd:                   costUsd,
		CarbonIntensityGco2PerKwh: DefaultCarbonIntensityGCO2PerKWh,
		EnergyPriceUsdPerKwh:      DefaultEnergyPriceUSDPerKWh,
		Timestamp:                 timestamp,
	}, nil
}
