package sustainability

import (
	"k8s.io/apimachinery/pkg/labels"
)

// SeriesIdentifier uniquely identifies a Kepler metric time series
type SeriesIdentifier struct {
	ContainerNamespace string
	PodName            string
	ContainerName      string
}

// String returns a string representation for use as a map key
func (s SeriesIdentifier) String() string {
	return s.ContainerNamespace + ":" + s.PodName + ":" + s.ContainerName
}

// AggregationResult holds the results of energy aggregation
type AggregationResult struct {
	NamespaceAggregates map[NamespaceKey]float64
	WorkloadAggregates  map[WorkloadKey]float64
}

// SustainabilityConfig holds configuration for carbon and cost calculations
type SustainabilityConfig struct {
	// Carbon intensity in grams of CO2 equivalent per kWh
	CarbonIntensityGCO2PerKWh float64 `yaml:"carbonIntensity" json:"carbonIntensity"`

	// Energy price in USD per kWh
	EnergyPriceUSDPerKWh float64 `yaml:"energyPrice" json:"energyPrice"`

	// Scrape interval for collecting metrics
	ScrapeIntervalSeconds int `yaml:"scrapeInterval" json:"scrapeInterval"`

	// Number of worker goroutines for scraping
	WorkerCount int `yaml:"workerCount" json:"workerCount"`
}

// DefaultSustainabilityConfig returns a config with sensible defaults
func DefaultSustainabilityConfig() *SustainabilityConfig {
	return &SustainabilityConfig{
		CarbonIntensityGCO2PerKWh: DefaultCarbonFactor,
		EnergyPriceUSDPerKWh:      DefaultCostFactor,
		ScrapeIntervalSeconds:     30,
		WorkerCount:               10,
	}
}

// AgentPodSelector returns a label selector for kvisor-agent pods
func AgentPodSelector() labels.Selector {
	req, _ := labels.NewRequirement("app.kubernetes.io/name", "=", []string{"kvisor"})
	compReq, _ := labels.NewRequirement("app.kubernetes.io/component", "=", []string{"agent"})

	selector := labels.NewSelector()
	selector = selector.Add(*req, *compReq)

	return selector
}

// ConvertJoulesToKWh converts joules to kilowatt-hours
func ConvertJoulesToKWh(joules float64) float64 {
	return joules / 3600000 // 1 kWh = 3,600,000 J
}

// CalculateCarbonEmissions calculates CO2 emissions in grams
func CalculateCarbonEmissions(joules, carbonIntensityGCO2PerKWh float64) float64 {
	kwh := ConvertJoulesToKWh(joules)
	return kwh * carbonIntensityGCO2PerKWh
}

// CalculateEnergyCost calculates energy cost in USD
func CalculateEnergyCost(joules, energyPriceUSDPerKWh float64) float64 {
	kwh := ConvertJoulesToKWh(joules)
	return kwh * energyPriceUSDPerKWh
}
