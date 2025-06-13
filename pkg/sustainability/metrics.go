package sustainability

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	// Internal metrics for monitoring the service itself
	ScrapeDuration    prometheus.Histogram
	ScrapeErrors      prometheus.Counter
	SuccessfulScrapes prometheus.Gauge

	// Exported aggregated metrics for sustainability dashboard
	NamespaceEnergyJoules *prometheus.GaugeVec
	NamespaceCarbonGrams  *prometheus.GaugeVec
	NamespaceCostUSD      *prometheus.GaugeVec

	WorkloadEnergyJoules *prometheus.GaugeVec
	WorkloadCarbonGrams  *prometheus.GaugeVec
	WorkloadCostUSD      *prometheus.GaugeVec
}

func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		// Internal service metrics
		ScrapeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kvisor_sustainability_scrape_duration_seconds",
			Help:    "Duration of sustainability metrics scrape cycles",
			Buckets: prometheus.DefBuckets,
		}),
		ScrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kvisor_sustainability_scrape_errors_total",
			Help: "Total number of sustainability scrape errors",
		}),
		SuccessfulScrapes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kvisor_sustainability_successful_scrapes",
			Help: "Number of successful scrapes in the last cycle",
		}),

		// Namespace-level aggregated metrics
		NamespaceEnergyJoules: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_namespace_energy_joules_total",
				Help: "Total energy consumed by a namespace, in Joules",
			},
			[]string{"namespace"},
		),
		NamespaceCarbonGrams: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_namespace_carbon_emissions_grams_co2e_total",
				Help: "Estimated carbon emissions from a namespace, in grams of CO2e",
			},
			[]string{"namespace"},
		),
		NamespaceCostUSD: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_namespace_energy_cost_usd_total",
				Help: "Estimated energy cost of a namespace, in USD",
			},
			[]string{"namespace"},
		),

		// Workload-level aggregated metrics
		WorkloadEnergyJoules: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_workload_energy_joules_total",
				Help: "Total energy consumed by a workload, in Joules",
			},
			[]string{"namespace", "workload_name", "workload_type"},
		),
		WorkloadCarbonGrams: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_workload_carbon_emissions_grams_co2e_total",
				Help: "Estimated carbon emissions from a workload, in grams of CO2e",
			},
			[]string{"namespace", "workload_name", "workload_type"},
		),
		WorkloadCostUSD: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kvisor_workload_energy_cost_usd_total",
				Help: "Estimated energy cost of a workload, in USD",
			},
			[]string{"namespace", "workload_name", "workload_type"},
		),
	}

	// Register all metrics
	if registry != nil {
		registry.MustRegister(
			m.ScrapeDuration,
			m.ScrapeErrors,
			m.SuccessfulScrapes,
			m.NamespaceEnergyJoules,
			m.NamespaceCarbonGrams,
			m.NamespaceCostUSD,
			m.WorkloadEnergyJoules,
			m.WorkloadCarbonGrams,
			m.WorkloadCostUSD,
		)
	}

	return m
}

// Reset clears all metric values (useful for testing or resets)
func (m *Metrics) Reset() {
	m.NamespaceEnergyJoules.Reset()
	m.NamespaceCarbonGrams.Reset()
	m.NamespaceCostUSD.Reset()
	m.WorkloadEnergyJoules.Reset()
	m.WorkloadCarbonGrams.Reset()
	m.WorkloadCostUSD.Reset()
}
