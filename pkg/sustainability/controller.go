package sustainability

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/listers/core/v1"
)

const (
	DefaultScrapeInterval = 30 * time.Second
	DefaultKeplerPort     = 8888
	DefaultCarbonFactor   = 415.7 // gCO2e/kWh (US average)
	DefaultCostFactor     = 0.12  // USD/kWh
)

type Controller struct {
	log           *logging.Logger
	client        kubernetes.Interface
	podLister     v1.PodLister
	scraper       *Scraper
	aggregator    *Aggregator
	metrics       *Metrics
	configManager *ConfigManager

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewController(
	log *logging.Logger,
	client kubernetes.Interface,
	factory informers.SharedInformerFactory,
	registry prometheus.Registerer,
	configPath string,
) (*Controller, error) {
	metrics := NewMetrics(registry)

	configManager, err := NewConfigManager(log, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create config manager: %w", err)
	}

	controller := &Controller{
		log:           log.WithField("component", "sustainability"),
		client:        client,
		podLister:     factory.Core().V1().Pods().Lister(),
		scraper:       NewScraper(log, DefaultKeplerPort),
		aggregator:    NewAggregator(log),
		metrics:       metrics,
		configManager: configManager,
		stopCh:        make(chan struct{}),
	}

	return controller, nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.log.Info("Starting sustainability controller")

	c.wg.Add(1)
	go c.run(ctx)

	return nil
}

func (c *Controller) Stop() {
	c.log.Info("Stopping sustainability controller")
	close(c.stopCh)
	c.wg.Wait()
	if c.configManager != nil {
		c.configManager.Stop()
	}
}

func (c *Controller) run(ctx context.Context) {
	defer c.wg.Done()

	// Get initial scrape interval from config
	config := c.configManager.GetConfig()
	scrapeInterval := time.Duration(config.ScrapeIntervalSeconds) * time.Second
	ticker := time.NewTicker(scrapeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			// Check if scrape interval changed
			newConfig := c.configManager.GetConfig()
			newInterval := time.Duration(newConfig.ScrapeIntervalSeconds) * time.Second
			if newInterval != scrapeInterval {
				ticker.Stop()
				ticker = time.NewTicker(newInterval)
				scrapeInterval = newInterval
				c.log.Infof("Updated scrape interval to %v", newInterval)
			}

			c.scrapeAndProcess()
		}
	}
}

func (c *Controller) scrapeAndProcess() {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		c.metrics.ScrapeDuration.Observe(duration.Seconds())
		c.log.Debugf("Sustainability scrape cycle completed in %v", duration)
	}()

	// Discover kvisor-agent pods with Kepler sidecars
	targets, err := c.discoverTargets()
	if err != nil {
		c.log.Errorf("Failed to discover scrape targets: %v", err)
		c.metrics.ScrapeErrors.Inc()
		return
	}

	if len(targets) == 0 {
		c.log.Warn("No kvisor-agent pods found for scraping")
		return
	}

	c.log.Debugf("Discovered %d targets for scraping", len(targets))

	// Scrape all targets concurrently
	results := c.scraper.ScrapeAll(targets)

	// Process results and update aggregations
	c.processResults(results)

	// Update Prometheus metrics
	c.updateMetrics()
}

func (c *Controller) discoverTargets() ([]*ScrapeTarget, error) {
	// List all pods with kvisor-agent labels
	pods, err := c.podLister.List(labels.NewSelector())
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	var targets []*ScrapeTarget
	for _, pod := range pods {
		// Check if this is a kvisor-agent pod with Kepler sidecar
		if c.isKvisorAgentPod(pod) && c.hasKeplerContainer(pod) && pod.Status.PodIP != "" {
			targets = append(targets, &ScrapeTarget{
				PodName:   pod.Name,
				PodIP:     pod.Status.PodIP,
				NodeName:  pod.Spec.NodeName,
				Namespace: pod.Namespace,
			})
		}
	}

	return targets, nil
}

func (c *Controller) isKvisorAgentPod(pod *corev1.Pod) bool {
	// Check for kvisor-agent labels
	if app, ok := pod.Labels["app.kubernetes.io/name"]; ok && app == "kvisor" {
		if component, ok := pod.Labels["app.kubernetes.io/component"]; ok && component == "agent" {
			return true
		}
	}
	return false
}

func (c *Controller) hasKeplerContainer(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == "kepler" {
			return true
		}
	}
	return false
}

func (c *Controller) processResults(results []*ScrapeResult) {
	successCount := 0

	for _, result := range results {
		if result.Error != nil {
			c.log.Errorf("Failed to scrape %s: %v", result.Target.PodName, result.Error)
			c.metrics.ScrapeErrors.Inc()
			continue
		}

		// Process the metrics from this target
		c.aggregator.ProcessMetrics(result.Target, result.Metrics)
		successCount++
	}

	c.metrics.SuccessfulScrapes.Set(float64(successCount))
	c.log.Debugf("Successfully processed %d out of %d targets", successCount, len(results))
}

func (c *Controller) updateMetrics() {
	config := c.configManager.GetConfig()

	// Get aggregated data from the aggregator
	namespaceData := c.aggregator.GetNamespaceAggregations()
	workloadData := c.aggregator.GetWorkloadAggregations()

	// Update namespace metrics
	for key, joules := range namespaceData {
		carbonGrams := CalculateCarbonEmissions(joules, config.CarbonIntensityGCO2PerKWh)
		costUSD := CalculateEnergyCost(joules, config.EnergyPriceUSDPerKWh)

		c.metrics.NamespaceEnergyJoules.WithLabelValues(key.Namespace).Set(joules)
		c.metrics.NamespaceCarbonGrams.WithLabelValues(key.Namespace).Set(carbonGrams)
		c.metrics.NamespaceCostUSD.WithLabelValues(key.Namespace).Set(costUSD)
	}

	// Update workload metrics
	for key, joules := range workloadData {
		carbonGrams := CalculateCarbonEmissions(joules, config.CarbonIntensityGCO2PerKWh)
		costUSD := CalculateEnergyCost(joules, config.EnergyPriceUSDPerKWh)

		c.metrics.WorkloadEnergyJoules.WithLabelValues(
			key.Namespace, key.WorkloadName, key.WorkloadType,
		).Set(joules)
		c.metrics.WorkloadCarbonGrams.WithLabelValues(
			key.Namespace, key.WorkloadName, key.WorkloadType,
		).Set(carbonGrams)
		c.metrics.WorkloadCostUSD.WithLabelValues(
			key.Namespace, key.WorkloadName, key.WorkloadType,
		).Set(costUSD)
	}
}

func (c *Controller) UpdateConfig(carbonIntensity, energyPrice float64) error {
	return c.configManager.UpdateConfig(carbonIntensity, energyPrice)
}

func (c *Controller) GetConfig() *SustainabilityConfig {
	return c.configManager.GetConfig()
}

func (c *Controller) GetAggregator() *Aggregator {
	return c.aggregator
}
