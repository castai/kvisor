package state

import (
	"context"
	"time"

	"github.com/castai/kvisor/pkg/sustainability"
)

func (c *Controller) RunSustainabilityPipeline(ctx context.Context, metricsChan <-chan *SustainabilityMetricData) error {
	c.log.Info("running sustainability pipeline")
	defer c.log.Info("sustainability pipeline done")

	ticker := time.NewTicker(30 * time.Second) // Export every 30 seconds
	defer ticker.Stop()

	var collectedMetrics []*SustainabilityMetricData

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case metric := <-metricsChan:
			// Collect metrics as they arrive
			collectedMetrics = append(collectedMetrics, metric)
		case <-ticker.C:
			// Periodically export collected metrics
			if len(collectedMetrics) > 0 {
				func() {
					start := time.Now()
					batch := c.createSustainabilityBatch(collectedMetrics)
					if len(batch.Items) > 0 {
						for _, exp := range c.exporters.Sustainability {
							exp.Enqueue(batch)
						}
						c.log.Infof("sustainability metrics exported: %d items, duration=%v", len(batch.Items), time.Since(start))
					}
					// Clear collected metrics after export
					collectedMetrics = collectedMetrics[:0]
				}()
			}
		}
	}
}

func (c *Controller) createSustainabilityBatch(rawMetrics []*SustainabilityMetricData) *SustainabilityBatch {
	batch := &SustainabilityBatch{}

	// Use default sustainability config for calculations
	sustainabilityConfig := sustainability.DefaultSustainabilityConfig()

	for _, raw := range rawMetrics {
		// Calculate carbon emissions and cost
		carbonGrams := sustainability.CalculateCarbonEmissions(raw.EnergyJoules, sustainabilityConfig.CarbonIntensityGCO2PerKWh)
		costUSD := sustainability.CalculateEnergyCost(raw.EnergyJoules, sustainabilityConfig.EnergyPriceUSDPerKWh)

		metric := &SustainabilityMetric{
			Timestamp:         raw.Timestamp,
			NodeName:          raw.NodeName,
			Namespace:         raw.Namespace,
			PodName:           raw.PodName,
			ContainerName:     raw.ContainerName,
			EnergyJoules:      raw.EnergyJoules,
			CarbonGramsCO2e:   carbonGrams,
			CostUSD:           costUSD,
			CarbonIntensity:   sustainabilityConfig.CarbonIntensityGCO2PerKWh,
			EnergyPricePerKWh: sustainabilityConfig.EnergyPriceUSDPerKWh,
		}

		batch.Items = append(batch.Items, metric)
	}

	return batch
}
