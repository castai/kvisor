# Kvisor Sustainability Service

This service collects Kepler energy metrics and transforms them into actionable sustainability insights for Kubernetes workloads.

## Overview

The sustainability service acts as a critical middle layer, collecting detailed power consumption metrics from Kepler (via Prometheus endpoints) and transforming them into high-level, actionable insights for sustainability dashboards.

## Features

### 1. Data Collection
- Periodically queries Kepler metrics endpoints via HTTP
- Collects `kepler_container_joules_total` with all labels:
  - `container_namespace`
  - `pod_name` 
  - `container_name`

### 2. External Configuration
- `carbon_intensity_gco2_per_kwh`: Carbon intensity (grams CO2e per kWh)
- `energy_price_usd_per_kwh`: Energy price (USD per kWh)
- Dynamic configuration reloading via file watcher

### 3. Processing and Aggregation
- **Namespace Aggregation**: Sums energy consumption by namespace
- **Workload Aggregation**: Groups by Kubernetes workload (Deployment, StatefulSet, etc.)
- Handles counter resets and maintains delta calculations
- Leverages existing kvisor ownership resolution logic

### 4. Metric Calculations
- **Carbon Emissions**: `total_joules / 3,600,000 * carbon_intensity_gco2_per_kwh`
- **Energy Cost**: `total_joules / 3,600,000 * energy_price_usd_per_kwh`

### 5. Prometheus Metrics
Exposes aggregated metrics via `/metrics` endpoint:

```prometheus
# Namespace-level metrics
kvisor_namespace_energy_joules_total{namespace="production"} 4829103.4
kvisor_namespace_carbon_emissions_grams_co2e_total{namespace="production"} 558.12
kvisor_namespace_energy_cost_usd_total{namespace="production"} 0.161

# Workload-level metrics  
kvisor_workload_energy_joules_total{namespace="production", workload_name="api-server", workload_type="Deployment"} 4829103.4
kvisor_workload_carbon_emissions_grams_co2e_total{namespace="production", workload_name="api-server", workload_type="Deployment"} 558.12
kvisor_workload_energy_cost_usd_total{namespace="production", workload_name="api-server", workload_type="Deployment"} 0.161
```

## Architecture

### Components

1. **Controller**: Main orchestrator that manages the scraping cycle
2. **Scraper**: Handles concurrent HTTP requests to Kepler endpoints with robust Prometheus text format parsing using `prometheus/common`
3. **Aggregator**: Processes metrics and maintains state for delta calculations
4. **ConfigManager**: Manages dynamic configuration with file watching
5. **Metrics**: Prometheus metric definitions and exposition

### Integration with Kvisor

The service integrates seamlessly with the existing kvisor controller:

- Uses existing Kubernetes client and informer factory
- Leverages kvisor's ownership resolution logic
- Shares the same Prometheus metrics endpoint
- Follows kvisor's logging and error handling patterns

## Configuration

Default configuration file: `/etc/sustainability/config.yaml`

```yaml
# Carbon intensity in grams CO2e per kWh
carbonIntensity: 415.7  # US average

# Energy price in USD per kWh  
energyPrice: 0.12

# Scrape interval in seconds
scrapeInterval: 30

# Number of concurrent scraping workers
workerCount: 10
```

## Deployment

The service is automatically deployed as part of the kvisor controller when Kepler sidecars are present in agent pods.

### Prerequisites

1. Kvisor agent DaemonSet with Kepler sidecars
2. Network policy allowing controller → agent communication on port 8888
3. RBAC permissions for pod discovery (already present in kvisor)

### Agent Configuration

The kvisor agent Helm chart includes Kepler sidecars:

```yaml
# In agent.yaml template
containers:
- name: kepler
  image: "quay.io/sustainable_computing_io/kepler:latest"
  ports:
  - containerPort: 8888
    name: kepler-metrics
```

## Usage

### Standalone Example

```go
package main

import (
    "context"
    "github.com/castai/kvisor/pkg/sustainability"
    "github.com/prometheus/client_golang/prometheus"
    "k8s.io/client-go/informers"
    "k8s.io/client-go/kubernetes"
)

func main() {
    // Create Kubernetes client and informer factory
    clientset, _ := kubernetes.NewForConfig(config)
    informerFactory := informers.NewSharedInformerFactory(clientset, 0)
    
    // Create sustainability controller
    controller, err := sustainability.NewController(
        logger,
        clientset, 
        informerFactory,
        prometheus.DefaultRegisterer,
        "", // Use default config path
    )
    
    // Start the service
    ctx := context.Background()
    controller.Start(ctx)
}
```

### Configuration Updates

```go
// Update carbon intensity and energy price
controller.UpdateConfig(450.0, 0.15)
```

### Accessing Aggregated Data

```go
// Get current aggregations
nsData := controller.GetAggregator().GetNamespaceAggregations()
workloadData := controller.GetAggregator().GetWorkloadAggregations()

// Calculate emissions and costs
config := controller.GetConfig()
for key, joules := range nsData {
    carbonGrams := sustainability.CalculateCarbonEmissions(joules, config.CarbonIntensityGCO2PerKWh)
    costUSD := sustainability.CalculateEnergyCost(joules, config.EnergyPriceUSDPerKWh)
}
```

## Monitoring

### Internal Metrics

The service exposes metrics about its own operation:

- `kvisor_sustainability_scrape_duration_seconds`: Scrape cycle duration
- `kvisor_sustainability_scrape_errors_total`: Number of scrape errors
- `kvisor_sustainability_successful_scrapes`: Successful scrapes in last cycle

### Alerts

Recommended Prometheus alerts:

```yaml
- alert: SustainabilityScrapeFailing
  expr: increase(kvisor_sustainability_scrape_errors_total[5m]) > 0
  annotations:
    summary: "Sustainability service scrape failures"

- alert: SustainabilityScrapeSlow  
  expr: kvisor_sustainability_scrape_duration_seconds > 30
  annotations:
    summary: "Sustainability scrape cycle taking too long"
```

## Troubleshooting

### Common Issues

1. **No metrics collected**: Check Kepler sidecar deployment and network connectivity
2. **Permission denied**: Verify RBAC allows pod listing and discovery
3. **Config not reloading**: Check config file permissions and path
4. **High memory usage**: Tune garbage collection and worker count

### Debug Logging

Enable debug logging to see detailed scrape information:

```yaml
extraArgs:
  log-level: debug
```

### Network Troubleshooting

Test connectivity from controller to agent:

```bash
# From controller pod
curl http://<agent-pod-ip>:8888/metrics | grep kepler_container_joules_total
```

## Performance Considerations

- **Scrape Interval**: 30s default balances accuracy vs. load
- **Worker Count**: Default 10 workers handle ~100 nodes efficiently  
- **Memory Usage**: ~50MB for 1000 containers with full aggregation
- **Network Load**: ~100KB per node per scrape cycle
- **Parsing Efficiency**: Uses `prometheus/common/expfmt` for robust and efficient metric parsing

## Security

- Uses read-only access to Kubernetes API
- Config file should be mounted read-only
- No sensitive data in metrics or logs
- Network policies recommended for endpoint access