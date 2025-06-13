package sustainability

import (
	"fmt"
	"sync"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
)

type SeriesKey string

type NamespaceKey struct {
	Namespace string
}

type WorkloadKey struct {
	Namespace    string
	WorkloadName string
	WorkloadType string
}

type StateStore struct {
	mu             sync.RWMutex
	previousValues map[SeriesKey]float64
}

type Aggregator struct {
	log        *logging.Logger
	stateStore *StateStore
	kubeClient *kube.Client

	mu                  sync.RWMutex
	namespaceAggregates map[NamespaceKey]float64
	workloadAggregates  map[WorkloadKey]float64
}

func NewAggregator(log *logging.Logger) *Aggregator {
	return &Aggregator{
		log: log.WithField("component", "aggregator"),
		stateStore: &StateStore{
			previousValues: make(map[SeriesKey]float64),
		},
		namespaceAggregates: make(map[NamespaceKey]float64),
		workloadAggregates:  make(map[WorkloadKey]float64),
	}
}

func (a *Aggregator) SetKubeClient(client *kube.Client) {
	a.kubeClient = client
}

func (a *Aggregator) ProcessMetrics(target *ScrapeTarget, metrics []*KeplerMetric) {
	if len(metrics) == 0 {
		return
	}

	a.log.Debugf("Processing %d metrics from target %s", len(metrics), target.PodName)

	// Track which series we've seen in this scrape for garbage collection
	currentSeries := make(map[SeriesKey]struct{})

	// Process each metric
	for _, metric := range metrics {
		seriesKey := a.buildSeriesKey(metric)
		currentSeries[seriesKey] = struct{}{}

		delta := a.calculateDelta(seriesKey, metric.Value)
		if delta <= 0 {
			continue // Skip invalid deltas
		}

		// Aggregate by namespace
		nsKey := NamespaceKey{Namespace: metric.ContainerNamespace}
		a.addToNamespaceAggregate(nsKey, delta)

		// Aggregate by workload (requires K8s API lookup)
		if a.kubeClient != nil {
			workloadKey := a.resolveWorkloadKey(metric)
			if workloadKey != nil {
				a.addToWorkloadAggregate(*workloadKey, delta)
			}
		}
	}

	// Garbage collect stale series
	a.garbageCollectStates(currentSeries)
}

func (a *Aggregator) buildSeriesKey(metric *KeplerMetric) SeriesKey {
	return SeriesKey(fmt.Sprintf("%s:%s:%s",
		metric.ContainerNamespace,
		metric.PodName,
		metric.ContainerName,
	))
}

func (a *Aggregator) calculateDelta(seriesKey SeriesKey, currentValue float64) float64 {
	a.stateStore.mu.Lock()
	defer a.stateStore.mu.Unlock()

	previousValue, exists := a.stateStore.previousValues[seriesKey]
	a.stateStore.previousValues[seriesKey] = currentValue

	if !exists {
		// First time seeing this series, can't calculate delta
		a.log.Debugf("New series detected: %s, value: %.2f", seriesKey, currentValue)
		return 0
	}

	// Check for counter reset
	if currentValue < previousValue {
		a.log.Debugf("Counter reset detected for series %s: current=%.2f, previous=%.2f",
			seriesKey, currentValue, previousValue)
		return currentValue // Delta is just the current value
	}

	delta := currentValue - previousValue
	a.log.Debugf("Calculated delta for series %s: %.2f (current=%.2f, previous=%.2f)",
		seriesKey, delta, currentValue, previousValue)

	return delta
}

func (a *Aggregator) garbageCollectStates(currentSeries map[SeriesKey]struct{}) {
	a.stateStore.mu.Lock()
	defer a.stateStore.mu.Unlock()

	var toDelete []SeriesKey
	for seriesKey := range a.stateStore.previousValues {
		if _, exists := currentSeries[seriesKey]; !exists {
			toDelete = append(toDelete, seriesKey)
		}
	}

	for _, key := range toDelete {
		delete(a.stateStore.previousValues, key)
		a.log.Debugf("Garbage collected stale series: %s", key)
	}

	if len(toDelete) > 0 {
		a.log.Debugf("Garbage collected %d stale series", len(toDelete))
	}
}

func (a *Aggregator) addToNamespaceAggregate(key NamespaceKey, delta float64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.namespaceAggregates[key] += delta
	a.log.Debugf("Added %.2f joules to namespace %s (total: %.2f)",
		delta, key.Namespace, a.namespaceAggregates[key])
}

func (a *Aggregator) addToWorkloadAggregate(key WorkloadKey, delta float64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.workloadAggregates[key] += delta
	a.log.Debugf("Added %.2f joules to workload %s/%s:%s (total: %.2f)",
		delta, key.Namespace, key.WorkloadName, key.WorkloadType, a.workloadAggregates[key])
}

func (a *Aggregator) resolveWorkloadKey(metric *KeplerMetric) *WorkloadKey {
	if a.kubeClient == nil {
		// Fallback to pod-level aggregation
		return &WorkloadKey{
			Namespace:    metric.ContainerNamespace,
			WorkloadName: metric.PodName,
			WorkloadType: "Pod",
		}
	}

	// This is a simplified implementation
	// In practice, you'd need to find the pod by namespace/name combination
	// and use the existing ownership resolution logic
	// For now, we'll use a fallback approach

	return &WorkloadKey{
		Namespace:    metric.ContainerNamespace,
		WorkloadName: metric.PodName,
		WorkloadType: "Pod",
	}
}

func (a *Aggregator) GetNamespaceAggregations() map[NamespaceKey]float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[NamespaceKey]float64, len(a.namespaceAggregates))
	for k, v := range a.namespaceAggregates {
		result[k] = v
	}

	return result
}

func (a *Aggregator) GetWorkloadAggregations() map[WorkloadKey]float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[WorkloadKey]float64, len(a.workloadAggregates))
	for k, v := range a.workloadAggregates {
		result[k] = v
	}

	return result
}

func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear aggregates but keep state store for delta calculations
	a.namespaceAggregates = make(map[NamespaceKey]float64)
	a.workloadAggregates = make(map[WorkloadKey]float64)

	a.log.Debug("Reset aggregator state")
}

func (a *Aggregator) GetStats() (int, int, int) {
	a.mu.RLock()
	a.stateStore.mu.RLock()
	defer func() {
		a.stateStore.mu.RUnlock()
		a.mu.RUnlock()
	}()

	return len(a.stateStore.previousValues), len(a.namespaceAggregates), len(a.workloadAggregates)
}
