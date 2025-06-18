package ebpftracer

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

func buildSummaryBufferMap(originalSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec := originalSpec.Copy()
	spec.Contents = make([]ebpf.MapKV, spec.MaxEntries)

	for i := uint32(0); i < spec.MaxEntries; i++ {
		innerSpec := spec.InnerMap.Copy()
		innerSpec.Name = fmt.Sprintf("nt_sum_%d", i)

		innerMap, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return nil, err
		}
		defer innerMap.Close()

		spec.Contents[i] = ebpf.MapKV{Key: i, Value: innerMap}
	}

	outerMap, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}

	return outerMap, nil
}

type TrafficSummary tracerTrafficSummary
type TrafficKey tracerIpKey

func (t *Tracer) CollectNetworkSummary() ([]TrafficKey, []TrafficSummary, error) {
	var config tracerNetflowConfigT

	zero := uint32(0)

	err := t.module.objects.NetflowConfigMap.Lookup(zero, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("error while config lookup: %w", err)
	}

	numEntries := t.module.objects.NetworkTrafficBufferMap.MaxEntries()
	indexToCollect := config.MapIndex

	config.MapIndex = (config.MapIndex + 1) % int32(numEntries) // nolint:gosec

	err = t.module.objects.NetflowConfigMap.Update(zero, &config, ebpf.UpdateExist)
	if err != nil {
		return nil, nil, fmt.Errorf("error while updating config: %w", err)
	}

	return collectMapBatch[TrafficKey, TrafficSummary](t.module.networkTrafficSummaryMapSpec, t.module.objects.NetworkTrafficBufferMap, indexToCollect)
}

func startingChunkSize(maxEntries int) int {
	bucketSize := math.Sqrt(float64(maxEntries * 2))
	nearest2 := math.Log2(bucketSize)
	return int(math.Pow(2, math.Ceil(nearest2)))
}
