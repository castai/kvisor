package ebpftracer

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func buildNetworkSummaryBufferMap(originalSpec *ebpf.MapSpec) (*ebpf.Map, error) {
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
	var config tracerConfigT

	zero := uint32(0)

	err := t.module.objects.ConfigMap.Lookup(zero, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("error while config lookup: %w", err)
	}

	numEntries := t.module.objects.NetworkTrafficBufferMap.MaxEntries()
	indexToCollect := config.SummaryMapIndex

	config.SummaryMapIndex = (config.SummaryMapIndex + 1) % int32(numEntries) // nolint:gosec

	err = t.module.objects.ConfigMap.Update(zero, &config, ebpf.UpdateExist)
	if err != nil {
		return nil, nil, fmt.Errorf("error while updating config: %w", err)
	}

	innerMapSpec := t.module.networkTrafficSummaryMapSpec.InnerMap.Copy()
	if innerMapSpec == nil {
		return nil, nil, errors.New("error: no inner map spec for `networkTrafficSummary`")
	}
	innerMapSpec.Name = fmt.Sprintf("nt_sum_%d", indexToCollect)

	newMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("error while creating new inner map: %w", err)
	}
	defer newMap.Close()

	var summaryMap *ebpf.Map
	err = t.module.objects.NetworkTrafficBufferMap.Lookup(indexToCollect, &summaryMap)
	if err != nil {
		return nil, nil, fmt.Errorf("error while getting existing map: %w", err)
	}
	defer summaryMap.Close()

	err = t.module.objects.NetworkTrafficBufferMap.Update(indexToCollect, newMap, ebpf.UpdateAny)
	if err != nil {
		return nil, nil, fmt.Errorf("error while replacing existing map: %w", err)
	}

	batchSize := startingChunkSize(int(summaryMap.MaxEntries()))
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		resKeys, resVals, err := collectEntriesBatch(summaryMap, batchSize)

		if err != nil {
			// Lookup batch on LRU hash map may fail if the buffer passed is not big enough to
			// accommodate the largest bucket size in the LRU map [1]
			// Because bucket size, in general, cannot be known, we take the number of entries until
			// we expect to see a hash map collision: sqrt(max_entries * 2)
			// To avoid unbounded growth, each ENOSPC will result in a doubling of the chuck chunkSize
			// which will persist into subsequent calls of Stats, up to a maximum of 3 (fold-increase).
			//
			// [1] https://elixir.bootlin.com/linux/latest/source/kernel/bpf/hashtab.c#L1776
			if errors.Is(err, unix.ENOSPC) {
				batchSize *= 2
				continue
			}
		}

		return resKeys, resVals, nil
	}

	t.log.Error("collecting network summary in batch was not successful, falling back to slower iterator approach.")

	// Fallback to slower iterator based collection in case the batch approach fails.
	return collectEntriesIterator(summaryMap)
}

func collectEntriesBatch(summaryMap *ebpf.Map, batchSize int) ([]TrafficKey, []TrafficSummary, error) {
	kout := make([]TrafficKey, batchSize)
	vout := make([]TrafficSummary, batchSize)

	resKeys := make([]TrafficKey, 0)
	resVals := make([]TrafficSummary, 0)

	var cursor ebpf.MapBatchCursor

	for {
		count, err := summaryMap.BatchLookup(&cursor, kout, vout, nil)

		resKeys = slices.Grow(resKeys, count)
		resVals = slices.Grow(resVals, count)
		for i := 0; i < count; i++ {
			resKeys = append(resKeys, kout[i])
			resVals = append(resVals, vout[i])
		}

		if err != nil {
			// When the iteration is done, BatchLookup will return a ErrKeyNotExist.
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return resKeys, resVals, nil
			}

			return nil, nil, err
		}
	}
}

func collectEntriesIterator(summaryMap *ebpf.Map) ([]TrafficKey, []TrafficSummary, error) {
	iter := summaryMap.Iterate()
	var ipKey TrafficKey
	var trafficSummary TrafficSummary

	resKeys := make([]TrafficKey, 0)
	resVals := make([]TrafficSummary, 0)

	for iter.Next(&ipKey, &trafficSummary) {
		resKeys = append(resKeys, ipKey)
		resVals = append(resVals, trafficSummary)
	}

	if err := iter.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterator finished with error: %w", err)
	}

	return resKeys, resVals, nil
}

func startingChunkSize(maxEntries int) int {
	bucketSize := math.Sqrt(float64(maxEntries * 2))
	nearest2 := math.Log2(bucketSize)
	return int(math.Pow(2, math.Ceil(nearest2)))
}
