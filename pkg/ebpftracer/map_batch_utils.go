package ebpftracer

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func collectMapBatch[K, V any](targetMapSpec *ebpf.MapSpec, targetMap *ebpf.Map, index int32) ([]K, []V, error) {
	innerMapSpec := targetMapSpec.InnerMap.Copy()
	if innerMapSpec == nil {
		return nil, nil, fmt.Errorf("error: no inner map spec for `%s`", targetMapSpec.Name)
	}
	innerMapSpec.Name = fmt.Sprintf("nt_sum_%d", index)

	newMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("error while creating new inner map: %w", err)
	}
	defer newMap.Close()

	var summaryMap *ebpf.Map
	err = targetMap.Lookup(index, &summaryMap)
	if err != nil {
		return nil, nil, fmt.Errorf("error while getting existing map: %w", err)
	}
	defer summaryMap.Close()

	err = targetMap.Update(index, newMap, ebpf.UpdateAny)
	if err != nil {
		return nil, nil, fmt.Errorf("error while replacing existing map: %w", err)
	}

	batchSize := startingChunkSize(int(summaryMap.MaxEntries()))
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		resKeys, resVals, err := collectEntriesBatch[K, V](summaryMap, batchSize)

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

	// Fallback to slower iterator based collection in case the batch approach fails.
	return collectEntriesIterator[K, V](summaryMap)
}

func collectEntriesBatch[K, V any](summaryMap *ebpf.Map, batchSize int) ([]K, []V, error) {
	kout := make([]K, batchSize)
	vout := make([]V, batchSize)

	resKeys := make([]K, 0)
	resVals := make([]V, 0)

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

func collectEntriesIterator[K, V any](summaryMap *ebpf.Map) ([]K, []V, error) {
	iter := summaryMap.Iterate()
	var key K
	var val V

	resKeys := make([]K, 0)
	resVals := make([]V, 0)

	for iter.Next(&key, &val) {
		resKeys = append(resKeys, key)
		resVals = append(resVals, val)
	}

	if err := iter.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterator finished with error: %w", err)
	}

	return resKeys, resVals, nil
}
