package ebpftracer

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type FileAccessStats tracerFileAccessStats
type FileAccessKey tracerFileAccessKey

func (t *Tracer) CollectFileAccessStats() ([]FileAccessKey, []FileAccessStats, error) {
	var config tracerFileAccessConfigT

	zero := uint32(0)

	err := t.module.objects.FileAccessConfigMap.Lookup(zero, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("error while config lookup: %w", err)
	}

	numEntries := t.module.objects.FileAccessStatsMap.MaxEntries()
	indexToCollect := config.MapIndex

	config.MapIndex = (config.MapIndex + 1) % int32(numEntries) // nolint:gosec

	err = t.module.objects.FileAccessConfigMap.Update(zero, &config, ebpf.UpdateExist)
	if err != nil {
		return nil, nil, fmt.Errorf("error while updating config: %w", err)
	}

	return collectMapBatch[FileAccessKey, FileAccessStats](t.module.fileAccessMapSpec, t.module.objects.FileAccessStatsMap, indexToCollect)
}
