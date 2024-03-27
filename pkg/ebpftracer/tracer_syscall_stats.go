package ebpftracer

import (
	"errors"
	"fmt"

	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/systable"
	"github.com/cilium/ebpf"
)

type SyscallStatsKeyCgroupID uint64

type SyscallStats struct {
	ID    SyscallID
	Count uint64
}

type SyscallID uint32

func (s SyscallID) String() string {
	return systable.List[s]
}

type rawSyscallStatsKey struct {
	CgroupID uint64
	ID       uint64
}

func (t *Tracer) ReadSyscallStats() (map[SyscallStatsKeyCgroupID][]SyscallStats, error) {
	out := make(map[SyscallStatsKeyCgroupID][]SyscallStats)
	statsMap := t.module.objects.SyscallStatsMap
	iterator := statsMap.Iterate()

	var (
		key   rawSyscallStatsKey
		value uint64
	)
	for iterator.Next(&key, &value) {
		if key.ID > 340 {
			//t.log.Warnf("syscall id=%d not mapped", key.ID)
			// TODO: Add metrics and fix this hardcoded value.
			continue
		}
		out[SyscallStatsKeyCgroupID(key.CgroupID)] = append(out[SyscallStatsKeyCgroupID(key.CgroupID)], SyscallStats{
			ID:    SyscallID(key.ID),
			Count: value,
		})
	}

	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("syscall stats iterator: %w", err)
	}

	t.cleanupSyscallStats(out)

	return out, nil
}

func (t *Tracer) cleanupSyscallStats(stats map[SyscallStatsKeyCgroupID][]SyscallStats) {
	var obsoleteStatsKeys []rawSyscallStatsKey

	t.removedCgroupsMu.Lock()
	for removedCgroupID := range t.removedCgroups {
		if st, found := stats[SyscallStatsKeyCgroupID(removedCgroupID)]; found {
			for _, syscallStats := range st {
				obsoleteStatsKeys = append(obsoleteStatsKeys, rawSyscallStatsKey{
					CgroupID: removedCgroupID,
					ID:       uint64(syscallStats.ID),
				})
			}

		}
	}
	t.removedCgroupsMu.Unlock()

	if len(obsoleteStatsKeys) > 0 {
		if err := t.cleanupSyscallStatsKernel(obsoleteStatsKeys); err != nil {
			t.log.Errorf("cleanup obsolete syscall stats: %v", err)
		} else {
			t.removedCgroupsMu.Lock()
			t.removedCgroups = map[uint64]struct{}{}
			t.removedCgroupsMu.Unlock()
		}
	}
}

func (t *Tracer) cleanupSyscallStatsKernel(obsoleteStatsKeys []rawSyscallStatsKey) error {
	kernelVersion, err := kernel.CurrentKernelVersion()
	if err != nil {
		return err
	}

	// The ebpf batch helpers are available since kernel version 5.6.
	if kernelVersion.Major > 5 || (kernelVersion.Major == 5 && kernelVersion.Minor >= 6) {
		_, err = t.module.objects.SyscallStatsMap.BatchDelete(obsoleteStatsKeys, &ebpf.BatchOptions{})
		if err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("got error while trying to delete syscall stats: %w", err)
			}
		}
	} else {
		for _, key := range obsoleteStatsKeys {
			err = t.module.objects.SyscallStatsMap.Delete(key)
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.log.Warnf("deleting syscall stats: %v", err)
			}
		}
	}
	return nil
}
