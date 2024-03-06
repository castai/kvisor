#ifndef __STATS_H__
#define __STATS_H__

#include <vmlinux.h>

#include <types.h>
#include <common/common.h>

statfunc int update_syscall_stats(void *ctx, u64 cgroup_id, u64 syscall_id)
{
    syscall_stats_key_t key = {};
    key.cgroup_id = cgroup_id;
    key.id = syscall_id;

    u64 *count = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!count) {
        u64 initial_val = 1;
        bpf_map_update_elem(&syscall_stats_map, &key, &initial_val, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(count, 1);
    return 0;
}

#endif
