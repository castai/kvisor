#ifndef __COMMON_METRICS_H__
#define __COMMON_METRICS_H__

#include "common/common.h"
#include "common/consts.h"
#include "types.h"

statfunc void metrics_increase(enum metric m)
{
    if (!global_config.export_metrics) {
        return;
    }

    if (m >= MAX_METRIC) {
        enum metric unknown = UNKNOWN_METRIC;
        u64 *counter = bpf_map_lookup_elem(&metrics, &unknown);
        if (unlikely(counter == NULL)) {
            return;
        }
        __sync_fetch_and_add(counter, 1);
        return;
    }
    u64 *counter = bpf_map_lookup_elem(&metrics, &m);
    if (unlikely(counter == NULL)) {
        return;
    }
    // When the u64 overflows, we should start back at 0, so there is no need to think about
    // reseting the counter.
    __sync_fetch_and_add(counter, 1);
}

#endif /* __COMMON_METRICS_H__ */
