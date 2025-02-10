#ifndef __COMMON_NETFLOW_H__
#define __COMMON_NETFLOW_H__

#include "network.h"
#include "maps.h"

statfunc void
update_traffic_summary(struct traffic_summary *val, u64 bytes, enum flow_direction direction)
{
    if (unlikely(!val)) {
        return;
    }

    val->last_packet_ts = bpf_ktime_get_ns();

    switch (direction) {
        case INGRESS:
            __sync_fetch_and_add(&val->rx_bytes, bytes);
            __sync_fetch_and_add(&val->rx_packets, 1);
            break;
        case EGRESS:
            __sync_fetch_and_add(&val->tx_bytes, bytes);
            __sync_fetch_and_add(&val->tx_packets, 1);
            break;
    }
}

statfunc void record_netflow(struct __sk_buff *ctx,
                             task_context_t *task_ctx,
                             nethdrs *nethdrs,
                             enum flow_direction direction)
{
    process_identity_t identity = {
        .pid = task_ctx->pid,
        .pid_start_time = task_ctx->start_time,
        .cgroup_id = task_ctx->cgroup_id,
    };

    __builtin_memcpy(identity.comm, task_ctx->comm, sizeof(identity.comm));

    int zero = 0;
    config_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (!config)
        return;

    struct ip_key key = {0};

    if (!load_ip_key(&key, ctx->sk, nethdrs, identity, direction)) {
        return;
    }

    void *sum_map = bpf_map_lookup_elem(&network_traffic_buffer_map, &config->summary_map_index);
    if (!sum_map)
        return;

    struct traffic_summary *summary = bpf_map_lookup_elem(sum_map, &key);
    if (summary == NULL) {
        struct traffic_summary empty = {0};

        // We do not really care if the update fails, as it would mean, another thread added the
        // entry.
        bpf_map_update_elem(sum_map, &key, &empty, BPF_NOEXIST);

        summary = bpf_map_lookup_elem(sum_map, &key);
        if (summary == NULL) // Something went terribly wrong...
            return;
    }

    update_traffic_summary(summary, ctx->len, direction);
}

#endif
