#ifndef __COMMON_FILTERING_H__
#define __COMMON_FILTERING_H__

#include "common/consts.h"
#include <vmlinux.h>

#include <maps.h>
#include <common/logging.h>
#include <common/task.h>
#include <common/common.h>

// PROTOTYPES

statfunc bool should_trace(program_data_t *);
statfunc bool should_submit(u32, event_data_t *);
statfunc bool should_submit_event(u32);

// FUNCTIONS

statfunc bool should_trace(program_data_t *p)
{
    if (bpf_map_lookup_elem(&ignored_cgroups_map, &p->event->context.task.cgroup_id) != NULL) {
        return false;
    }

    task_context_t *context = &p->event->context.task;

    // Don't monitor self
    if (global_config.self_pid == context->host_pid)
        return false;

    return true;
}

statfunc bool should_skip_cgroup(u64 cgroup_id)
{
    return !!bpf_map_lookup_elem(&ignored_cgroups_map, &cgroup_id);
}

statfunc bool should_submit(u32 event_id, event_data_t *event)
{
    event_config_t *event_config = bpf_map_lookup_elem(&events_map, &event_id);
    // if event config not set, don't submit
    if (event_config == NULL)
        return false;

    // save event's param types
    event->param_types = event_config->param_types;

    return true;
}

statfunc bool should_submit_event(u32 event_id)
{
    return !!bpf_map_lookup_elem(&events_map, &event_id);
}

#endif
