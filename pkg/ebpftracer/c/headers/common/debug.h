#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG_NAME_LEN 16
#define TASK_COMM_LEN 16

struct debug_event_t {
    u32 pid;
    u32 tid;
    u64 ts;
    u64 cgroup_id;
    char name[DEBUG_NAME_LEN];
    char task[TASK_COMM_LEN];
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    // For sock.
//    u64 sock_addr;
//    struct tuple_t tuple;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} debug_events SEC(".maps");

static __always_inline void fill_debug_event_name(struct debug_event_t *e, const char *name) {
    for (int i = 0; i < DEBUG_NAME_LEN; i++) {
        e->name[i] = name[i];
    }
}

static __always_inline void init_debug_event(const char *name, struct debug_event_t *event) {
    event->ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    event->pid = pid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->task, sizeof(event->task));
    fill_debug_event_name(event, name);
}

static __always_inline void output_debug(void *ctx, const char *name) {
    struct debug_event_t event = {0};
    init_debug_event(name, &event);

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline void output_debug1(void *ctx, const char *name, u64 arg1) {
    struct debug_event_t event = {0};
    init_debug_event(name, &event);
    event.arg1 = arg1;

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline void output_debug2(void *ctx, const char *name, u64 arg1, u64 arg2) {
    struct debug_event_t event = {0};
    init_debug_event(name, &event);
    event.arg1 = arg1;
    event.arg2 = arg2;

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline void output_debug3(void *ctx, const char *name, u64 arg1, u64 arg2, u64 arg3) {
    struct debug_event_t event = {0};
    init_debug_event(name, &event);
    event.arg1 = arg1;
    event.arg2 = arg2;
    event.arg3 = arg3;

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

static __always_inline void output_debug4(void *ctx, const char *name, u64 arg1, u64 arg2, u64 arg3, u64 arg4) {
    struct debug_event_t event = {0};
    init_debug_event(name, &event);
    event.arg1 = arg1;
    event.arg2 = arg2;
    event.arg3 = arg3;
    event.arg4 = arg4;

    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}
//
//static __always_inline void output_debug_sock(void *ctx, const char *name, struct sock *sk) {
//    if (cfg->debug == 0) {
//        return;
//    }
//
//    struct debug_event_t event = {0};
//    init_debug_event(name, &event);
//    event.sock_addr = (u64) (void *)sk;
//    bpf_get_current_comm(&event.task, sizeof(event.task));
//    fill_tuple(&event.tuple, sk);
//    fill_debug_event_name(&event, name);
//
//    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//}

#endif