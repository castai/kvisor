typedef struct net_task_context {
    struct task_struct *task;
    task_context_t taskctx;
    u64 matched_policies;
    int syscall;
} net_task_context_t;

typedef struct task_context {
    u64 start_time; // thread's start time
    u64 cgroup_id;
    u32 pid;       // PID as in the userspace term
    u32 tid;       // TID as in the userspace term
    u32 ppid;      // Parent PID as in the userspace term
    u32 host_pid;  // PID in host pid namespace
    u32 host_tid;  // TID in host pid namespace
    u32 host_ppid; // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 flags;
} task_context_t;

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced;  // indicates that syscall_data is valid
    bool recompute_scope; // recompute matched_scopes (new task/context changed/policy changed)
    u64 matched_scopes;   // cached bitmap of scopes this task matched
    u8 container_state;   // the state of the container the task resides in
} task_info_t;

typedef struct event_context {
    u64 ts; // Timestamp
    task_context_t task;
    u32 eventid;
    s32 syscall; // The syscall which triggered the event
    u64 matched_policies;
    s64 retval;
    u32 stack_id;
    u16 processor_id; // The ID of the processor which processed the event
    u8 argnum;
} event_context_t;

// p->event.task = netctx->task
// p->event.context.task =

typedef struct event_data {
    event_context_t context;
    args_buffer_t args_buf;
    struct task_struct *task;
    u64 param_types;
} event_data_t;

typedef struct program_data {
    config_entry_t *config;
    task_info_t *task_info;
    event_data_t *event;
    scratch_t *scratch;
    void *ctx;
} program_data_t;

statfunc int init_program_data(program_data_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based event_data_t pointer
    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->event->task = (struct task_struct *) bpf_get_current_task();
    ret = init_context(ctx, &p->event->context, p->event->task, p->config->options);
    if (unlikely(ret < 0)) {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_INIT_CONTEXT, ret);
        return 0;
    }

    p->ctx = ctx;
    p->event->args_buf.offset = 0;
    p->event->args_buf.argnum = 0;

    bool container_lookup_required = true;

    p->task_info = bpf_map_lookup_elem(&task_info_map, &p->event->context.task.host_tid);
    if (unlikely(p->task_info == NULL)) {
        p->task_info = init_task_info(
            p->event->context.task.host_tid, p->event->context.task.host_pid, p->scratch);
        if (unlikely(p->task_info == NULL)) {
            return 0;
        }
        // just initialized task info: recompute_scope is already set to true
        goto out;
    }

    // in some places we don't call should_trace() (e.g. sys_exit) which also initializes
    // matched_policies. Use previously found scopes then to initialize it.
    p->event->context.matched_policies = p->task_info->matched_scopes;

    // check if we need to recompute scope due to context change
    if (context_changed(&p->task_info->context, &p->event->context.task))
        p->task_info->recompute_scope = true;

    u8 container_state = p->task_info->container_state;

    // if task is already part of a container: no need to check if state changed
    switch (container_state) {
        case CONTAINER_STARTED:
        case CONTAINER_EXISTED:
            p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            container_lookup_required = false;
    }

out:
    if (container_lookup_required) {
        u32 cgroup_id_lsb = p->event->context.task.cgroup_id;
        u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);

        if (state != NULL) {
            p->task_info->container_state = *state;
            switch (*state) {
                case CONTAINER_STARTED:
                case CONTAINER_EXISTED:
                    p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
            }
        }
    }

    // update task_info with the new context
    bpf_probe_read(&p->task_info->context, sizeof(task_context_t), &p->event->context.task);

    return 1;
}

statfunc int save_to_submit_buf(args_buffer_t *, void *, u32, u8);

statfunc int events_perf_submit(program_data_t *p, u32 id, long ret)
{
    p->event->context.eventid = id;
    p->event->context.retval = ret;

    // Get Stack trace
    if (p->config->options & OPT_CAPTURE_STACK_TRACES) {
        int stack_id = bpf_get_stackid(p->ctx, &stack_addresses, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            p->event->context.stack_id = stack_id;
        }
    }

    u32 size = sizeof(event_context_t) + p->event->buf_off;

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    return bpf_perf_event_output(p->ctx, &events, BPF_F_CURRENT_CPU, p->event, size);
}

typedef struct net_event_context {
    event_context_t eventctx;
    u8 argnum;
    struct { // event arguments (needs packing), use anonymous struct to ...
        u8 index0;
        u32 bytes;
        // ... (payload sent by bpf_perf_event_output)
    } __attribute__((__packed__)); // ... avoid address-of-packed-member warns
    // members bellow this point are metadata (not part of event to be sent)
    net_event_contextmd_t md;
} __attribute__((__packed__)) net_event_context_t;
