// +build ignore

// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0
// Copyright (C) Aqua Security inc.

#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#undef container_of

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <maps.h>
#include <types.h>

#include <common/arch.h>
#include <common/arguments.h>
#include <common/binprm.h>
#include <common/buffer.h>
#include <common/cgroups.h>
#include <common/common.h>
#include <common/consts.h>
#include <common/context.h>
#include <common/filesystem.h>
#include <common/filtering.h>
#include <common/logging.h>
#include <common/memory.h>
#include <common/network.h>
#include <common/stats.h>
#include <common/metrics.h>
#include <common/signatures.h>
#include <common/metrics.h>

char LICENSE[] SEC("license") = "GPL";

extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig;

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// initial entry for sys_enter syscall logic
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    int id = ctx->args[1];
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    u64 cgroup_id = 0;
    if (global_config.cgroup_v1) {
        cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        cgroup_id = bpf_get_current_cgroup_id();
    }
    // Skip if cgroup is muted
    if (bpf_map_lookup_elem(&ignored_cgroups_map, &cgroup_id) != NULL) {
        return 0;
    }
    // Update containers syscall stats.
    if (global_config.track_syscall_stats) {
        update_syscall_stats(ctx, cgroup_id, id);
    }

    // Continue to tail calls.
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}

// initial tail call entry from sys_enter.
// purpose is to save the syscall info of relevant syscalls through the task_info map.
// can move to one of:
// 1. sys_enter_submit, general event submit logic from sys_enter
// 2. directly to syscall tail handler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_init")
int sys_enter_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL)) {
            return 0;
        }
        init_task_context(&task_info->context, task);
    }

    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];

    if (LINUX_HAS_SYSCALL_WRAPPER) {
        struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
            sys->args.args[0] = BPF_CORE_READ(regs, bx);
            sys->args.args[1] = BPF_CORE_READ(regs, cx);
            sys->args.args[2] = BPF_CORE_READ(regs, dx);
            sys->args.args[3] = BPF_CORE_READ(regs, si);
            sys->args.args[4] = BPF_CORE_READ(regs, di);
            sys->args.args[5] = BPF_CORE_READ(regs, bp);
#endif // bpf_target_x86
        } else {
            sys->args.args[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
            sys->args.args[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
            sys->args.args[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
            sys->args.args[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
            sys->args.args[4] = PT_REGS_PARM5_CORE_SYSCALL(regs);
            sys->args.args[5] = PT_REGS_PARM6_CORE_SYSCALL(regs);
        }
    } else {
        bpf_probe_read(sys->args.args, sizeof(6 * sizeof(u64)), (void *) ctx->args);
    }

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYSCALL_EXIT && sys->id != SYSCALL_EXIT_GROUP &&
        sys->id != SYSCALL_RT_SIGRETURN) {
        sys->ts = bpf_ktime_get_ns();
        task_info->syscall_traced = true;
    }

    // if id is irrelevant continue to next tail call
    bpf_tail_call(ctx, &sys_enter_submit_tail, sys->id);

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// submit tail call part of sys_enter.
// events that are required for submission go through two logics here:
// 1. parsing their FD filepath if requested as an option
// 2. submitting the event if relevant
// may move to the direct syscall handler in sys_enter_tails
SEC("raw_tracepoint/sys_enter_submit")
int sys_enter_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (sys->id != SYSCALL_RT_SIGRETURN && !p.task_info->syscall_traced) {
        save_to_submit_buf(&p.event->args_buf, (void *) &(sys->args.args[0]), sizeof(int), 0);
        events_ringbuf_submit(&p, sys->id, 0);
    }

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long ret)
// initial entry for sys_exit syscall logic
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Skip if cgroup is muted.
    u64 cgroup_id = 0;
    if (global_config.cgroup_v1) {
        cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        cgroup_id = bpf_get_current_cgroup_id();
    }
    if (bpf_map_lookup_elem(&ignored_cgroups_map, &cgroup_id) != NULL) {
        return 0;
    }

    bpf_tail_call(ctx, &sys_exit_init_tail, id);
    return 0;
}

// initial tail call entry from sys_exit.
// purpose is to "confirm" the syscall data saved by marking it as complete(see
// task_info->syscall_traced) and adding the return value to the syscall_info struct. can move to
// one of:
// 1. sys_exit, general event submit logic from sys_exit
// 2. directly to syscall tail hanler in sys_exit_tails
SEC("raw_tracepoint/sys_exit_init")
int sys_exit_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL))
            return 0;

        init_task_context(&task_info->context, task);
    }

    // check if syscall is being traced and mark that it finished
    if (!task_info->syscall_traced)
        return 0;
    task_info->syscall_traced = false;

    syscall_data_t *sys = &task_info->syscall_data;

    long ret = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    // Sanity check - we returned from the expected syscall this task was executing
    if (sys->id != id)
        return 0;

    sys->ret = ret;

    // move to submit tail call if needed
    bpf_tail_call(ctx, &sys_exit_submit_tail, id);

    // otherwise move to direct syscall handler
    bpf_tail_call(ctx, &sys_exit_tails, id);
    return 0;
}

// submit tail call part of sys_exit.
// most syscall events are submitted at this point, and if not,
// they are submitted through direct syscall handlers in sys_exit_tails
SEC("raw_tracepoint/sys_exit_submit")
int sys_exit_submit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;
    long ret = ctx->args[1];

    if (!should_submit(sys->id, p.event))
        goto out;

    // We can't use saved args after execve syscall, as pointers are invalid.
    // To avoid showing execve event both on entry and exit, we only output failed execs.
    if ((sys->id == SYSCALL_EXECVE || sys->id == SYSCALL_EXECVEAT) && (ret == 0))
        goto out;

    save_args_to_submit_buf(p.event, &sys->args);
    p.event->context.ts = sys->ts;
    events_ringbuf_submit(&p, sys->id, ret);

out:
    bpf_tail_call(ctx, &sys_exit_tails, sys->id);
    return 0;
}

// here are the direct hook points for sys_enter and sys_exit.
// There are used not for submitting syscall events but the enter and exit events themselves.
// As such they are usually not attached, and will only be used if sys_enter or sys_exit events are
// given as tracing arguments.

// separate hook point for sys_enter event tracing
SEC("raw_tracepoint/trace_sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_ENTER, p.event))
        return 0;

    // always submit since this won't be attached otherwise
    int id = ctx->args[1];
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &id, sizeof(int), 0);
    events_ringbuf_submit(&p, RAW_SYS_ENTER, 0);
    return 0;
}

// separate hook point for sys_exit event tracing
SEC("raw_tracepoint/trace_sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(RAW_SYS_EXIT, p.event))
        return 0;

    // always submit since this won't be attached otherwise
    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];
    int id = get_syscall_id_from_regs(regs);
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    save_to_submit_buf(&p.event->args_buf, (void *) &id, sizeof(int), 0);
    events_ringbuf_submit(&p, RAW_SYS_EXIT, 0);
    return 0;
}

SEC("raw_tracepoint/sys_execve")
int syscall__execve(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!should_submit(SYSCALL_EXECVE, p.event))
        return 0;

    reset_event_args(&p);
    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[0] /*filename*/, 0);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[1] /*argv*/, 1);

    return events_ringbuf_submit(&p, SYSCALL_EXECVE, 0);
}

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!p.task_info->syscall_traced)
        return -1;
    syscall_data_t *sys = &p.task_info->syscall_data;
    p.event->context.ts = sys->ts;

    if (!should_submit(SYSCALL_EXECVEAT, p.event))
        return 0;

    reset_event_args(&p);
    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[0] /*dirfd*/, sizeof(int), 0);
    save_str_to_buf(&p.event->args_buf, (void *) sys->args.args[1] /*pathname*/, 1);
    save_str_arr_to_buf(&p.event->args_buf, (const char *const *) sys->args.args[2] /*argv*/, 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &sys->args.args[4] /*flags*/, sizeof(int), 4);

    return events_ringbuf_submit(&p, SYSCALL_EXECVEAT, 0);
}

statfunc int send_stdio_via_socket_from_socket_dup(program_data_t *p, u64 oldfd, u64 newfd)
{
    if (!should_submit(STDIO_VIA_SOCKET, p->event)) {
        return 0;
    }

    if (!check_fd_type(oldfd, S_IFSOCK)) {
        return 0;
    }

    struct file *f = get_struct_file_from_fd(oldfd);
    if (f == NULL) {
        return -1;
    }

    // get the address
    struct socket *socket_from_file = (struct socket *) BPF_CORE_READ(f, private_data);
    if (socket_from_file == NULL) {
        return -1;
    }

    struct sock *sk = get_socket_sock(socket_from_file);
    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (!is_stdio_via_socket(newfd, family)) {
        return 0;
    }

    reset_event_args(p);
    save_to_submit_buf(&(p->event->args_buf), &newfd, sizeof(u32), 0);

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in remote;
        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);
        save_to_submit_buf(&(p->event->args_buf), &remote, sizeof(struct sockaddr_in), 1);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 remote;
        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);
        save_to_submit_buf(&(p->event->args_buf), &remote, sizeof(struct sockaddr_in6), 1);
    }

    return events_ringbuf_submit(p, STDIO_VIA_SOCKET, 0);
}

SEC("raw_tracepoint/sys_dup")
int sys_dup_exit_tail(void *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    syscall_data_t *sys = &p.task_info->syscall_data;

    if (sys->ret < 0) {
        // dup failed
        return 0;
    }

    if (sys->id == SYSCALL_DUP) {
        // args.args[0]: oldfd
        // retval: newfd
        send_stdio_via_socket_from_socket_dup(&p, sys->args.args[0], sys->ret);
    } else if (sys->id == SYSCALL_DUP2 || sys->id == SYSCALL_DUP3) {
        // args.args[0]: oldfd
        // args.args[1]: newfd
        // retval: retval
        send_stdio_via_socket_from_socket_dup(&p, sys->args.args[0], sys->args.args[1]);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *parent, struct task_struct *child)
//
// NOTE: sched_process_fork is called by kernel_clone(), which is executed during
//       clone() calls as well, not only fork(). This means that sched_process_fork()
//       is also able to pick the creation of LWPs through clone().
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // NOTE: proc_info_map updates before should_trace() as the entries are needed in other places.

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    // Information needed before the event:
    int parent_pid = get_task_host_tgid(parent);
    u64 child_start_time = get_task_start_time(child);
    int child_pid = get_task_host_tgid(child);
    int child_tid = get_task_host_pid(child);
    int child_ns_pid = get_task_ns_tgid(child);
    int child_ns_tid = get_task_ns_pid(child);

    // Update the task_info map with the new task's info

    ret = bpf_map_update_elem(&task_info_map, &child_tid, p.task_info, BPF_ANY);
    if (ret < 0)
        tracee_log(ctx, BPF_LOG_LVL_DEBUG, BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
    task_info_t *task = bpf_map_lookup_elem(&task_info_map, &child_tid);
    if (unlikely(task == NULL)) {
        // this should never happen - we just updated the map with this key
        tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
        return 0;
    }

    task->context.tid = child_ns_tid;
    task->context.host_tid = child_tid;
    task->context.start_time = child_start_time;

    // Update the proc_info_map with the new process's info (from parent)

    proc_info_t *c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_pid);
    if (c_proc_info == NULL) {
        // It is a new process (not another thread): add it to proc_info_map.
        proc_info_t *p_proc_info = bpf_map_lookup_elem(&proc_info_map, &parent_pid);
        if (unlikely(p_proc_info == NULL)) {
            // parent should exist in proc_info_map (init_program_data sets it)
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        // Copy the parent's proc_info to the child's entry.
        bpf_map_update_elem(&proc_info_map, &child_pid, p_proc_info, BPF_NOEXIST);
        c_proc_info = bpf_map_lookup_elem(&proc_info_map, &child_pid);
        if (unlikely(c_proc_info == NULL)) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_ID_MAP_LOOKUP_ELEM, 0);
            return 0;
        }

        c_proc_info->new_proc = true; // started after tracee (new_pid filter)
    }

    if (!should_trace(&p))
        return 0;

    // Submit the event

    if (should_submit(SCHED_PROCESS_FORK, p.event)) {
        // Parent information.
        u64 parent_start_time = get_task_start_time(parent);
        int parent_tid = get_task_host_pid(parent);
        int parent_ns_pid = get_task_ns_tgid(parent);
        int parent_ns_tid = get_task_ns_pid(parent);

        // Parent (might be a thread or a process).
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_tid, sizeof(int), 0);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_ns_tid, sizeof(int), 1);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_pid, sizeof(int), 2);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_ns_pid, sizeof(int), 3);
        save_to_submit_buf(&p.event->args_buf, (void *) &parent_start_time, sizeof(u64), 4);

        // Child (might be a lwp or a process, sched_process_fork trace is calle by clone() also).
        save_to_submit_buf(&p.event->args_buf, (void *) &child_tid, sizeof(int), 5);
        save_to_submit_buf(&p.event->args_buf, (void *) &child_ns_tid, sizeof(int), 6);
        save_to_submit_buf(&p.event->args_buf, (void *) &child_pid, sizeof(int), 7);
        save_to_submit_buf(&p.event->args_buf, (void *) &child_ns_pid, sizeof(int), 8);
        save_to_submit_buf(&p.event->args_buf, (void *) &child_start_time, sizeof(u64), 9);

        // Both, the thread group leader and the "up_parent" (the first process, not lwp, found
        // as a parent of the child in the hierarchy), are needed by the userland process tree.
        // The userland process tree default source of events is the signal events, but there is
        // an option to use regular event for maintaining it as well (and it is needed for some
        // situatins). These arguments will always be removed by userland event processors.
        struct task_struct *leader = get_leader_task(child);
        struct task_struct *up_parent = get_leader_task(get_parent_task(leader));

        // Up Parent information: Go up in hierarchy until parent is process.
        u64 up_parent_start_time = get_task_start_time(up_parent);
        int up_parent_pid = get_task_host_tgid(up_parent);
        int up_parent_tid = get_task_host_pid(up_parent);
        int up_parent_ns_pid = get_task_ns_tgid(up_parent);
        int up_parent_ns_tid = get_task_ns_pid(up_parent);
        // Leader information.
        u64 leader_start_time = get_task_start_time(leader);
        int leader_pid = get_task_host_tgid(leader);
        int leader_tid = get_task_host_pid(leader);
        int leader_ns_pid = get_task_ns_tgid(leader);
        int leader_ns_tid = get_task_ns_pid(leader);

        // Up Parent: always a process (might be the same as Parent if parent is a process).
        save_to_submit_buf(&p.event->args_buf, (void *) &up_parent_tid, sizeof(int), 10);
        save_to_submit_buf(&p.event->args_buf, (void *) &up_parent_ns_tid, sizeof(int), 11);
        save_to_submit_buf(&p.event->args_buf, (void *) &up_parent_pid, sizeof(int), 12);
        save_to_submit_buf(&p.event->args_buf, (void *) &up_parent_ns_pid, sizeof(int), 13);
        save_to_submit_buf(&p.event->args_buf, (void *) &up_parent_start_time, sizeof(u64), 14);
        // Leader: always a process (might be the same as the Child if child is a process).
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_tid, sizeof(int), 15);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_ns_tid, sizeof(int), 16);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_pid, sizeof(int), 17);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_ns_pid, sizeof(int), 18);
        save_to_submit_buf(&p.event->args_buf, (void *) &leader_start_time, sizeof(u64), 19);

        // Submit
        signal_events_ringbuf_submit(&p, SCHED_PROCESS_FORK, 0);
    }

    return 0;
}

SEC("kprobe/exec_binprm")
int BPF_KPROBE(trace_exec_binprm)
{
    args_t args = {};
    args.args[0] = PT_REGS_PARM1(ctx);
    args.args[1] = PT_REGS_PARM2(ctx);
    args.args[2] = PT_REGS_PARM3(ctx);
    args.args[3] = PT_REGS_PARM4(ctx);
    args.args[4] = PT_REGS_PARM5(ctx);
    args.args[5] = PT_REGS_PARM6(ctx);

    // requried by kretprobe for this function
    save_args(&args, EXEC_BINPRM);

    // NOTE: we cannot do the calc based on the value we store in the args map, as the binprm struct
    // gets modified during the function execution and before it hits the tracepoint.

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct linux_binprm *bprm = (void *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    struct path f_path = (struct path) BPF_CORE_READ(file, f_path);
    struct dentry *dentry = f_path.dentry;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);

    u16 flags = 0;
    if (sb && inode) {
        if (get_exe_upper_layer(dentry, sb)) {
            flags |= FS_EXE_UPPER_LAYER;
        }

        if (is_executed_in_tmpfs(sb)) {
            flags |= FS_EXE_FROM_TMPFS;
        }

        if (get_exe_from_memfd(file)) {
            flags |= FS_EXE_FROM_MEMFD;
        }
    }

    bpf_map_update_elem(&pid_original_file_flags, &pid, &flags, BPF_ANY);

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    if (bprm == NULL) {
        return -1;
    }
    struct file *file = get_file_ptr_from_bprm(bprm);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

    proc_info_t *proc_info = p.proc_info;
    proc_info->new_proc = true; // task has started after tracee started running

    // extract the binary name to be used in should_trace
    __builtin_memset(proc_info->binary.path, 0, MAX_BIN_PATH_SIZE);
    bpf_probe_read_kernel_str(proc_info->binary.path, MAX_BIN_PATH_SIZE, file_path);
    proc_info->binary.mnt_id = p.event->context.task.mnt_id;

    if (!should_trace(&p)) {
        return 0;
    }

    if (!should_submit(SCHED_PROCESS_EXEC, p.event)) {
        return 0;
    }

    // Note: From v5.9+, there are two interesting fields in bprm that could be added:
    // 1. struct file *executable: the executable name passed to an interpreter
    // 2. fdpath: generated filename for execveat (after resolving dirfd)

    const char *filename = get_binprm_filename(bprm);
    dev_t s_dev = get_dev_from_file(file);
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned long inode_nr = BPF_CORE_READ(inode, i_ino);
    u64 ctime = get_ctime_nanosec_from_file(file);
    umode_t inode_mode = get_inode_mode_from_file(file);

    save_str_to_buf(&p.event->args_buf, (void *) filename, 0);
    save_str_to_buf(&p.event->args_buf, file_path, 1);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 2);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3);
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);
    save_to_submit_buf(&p.event->args_buf, &inode_mode, sizeof(umode_t), 5);

    // NOTES:
    // - interp is the real interpreter (sh, bash, python, perl, ...)
    // - interpreter is the binary interpreter (ld.so), also known as the loader
    // - interpreter might be the same as executable (so there is no interpreter)

    // Check if there is an interpreter and if it is different from the executable:

    bool itp_inode_exists = proc_info->interpreter.id.inode != 0;
    bool itp_dev_diff = proc_info->interpreter.id.device != s_dev;
    bool itp_inode_diff = proc_info->interpreter.id.inode != inode_nr;

    if (itp_inode_exists && (itp_dev_diff || itp_inode_diff)) {
        save_str_to_buf(
            &p.event->args_buf, &proc_info->interpreter.pathname, 6); // interpreter path
        save_to_submit_buf(&p.event->args_buf,
                           &proc_info->interpreter.id.device,
                           sizeof(dev_t),
                           7); // interpreter device number
        save_to_submit_buf(&p.event->args_buf,
                           &proc_info->interpreter.id.inode,
                           sizeof(u64),
                           8); // interpreter inode number
        save_to_submit_buf(&p.event->args_buf,
                           &proc_info->interpreter.id.ctime,
                           sizeof(u64),
                           9); // interpreter changed time
    }

    struct path f_path = (struct path) BPF_CORE_READ(file, f_path);
    struct dentry *dentry = f_path.dentry;
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    u32 flags = 0;
    if (sb && inode) {
        if (get_exe_upper_layer(dentry, sb)) {
            flags |= FS_EXE_UPPER_LAYER;
        }

        if (is_executed_in_tmpfs(sb)) {
            flags |= FS_EXE_FROM_TMPFS;
        }

        if (get_exe_from_memfd(file)) {
            flags |= FS_EXE_FROM_MEMFD;
        }
    }

    // If there is a dummy element in the map, we know the binary was dropped.
    if (bpf_map_lookup_elem(&dropped_binary_inodes, &inode_nr)) {
        flags |= FS_EXE_DROPPED_BINARY;
    }

    pid_t pid = p.event->context.task.host_pid;
    u16 *original_flags = bpf_map_lookup_elem(&pid_original_file_flags, &pid);
    if (original_flags != NULL) {
        u32 upper_flags = *original_flags;
        upper_flags = upper_flags << 16;
        flags |= upper_flags;
        bpf_map_delete_elem(&pid_original_file_flags, &pid);
    }

    save_to_submit_buf(&p.event->args_buf, &flags, sizeof(flags), 15);

    bpf_tail_call(ctx, &prog_array_tp, TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT);

    return 0;
}

SEC("raw_tracepoint/sched_process_exec_event_submit_tail")
int sched_process_exec_event_submit_tail(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_tailcall_program_data(&p, ctx))
        return -1;

    struct task_struct *task = (struct task_struct *) ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];

    if (bprm == NULL)
        return -1;

    // bprm->mm is null at this point (set by begin_new_exec()), and task->mm is already initialized
    struct mm_struct *mm = get_mm_from_task(task);

    unsigned long arg_start, arg_end;
    arg_start = get_arg_start_from_mm(mm);
    arg_end = get_arg_end_from_mm(mm);
    int argc = get_argc_from_bprm(bprm);

    struct file *stdin_file = get_struct_file_from_fd(0);
    unsigned short stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
    void *stdin_path = get_path_str(__builtin_preserve_access_index(&stdin_file->f_path));
    const char *interp = get_binprm_interp(bprm);

    int invoked_from_kernel = 0;
    if (get_task_parent_flags(task) & PF_KTHREAD) {
        invoked_from_kernel = 1;
    }

    save_args_str_arr_to_buf(&p.event->args_buf, (void *) arg_start, (void *) arg_end, argc, 10);
    save_str_to_buf(&p.event->args_buf, (void *) interp, 11);
    save_to_submit_buf(&p.event->args_buf, &stdin_type, sizeof(unsigned short), 12);
    save_str_to_buf(&p.event->args_buf, stdin_path, 13);
    save_to_submit_buf(&p.event->args_buf, &invoked_from_kernel, sizeof(int), 14);

    signal_events_ringbuf_submit(&p, SCHED_PROCESS_EXEC, 0);
    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    // evaluate should_trace before removing this pid from the maps
    bool traced = !!should_trace(&p);

    bpf_map_delete_elem(&task_info_map, &p.event->context.task.host_tid);

    bool group_dead = false;
    struct task_struct *task = p.task;
    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    atomic_t live = BPF_CORE_READ(signal, live);
    // This check could be true for multiple thread exits if the thread count was 0 when the hooks
    // were triggered. This could happen for example if the threads performed exit in different CPUs
    // simultaneously.
    if (live.counter == 0) {
        group_dead = true;
    }

    bool oom_killed = false;

    if (bpf_map_lookup_elem(&oom_info, &p.task_info->context.host_pid)) {
        oom_killed = true;
        bpf_map_delete_elem(&oom_info, &p.task_info->context.host_pid);
    }

    if (!traced)
        return 0;

    long exit_code = get_task_exit_code(p.task);

    if (oom_killed) {
        if (should_submit(PROCESS_OOM_KILLED, p.event)) {
            save_to_submit_buf(&p.event->args_buf, (void *) &exit_code, sizeof(long), 0);
            save_to_submit_buf(&p.event->args_buf, (void *) &group_dead, sizeof(bool), 1);

            signal_events_ringbuf_submit(&p, PROCESS_OOM_KILLED, 0);
        }

        return 0;
    }

    if (should_submit(SCHED_PROCESS_EXIT, p.event)) {
        save_to_submit_buf(&p.event->args_buf, (void *) &exit_code, sizeof(long), 0);
        save_to_submit_buf(&p.event->args_buf, (void *) &group_dead, sizeof(bool), 1);

        signal_events_ringbuf_submit(&p, SCHED_PROCESS_EXIT, 0);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(struct task_struct *p)
SEC("raw_tracepoint/sched_process_free")
int tracepoint__sched__sched_process_free(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) ctx->args[0];

    int pid = get_task_host_pid(task);
    int tgid = get_task_host_tgid(task);

    if (pid == tgid) {
        // we only care about process (and not thread) exit
        // if tgid task is freed, we know for sure that the process exited
        // so we can safely remove it from the process map
        bpf_map_delete_elem(&proc_info_map, &tgid);
    }

    return 0;
}

// trace/events/sched.h: TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SCHED_SWITCH, p.event))
        return 0;

    struct task_struct *prev = (struct task_struct *) ctx->args[1];
    struct task_struct *next = (struct task_struct *) ctx->args[2];
    int prev_pid = get_task_host_pid(prev);
    int next_pid = get_task_host_pid(next);
    int cpu = bpf_get_smp_processor_id();

    save_to_submit_buf(&p.event->args_buf, (void *) &cpu, sizeof(int), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &prev_pid, sizeof(int), 1);
    save_str_to_buf(&p.event->args_buf, prev->comm, 2);
    save_to_submit_buf(&p.event->args_buf, (void *) &next_pid, sizeof(int), 3);
    save_str_to_buf(&p.event->args_buf, next->comm, 4);

    return events_ringbuf_submit(&p, SCHED_SWITCH, 0);
}

statfunc struct trace_kprobe *get_trace_kprobe_from_trace_probe(void *tracep)
{
    struct trace_kprobe *tracekp =
        (struct trace_kprobe *) container_of(tracep, struct trace_kprobe, tp);

    return tracekp;
}

statfunc struct trace_uprobe *get_trace_uprobe_from_trace_probe(void *tracep)
{
    struct trace_uprobe *traceup =
        (struct trace_uprobe *) container_of(tracep, struct trace_uprobe, tp);

    return traceup;
}

// This function returns a pointer to struct trace_probe from struct trace_event_call.
statfunc void *get_trace_probe_from_trace_event_call(struct trace_event_call *call)
{
    void *tracep_ptr;

    struct trace_probe___v53 *legacy_tracep;
    if (bpf_core_field_exists(legacy_tracep->call)) {
        tracep_ptr = container_of(call, struct trace_probe___v53, call);
    } else {
        struct trace_probe_event *tpe = container_of(call, struct trace_probe_event, call);
        struct list_head probes = BPF_CORE_READ(tpe, probes);
        tracep_ptr = container_of(probes.next, struct trace_probe, list);
    }

    return tracep_ptr;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CGROUP_MKDIR, p.event))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    save_to_submit_buf(&p.event->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&p.event->args_buf, path, 1);
    save_to_submit_buf(&p.event->args_buf, &hierarchy_id, sizeof(u32), 2);
    signal_events_ringbuf_submit(&p, CGROUP_MKDIR, 0);

    return 0;
}

// trace/events/cgroup.h: TP_PROTO(struct cgroup *cgrp, const char *path)
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(CGROUP_MKDIR, p.event))
        return 0;

    struct cgroup *dst_cgrp = (struct cgroup *) ctx->args[0];
    char *path = (char *) ctx->args[1];

    u32 hierarchy_id = get_cgroup_hierarchy_id(dst_cgrp);
    u64 cgroup_id = get_cgroup_id(dst_cgrp);
    u32 cgroup_id_lsb = cgroup_id;

    save_to_submit_buf(&p.event->args_buf, &cgroup_id, sizeof(u64), 0);
    save_str_to_buf(&p.event->args_buf, path, 1);
    save_to_submit_buf(&p.event->args_buf, &hierarchy_id, sizeof(u32), 2);
    signal_events_ringbuf_submit(&p, CGROUP_RMDIR, 0);

    return 0;
}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(SECURITY_BPRM_CHECK, p.event))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *) PT_REGS_PARM1(ctx);
    struct file *file = get_file_ptr_from_bprm(bprm);
    dev_t s_dev = get_dev_from_file(file);
    unsigned long inode_nr = get_inode_nr_from_file(file);
    void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));

    syscall_data_t *sys = &p.task_info->syscall_data;
    const char *const *argv = NULL;
    const char *const *envp = NULL;
    switch (sys->id) {
        case SYSCALL_EXECVE:
            argv = (const char *const *) sys->args.args[1];
            envp = (const char *const *) sys->args.args[2];
            break;
        case SYSCALL_EXECVEAT:
            argv = (const char *const *) sys->args.args[2];
            envp = (const char *const *) sys->args.args[3];
            break;
        default:
            break;
    }

    save_str_to_buf(&p.event->args_buf, file_path, 0);
    save_to_submit_buf(&p.event->args_buf, &s_dev, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 2);
    save_str_arr_to_buf(&p.event->args_buf, argv, 3);

    return events_ringbuf_submit(&p, SECURITY_BPRM_CHECK, 0);
}

statfunc int send_stdio_via_socket_from_sock_connect(struct pt_regs *ctx, program_data_t *p)
{
    u64 addr_len = PT_REGS_PARM3(ctx);

    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);
    if (!sock)
        return 0;

    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    // Check if the socket type is supported.
    u32 type = BPF_CORE_READ(sock, type);
    switch (type) {
        // TODO: case SOCK_DCCP:
        case SOCK_DGRAM:
        case SOCK_SEQPACKET:
        case SOCK_STREAM:
            break;
        default:
            return 0;
    }

    // Check if the socket family is supported.
    sa_family_t sa_fam = get_sockaddr_family(address);
    switch (sa_fam) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return 0;
    }

    // Load args given to the syscall that invoked this function.
    syscall_data_t *sys = &p->task_info->syscall_data;
    if (!p->task_info->syscall_traced)
        return 0;

    // Reduce line cols by having a few temp pointers.
    reset_event_args(p);
    int (*stsb)(args_buffer_t *, void *, u32, u8) = save_to_submit_buf;
    void *args_buf = &p->event->args_buf;
    void *to = (void *) &sys->args.args[0];

    if (is_x86_compat(p->task)) // only i386 binaries uses socketcall
        to = (void *) sys->args.args[1];

    if (!is_stdio_via_socket((u64) to, sa_fam)) {
        return 0;
    }

    // Save the socket fd, depending on the syscall.
    switch (sys->id) {
        case SYSCALL_CONNECT:
        case SYSCALL_SOCKETCALL:
            break;
        default:
            return 0;
    }

    // Save the socket fd argument to the event.
    stsb(args_buf, to, sizeof(u32), 0);

    bool need_workaround = false;
    // Save the sockaddr struct, depending on the family.
    size_t sockaddr_len = 0;
    switch (sa_fam) {
        case AF_INET:
            sockaddr_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            sockaddr_len = sizeof(struct sockaddr_in6);
            break;
        case AF_UNIX:
            sockaddr_len = sizeof(struct sockaddr_un);
            if (addr_len < sockaddr_len)
                need_workaround = true;
            break;
    }

#if defined(bpf_target_x86)
    if (need_workaround) {
        // Workaround for sockaddr_un struct length (issue: #1129).
        struct sockaddr_un sockaddr = {0};
        bpf_probe_read(&sockaddr, (u32) addr_len, (void *) address);
        stsb(args_buf, (void *) &sockaddr, sizeof(struct sockaddr_un), 1);
    }
#endif
    // Save the sockaddr struct argument to the event.
    if (!need_workaround) {
        stsb(args_buf, (void *) address, sockaddr_len, 1);
    }

    return events_ringbuf_submit(p, STDIO_VIA_SOCKET, 0);
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (should_submit(STDIO_VIA_SOCKET, p.event)) {
        send_stdio_via_socket_from_sock_connect(ctx, &p);
    }

    return 0;
}

enum bin_type_e {
    SEND_VFS_WRITE = 1,
    SEND_MPROTECT,
    SEND_KERNEL_MODULE,
    SEND_BPF_OBJECT,
    SEND_VFS_READ
};

statfunc u32 send_bin_helper(void *ctx, void *prog_array, int tail_call)
{
    // Note: sending the data to the userspace have the following constraints:
    //
    // 1. We need a buffer that we know it's exact size
    //    (so we can send chunks of known sizes in BPF)
    // 2. We can have multiple cpus - need percpu array
    // 3. We have to use perf submit and not maps as data
    //    can be overridden if userspace doesn't consume
    //    it fast enough

    int i = 0;
    unsigned int chunk_size;
    u32 zero = 0;

    event_data_t *event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (!event || (event->args_buf.offset > ARGS_BUF_SIZE - sizeof(bin_args_t)))
        return 0;

    bin_args_t *bin_args = (bin_args_t *) &(event->args_buf.args[event->args_buf.offset]);

    if (bin_args->full_size <= 0) {
        // If there are more vector elements, continue to the next one
        bin_args->iov_idx++;
        if (bin_args->iov_idx < bin_args->iov_len) {
            // Handle the rest of write recursively
            bin_args->start_off += bin_args->full_size;
            struct iovec io_vec;
            bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
            bin_args->ptr = io_vec.iov_base;
            bin_args->full_size = io_vec.iov_len;
            bpf_tail_call(ctx, prog_array, tail_call);
        }
        return 0;
    }

    buf_t *file_buf_p = get_buf(FILE_BUF_IDX);
    if (file_buf_p == NULL)
        return 0;

#define F_SEND_TYPE  0
#define F_CGROUP_ID  (F_SEND_TYPE + sizeof(u8))
#define F_META_OFF   (F_CGROUP_ID + sizeof(u64))
#define F_SZ_OFF     (F_META_OFF + SEND_META_SIZE)
#define F_POS_OFF    (F_SZ_OFF + sizeof(unsigned int))
#define F_CHUNK_OFF  (F_POS_OFF + sizeof(off_t))
#define F_CHUNK_SIZE (MAX_PERCPU_BUFSIZE >> 1)

    bpf_probe_read_kernel((void **) &(file_buf_p->buf[F_SEND_TYPE]), sizeof(u8), &bin_args->type);

    u64 cgroup_id = event->context.task.cgroup_id;
    bpf_probe_read_kernel((void **) &(file_buf_p->buf[F_CGROUP_ID]), sizeof(u64), &cgroup_id);

    // Save metadata to be used in filename
    bpf_probe_read_kernel(
        (void **) &(file_buf_p->buf[F_META_OFF]), SEND_META_SIZE, bin_args->metadata);

    // Save number of written bytes. Set this to CHUNK_SIZE for full chunks
    chunk_size = F_CHUNK_SIZE;
    bpf_probe_read_kernel(
        (void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);

    unsigned int full_chunk_num = bin_args->full_size / F_CHUNK_SIZE;
    void *data = file_buf_p->buf;

// Handle full chunks in loop
#pragma unroll
    for (i = 0; i < MAX_BIN_CHUNKS; i++) {
        // Dummy instruction, as break instruction can't be first with unroll optimization
        chunk_size = F_CHUNK_SIZE;

        if (i == full_chunk_num)
            break;

        // Save binary chunk and file position of write
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_CHUNK_OFF]), F_CHUNK_SIZE, bin_args->ptr);
        bin_args->ptr += F_CHUNK_SIZE;
        bin_args->start_off += F_CHUNK_SIZE;

        bpf_perf_event_output(
            ctx, &file_writes, BPF_F_CURRENT_CPU, data, F_CHUNK_OFF + F_CHUNK_SIZE);
    }

    chunk_size = bin_args->full_size - i * F_CHUNK_SIZE;

    if (chunk_size > F_CHUNK_SIZE) {
        // Handle the rest of write recursively
        bin_args->full_size = chunk_size;
        bpf_tail_call(ctx, prog_array, tail_call);
        return 0;
    }

    if (chunk_size) {
        // Save last chunk
        chunk_size = chunk_size & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
        bpf_probe_read_kernel((void **) &(file_buf_p->buf[F_CHUNK_OFF]), chunk_size, bin_args->ptr);
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_SZ_OFF]), sizeof(unsigned int), &chunk_size);
        bpf_probe_read_kernel(
            (void **) &(file_buf_p->buf[F_POS_OFF]), sizeof(off_t), &bin_args->start_off);

        // Satisfy validator by setting buffer bounds
        int size = (F_CHUNK_OFF + chunk_size) & (MAX_PERCPU_BUFSIZE - 1);
        bpf_perf_event_output(ctx, &file_writes, BPF_F_CURRENT_CPU, data, size);
    }

    // We finished writing an element of the vector - continue to next element
    bin_args->iov_idx++;
    if (bin_args->iov_idx < bin_args->iov_len) {
        // Handle the rest of write recursively
        bin_args->start_off += bin_args->full_size;
        struct iovec io_vec;
        bpf_probe_read(&io_vec, sizeof(struct iovec), &bin_args->vec[bin_args->iov_idx]);
        bin_args->ptr = io_vec.iov_base;
        bin_args->full_size = io_vec.iov_len;
        bpf_tail_call(ctx, prog_array, tail_call);
    }

    return 0;
}

statfunc int is_elf(io_data_t io_data, const u8 header[FILE_MAGIC_HDR_SIZE])
{
    // ELF binaries start with a 4 byte long header
    if (io_data.len < 4) {
        return false;
    }

    return header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
}

statfunc int do_vfs_write_magic_enter(struct pt_regs *ctx)
{
    loff_t start_pos;
    loff_t *pos = (loff_t *) PT_REGS_PARM4(ctx);
    bpf_probe_read_kernel(&start_pos, sizeof(off_t), pos);
    if (start_pos != 0) {
        return 0;
    }
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    unsigned short i_mode = get_inode_mode_from_file(file);
    if ((i_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    args_t args = {};
    args.args[0] = PT_REGS_PARM1(ctx);
    args.args[1] = PT_REGS_PARM2(ctx);
    args.args[2] = PT_REGS_PARM3(ctx);
    args.args[3] = PT_REGS_PARM4(ctx);
    args.args[4] = PT_REGS_PARM5(ctx);
    args.args[5] = PT_REGS_PARM6(ctx);

    return save_args(&args, MAGIC_WRITE);
}

statfunc int do_vfs_write_magic_return(struct pt_regs *ctx, bool is_buf)
{
    args_t saved_args;
    if (load_args(&saved_args, MAGIC_WRITE) != 0) {
        // missed entry or not traced
        return 0;
    }
    del_args(MAGIC_WRITE);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p)) {
        return 0;
    }

    if (!should_submit(MAGIC_WRITE, p.event)) {
        return 0;
    }

    u32 bytes_written = PT_REGS_RC(ctx);
    if (bytes_written == 0) {
        return 0;
    }

    io_data_t io_data;
    file_info_t file_info;

    struct file *file = (struct file *) saved_args.args[0];
    file_info.pathname_p = get_path_str_cached(file);

    io_data.is_buf = is_buf;
    io_data.ptr = (void *) saved_args.args[1];
    io_data.len = (unsigned long) saved_args.args[2];

    // Extract device id, inode number, and pos (offset)
    file_info.id.device = get_dev_from_file(file);
    file_info.id.inode = get_inode_nr_from_file(file);

    u32 header_bytes = FILE_MAGIC_HDR_SIZE;
    if (header_bytes > bytes_written)
        header_bytes = bytes_written;

    u8 header[FILE_MAGIC_HDR_SIZE];
    __builtin_memset(&header, 0, sizeof(header));

    save_str_to_buf(&(p.event->args_buf), file_info.pathname_p, 0);

    fill_file_header(header, io_data);

    if (!is_elf(io_data, header)) {
        return 0;
    }

    u32 one = 1;
    // We just need a dummy value in the map for now.
    bpf_map_update_elem(&dropped_binary_inodes, &file_info.id.inode, &one, BPF_ANY);

    save_bytes_to_buf(&(p.event->args_buf), header, header_bytes, 1);
    save_to_submit_buf(&(p.event->args_buf), &file_info.id.device, sizeof(dev_t), 2);
    save_to_submit_buf(&(p.event->args_buf), &file_info.id.inode, sizeof(unsigned long), 3);

    // Submit magic_write event
    return events_ringbuf_submit(&p, MAGIC_WRITE, bytes_written);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(vfs_writev_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kprobe/__kernel_write")
int BPF_KPROBE(kernel_write_magic_enter)
{
    return do_vfs_write_magic_enter(ctx);
}

SEC("kretprobe/vfs_write")
int BPF_KPROBE(vfs_write_magic_return)
{
    return do_vfs_write_magic_return(ctx, true);
}

SEC("kretprobe/vfs_writev")
int BPF_KPROBE(vfs_writev_magic_return)
{
    return do_vfs_write_magic_return(ctx, false);
}

SEC("kretprobe/__kernel_write")
int BPF_KPROBE(kernel_write_magic_return)
{
    return do_vfs_write_magic_return(ctx, true);
}
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM2(ctx);

    // check if regular file. otherwise don't save the file_mod_key_t in file_modification_map.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};
    int op = FILE_MODIFICATION_SUBMIT;

    bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);

    return 0;
}

SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};

    bpf_map_delete_elem(&file_modification_map, &file_mod_key);

    return 0;
}

enum signal_handling_method_e {
    SIG_DFL,
    SIG_IGN,
    SIG_HND = 2 // Doesn't exist in the kernel, but signifies that the method is through
                // user-defined handler
};

statfunc int common_file_modification_ent(struct pt_regs *ctx)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);

    // check if regular file. otherwise don't output the event.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    u64 ctime = get_ctime_nanosec_from_file(file);

    args_t args = {};
    args.args[0] = (unsigned long) file;
    args.args[1] = ctime;
    save_args(&args, FILE_MODIFICATION);

    return 0;
}

statfunc int common_file_modification_ret(struct pt_regs *ctx)
{
    args_t saved_args;
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    if (!should_submit(FILE_MODIFICATION, p.event))
        return 0;

    struct file *file = (struct file *) saved_args.args[0];
    u64 old_ctime = saved_args.args[1];

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {
        p.task_info->context.host_pid, file_info.id.device, file_info.id.inode};

    int *op = bpf_map_lookup_elem(&file_modification_map, &file_mod_key);
    if (op == NULL || *op == FILE_MODIFICATION_SUBMIT) {
        // we should submit the event once and mark as done.
        int op = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);
    } else {
        // no need to submit. return.
        return 0;
    }

    save_str_to_buf(&p.event->args_buf, file_info.pathname_p, 0);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.device, sizeof(dev_t), 1);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.inode, sizeof(unsigned long), 2);
    save_to_submit_buf(&p.event->args_buf, &old_ctime, sizeof(u64), 3);
    save_to_submit_buf(&p.event->args_buf, &file_info.id.ctime, sizeof(u64), 4);

    events_ringbuf_submit(&p, FILE_MODIFICATION, 0);

    return 0;
}

SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time)
{
    return common_file_modification_ent(ctx);
}

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_ret_file_update_time)
{
    return common_file_modification_ret(ctx);
}

SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified)
{
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }

    return 0;
}

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_ret_file_modified)
{
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ret(ctx);
    }

    return 0;
}

// Network Packets

//
// Support functions for network code
//

statfunc u64 sizeof_net_event_context_t(void)
{
    return sizeof(net_event_context_t) - sizeof(net_event_contextmd_t);
}

statfunc void set_net_task_context(program_data_t *p, net_task_context_t *netctx)
{
    __builtin_memset(&netctx->taskctx, 0, sizeof(task_context_t));
    __builtin_memcpy(&netctx->taskctx, &p->event->context.task, sizeof(task_context_t));

    // Normally this will be set filled inside events_ringbuf_submit but for some events like
    // set_socket_state we want to prefill full network context.
    init_task_context(&netctx->taskctx, p->task);
}

statfunc enum event_id_e net_packet_to_net_event(net_packet_t packet_type)
{
    switch (packet_type) {
        // Packets
        case SUB_NET_PACKET_IP:
            return NET_PACKET_IP;
        case SUB_NET_PACKET_TCP:
            return NET_PACKET_TCP;
        case SUB_NET_PACKET_UDP:
            return NET_PACKET_UDP;
        case SUB_NET_PACKET_ICMP:
            return NET_PACKET_ICMP;
        case SUB_NET_PACKET_ICMPV6:
            return NET_PACKET_ICMPV6;
        case SUB_NET_PACKET_DNS:
            return NET_PACKET_DNS;
        case SUB_NET_PACKET_SOCKS5:
            return NET_PACKET_SOCKS5;
        case SUB_NET_PACKET_SSH:
            return NET_PACKET_SSH;
    };
    return MAX_EVENT_ID;
}

// The address of &neteventctx->eventctx will be aligned as eventctx is the
// first member of that packed struct. This is a false positive as we do need
// the neteventctx struct to be all packed.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"

// Return if a network event should to be sumitted.
statfunc bool should_submit_net_event(event_context_t *neteventctx, net_packet_t packet_type)
{
    enum event_id_e evt_id = net_packet_to_net_event(packet_type);

    event_config_t *evt_config = bpf_map_lookup_elem(&events_map, &evt_id);
    if (evt_config == NULL)
        return false;

    return true;
}

#pragma clang diagnostic pop // -Waddress-of-packed-member


//
// Protocol parsing functions
//

#define CGROUP_SKB_HANDLE_FUNCTION(name)                                                           \
    statfunc u32 cgroup_skb_handle_##name(struct __sk_buff *ctx,                                   \
                                          net_event_contextmd_t md,                                \
                                          event_context_t *neteventctx,                            \
                                          nethdrs *nethdrs,                                        \
                                          enum flow_direction flow_direction)

CGROUP_SKB_HANDLE_FUNCTION(family);
CGROUP_SKB_HANDLE_FUNCTION(proto);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_socks5);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_ssh);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns);

#define CGROUP_SKB_HANDLE(name) cgroup_skb_handle_##name(ctx, md, neteventctx, nethdrs, flow_direction);

//
// Network submission functions
//

// Submit a network event (packet, capture, flow) to userland.
statfunc u32 cgroup_skb_submit(void *map, struct __sk_buff *ctx, net_event_contextmd_t md, event_context_t *neteventctx, u32 event_type, u32 size)
{
    size = size > FULL ? FULL : size;
    switch (size) {
        case HEADERS: // submit only headers
            size = md.header_size;
            break;
        case FULL: // submit full packet
            size = ctx->len;
            break;
        default: // submit size bytes
            size += md.header_size;
            size = size > ctx->len ? ctx->len : size;
            break;
    }

    if (size > MAX_SKB_PAYLOAD_SIZE) {
        return 1;
    }

    net_event_context_t *e = bpf_ringbuf_reserve(map, sizeof(net_event_context_t), 0);
    if (!e) {
        return 1;
    }
    __builtin_memcpy(&e->eventctx, neteventctx, sizeof(event_context_t));

    u32 read_len = size;

    // Make the verifier happy to ensure we are not reading less than 1 byte and not more than max skb payload size.
    asm goto("if %[size] < 1 goto %l[out]" ::[size] "r"(read_len)::out);
    asm goto("if %[size] > %[max] goto %l[out]"
                :
                :[size] "r"(read_len)
                ,[max] "i"(MAX_SKB_PAYLOAD_SIZE)::out);

    if (bpf_skb_load_bytes(ctx, 0, &e->payload, read_len)) {
        goto out;
    }

    e->argnum = 1;
    e->index0 = 0;
    e->bytes = size;
    e->eventctx.eventid = event_type;

    bpf_ringbuf_submit(e, 0);
    return 0;

out:
    bpf_ringbuf_discard(e, 0);
    metrics_increase(SKB_EVENTS_RINGBUF_DISCARD);
    return 0;
}

// Submit a network event.
#define cgroup_skb_submit_event(a, b, c, d, e) cgroup_skb_submit(&skb_events, a, b, c, d, e)

// Check if a flag is set in the retval.
#define retval_hasflag(flag) (neteventctx->eventctx.retval & flag) == flag

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx)
{
    u32 family = ctx->family;
    switch (family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // not supported
    }

    u32 protocol = ctx->protocol;
    switch (protocol) {
        case IPPROTO_IP:
        case IPPROTO_IPV6:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            break;
        default:
            return 1; // not supported
    }

    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 1;
    }

    if (!should_trace(&p)) {
        return 1;
    }

    net_task_context_t netctx = {0};
    set_net_task_context(&p, &netctx);

    // Populate socket map with network task context.
    bpf_sk_storage_get(&net_taskctx_map, ctx, &netctx, BPF_LOCAL_STORAGE_GET_F_CREATE);

    return 1;
}

// This iterates over all open files of all processes, filter per socket and updates the
// netcontext map accordingly.
SEC("iter/task_file")
int socket_task_file_iter(struct bpf_iter__task_file *ctx)
{
    struct file *file = ctx->file;
    struct task_struct *task = ctx->task;

    if (!file || !task)
        return 0;

    // // We only care about sockets.
    if ((u64) file->f_op != global_config.socket_file_ops_addr) {
        return 0;
    }
    net_task_context_t netctx = {0};
    init_task_context(&netctx.taskctx, task);
    netctx.taskctx.host_pid = task->pid;
    netctx.taskctx.host_tid = task->tgid;

    if (global_config.cgroup_v1) {
        netctx.taskctx.cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        netctx.taskctx.cgroup_id = get_default_cgroup_id(task);
    }

    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        struct socket *socket = (struct socket *) file->private_data;
        if (!socket) {
            return 0;
        }
        struct sock *sock = BPF_CORE_READ(socket, sk);
        if (!sock) {
            return 0;
        }

        bpf_map_update_elem(&existing_sockets_map, &sock, &netctx, BPF_ANY);
    } else {
        struct socket *sock = bpf_sock_from_file(file);
        if (sock) {
            bpf_sk_storage_get(&net_taskctx_map, sock->sk, &netctx, BPF_LOCAL_STORAGE_GET_F_CREATE);
        }
    }

    return 0;
}

//
// SKB eBPF programs
//
statfunc u32 cgroup_skb_generic(struct __sk_buff *ctx, enum flow_direction flow_direction)
{
    switch (ctx->family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // PF_INET and PF_INET6 only
    }

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

    net_task_context_t *netctx =
        bpf_sk_storage_get(&net_taskctx_map, sk, 0, 0); // obtain event context
    if (!netctx) {
        net_task_context_t *existing_netctx = NULL;

        // For older kernels, also check the existing socket map.
        if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
            struct sk_buff *buf = (void *) ctx;
            struct sock *key = BPF_CORE_READ(buf, sk);

            existing_netctx = bpf_map_lookup_elem(&existing_sockets_map, &key);
            // There are certain types of sockets that we do not detect and would still be missing,
            // such as for the IGMP. This only applies to cgroup v1 though, as for cgroup v2, we
            // can still attribute traffic to at least a container via the cgroup id.
            if (!existing_netctx && global_config.cgroup_v1) {
                return 1;
            }
        } else {
            // There is no fallback for cgroup v1 as we cannot figure out the cgroup id for the
            // originating process.
            if (global_config.cgroup_v1) {
                return 1;
            }
        }

        // For cgroup v2, if there was no existing task context found, we fallback to just the
        // cgroup id which we should be able to attribute to a container in userspace.
        //
        // NOTE: this will not work for nested cgroups, but it is an accepted limitation for now.
        if (!existing_netctx) {
            net_task_context_t cgroup_context = {0};
            cgroup_context.taskctx.cgroup_id = bpf_sk_cgroup_id(sk);
            existing_netctx = &cgroup_context;
        }

        netctx = bpf_sk_storage_get(&net_taskctx_map, sk, existing_netctx, BPF_SK_STORAGE_GET_F_CREATE);
        if (!netctx) {
            // This should never happen, but if it does there is nothing we can do.
            return 1;
        }
    }

    // Skip if cgroup is muted.
    u64 cgroup_id = netctx->taskctx.cgroup_id;
    if (bpf_map_lookup_elem(&ignored_cgroups_map, &cgroup_id)) {
        return 1;
    }

    event_context_t neteventctx_val = {0};
    event_context_t *neteventctx = &neteventctx_val;

    __builtin_memcpy(&neteventctx->task, &netctx->taskctx, sizeof(task_context_t));
    neteventctx->ts = bpf_ktime_get_ns();
    neteventctx->eventid = NET_PACKET_IP; // will be changed in skb program
    neteventctx->processor_id = (u16) bpf_get_smp_processor_id();
    neteventctx->syscall = NO_SYSCALL; // ingress has no orig syscall
    neteventctx->retval = flow_direction == INGRESS ? packet_ingress : packet_egress;

    net_event_contextmd_t md = {0};
    md.header_size = 0;

    nethdrs hdrs = {0}, *nethdrs = &hdrs;
    u32 ret = CGROUP_SKB_HANDLE(proto);
    return ret; // Based on ret value we can block packets here. ret=1 (ok), ret=0 (block).
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, INGRESS);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, EGRESS);
}

//
// Network Protocol Events Logic
//

//
// SUPPORTED L3 NETWORK PROTOCOLS (ip, ipv6) HANDLERS
//
CGROUP_SKB_HANDLE_FUNCTION(proto)
{
    void *dest = NULL;
    u32 size = 0;
    u32 prev_hdr_size = 0;
    u32 family = ctx->family;
    u32 ihl = 0;
    u8 next_proto = 0;
    switch (family) {
        case PF_INET:
            dest = &nethdrs->iphdrs.iphdr;
            size = get_type_size(struct iphdr);

            // Load L3 header.
            if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET))
                return 1;

            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            ihl = nethdrs->iphdrs.iphdr.ihl;
            if (ihl > 5) { // re-read IPv4 header if needed
                size -= get_type_size(struct iphdr);
                size += ihl * 4;
                if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET)) {
                    return 1;
                }
            }
            md.header_size += size;

            prev_hdr_size = size;
            next_proto = nethdrs->iphdrs.iphdr.protocol;
            switch (next_proto) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                default:
                    size = 0;
                    break;
            }

            // Load next proto header.
            if (size > 0) {
                if (bpf_skb_load_bytes_relative(ctx, prev_hdr_size, dest, size, BPF_HDR_START_NET))
                    return 1;
            }

            md.header_size += size;
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = get_type_size(struct ipv6hdr);

            // Load L3 header.
            if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET))
                return 1;

            md.header_size += size;

            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism
            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            prev_hdr_size = size;
            next_proto = nethdrs->iphdrs.ipv6hdr.nexthdr;
            switch (next_proto) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = get_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = get_type_size(struct udphdr);
                    break;
                default:
                    size = 0;
                    break;
            }

            // Load next proto header.
            if (size > 0) {
                if (bpf_skb_load_bytes_relative(ctx, prev_hdr_size, dest, size, BPF_HDR_START_NET))
                    return 1;
            }

            md.header_size += size;
            break;
        default:
            return 1;
    }

    if (should_submit_event(NET_FLOW_BASE)) {
        record_netflow(ctx, &neteventctx->task, nethdrs, flow_direction);
    }

    // size == 0 means protocol we do not have any specific handling logic for. We still want
    // to record a netflow though.
    if (size == 0) {
        return 1;
    }

    // fastpath: submit the IP base event
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_IP, HEADERS);

    // Call the next protocol handler.
    switch (next_proto) {
        case IPPROTO_TCP:
            return CGROUP_SKB_HANDLE(proto_tcp);
        case IPPROTO_UDP:
            return CGROUP_SKB_HANDLE(proto_udp);
        default:
            return 1; // verifier needs
    }

    return 1;
}

//
// GUESS L7 NETWORK PROTOCOLS (http, dns, etc)
//

#define SOCKS5_VERSION(buf)     buf[0]
#define SOCKS5_NUM_METHODS(buf) buf[1]
#define SOCKS5_CMD(buf)         buf[1]
#define SOCKS5_RESERVED(buf)    buf[2]
#define SOCKS5_ADDR_TYPE(buf)   buf[3]

// see https://datatracker.ietf.org/doc/html/rfc1928 for the definition of the socks5 protocol
statfunc bool net_l7_is_socks5(struct __sk_buff *skb, u32 l7_off)
{
    // we treat all messages from the default socks ports as potential sock messages and try to
    // parse them in userspace.
    if (skb->remote_port == TCP_PORT_SOCKS5) {
        return true;
    }

    if (skb->local_port == TCP_PORT_SOCKS5) {
        return true;
    }

    char buf[socks5_min_len];
    __builtin_memset(&buf, 0, sizeof(buf));

    if (skb->len < l7_off) {
        return false;
    }

    u32 payload_len = skb->len - l7_off;
    u32 read_len = payload_len;
    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(read_len), [max_size] "i"(socks5_min_len));

    // make the verifier happy to ensure that we read more than a single byte
    // the test is for 2, since we anyway exect at least 2 bytes to check for socks5
    asm goto("if %[size] < 2 goto %l[out]" ::[size] "r"(read_len)::out);

    if (read_len < 2) {
        return false;
    }

    // load first socks5_min_len bytes from layer 7 in packet.
    if (bpf_skb_load_bytes(skb, l7_off, buf, read_len) < 0) {
        return false; // failed loading data into http_min_str - return.
    }

    if (SOCKS5_VERSION(buf) != 5) {
        return false; // all socks5 messages begin with the version (which is 5 for socks5)
    }

    // this might be a bit of a leap of faith here, since the first server response only selects the
    // method used for auth. This requires more massaging in userspace.
    if (payload_len == 2) {
        return true;
    }

    // the client starts by sending a message containing the number of methods for auth in the
    // second byte. Each of these methods are then listed in the following bytes, meaning that
    // if our message is the length of the number of messages + 2 (since starting after the second
    // byte), we should have ourselfs a client request.
    if (payload_len == (u32) SOCKS5_NUM_METHODS(buf) + 2) {
        return true;
    }

    // we now access fields above the two
    if (read_len < socks5_min_len) {
        return false;
    }

    // both request and response have the 3rd byte reserved and it needs to be set to 0x00
    if (SOCKS5_RESERVED(buf) != 0x00) {
        return false;
    }

    if (SOCKS5_ADDR_TYPE(buf) == 0x01       // IPv4 address
        || SOCKS5_ADDR_TYPE(buf) == 0x03    // domain name
        || SOCKS5_ADDR_TYPE(buf) == 0x04) { // IPv6 address
        return true;
    }

out:
    return false;
}

// see https://datatracker.ietf.org/doc/html/rfc4253 for the definition of the ssh protocol
statfunc bool net_l7_is_ssh(struct __sk_buff *skb, u32 l7_off)
{
    char buf[ssh_min_len];
    __builtin_memset(&buf, 0, sizeof(buf));

    if (skb->len < l7_off) {
        return false;
    }

    u32 payload_len = skb->len - l7_off;
    u32 read_len = payload_len;
    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(read_len), [max_size] "i"(ssh_min_len));

    // make the verifier happy to ensure that we read more than a single byte
    asm goto("if %[size] < %[min_ssh] goto %l[out]"
             :
             : [size] "r"(read_len), [min_ssh] "i"(ssh_min_len)::out);

    if (read_len < ssh_min_len) {
        return false;
    }

    // load first ssh_min_len bytes from layer 7 in packet.
    if (bpf_skb_load_bytes(skb, l7_off, buf, read_len) < 0) {
        return false; // failed loading data into http_min_str - return.
    }

    // the rfc mentions that a server could also send other data before the ssh version, meaning
    // this check will not work 100% of the time, but it should be good enough to catch most ssh
    // servers.
    if (has_prefix("SSH-", buf, 5)) {
        return true;
    }

out:
    return false;
}

//
// SUPPORTED L4 NETWORK PROTOCOL (tcp, udp, icmp) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp)
{
    // check flag for dynamic header size (TCP: data offset flag)

    if (nethdrs->protohdrs.tcphdr.doff > 5) { // offset flag set
        u32 doff = nethdrs->protohdrs.tcphdr.doff * (32 / 8);
        md.header_size -= get_type_size(struct tcphdr);
        md.header_size += doff;
    }

    // Pick src/dst ports.
    u16 srcport = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
    u16 dstport = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);

    // Submit TCP base event if needed (only headers)

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_TCP, HEADERS);

    bool submit_dns = should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS);
    bool submit_socks5 = should_submit_net_event(neteventctx, SUB_NET_PACKET_SOCKS5);
    bool submit_ssh = should_submit_net_event(neteventctx, SUB_NET_PACKET_SSH);

    // Fastpath: return if no other L7 network events.
    if (!submit_dns && !submit_socks5 && !submit_ssh)
        goto done;

    // Guess layer 7 protocols by src/dst ports ...
    u16 lower_port = srcport < dstport ? srcport : dstport;

    switch (lower_port) {
        case TCP_PORT_DNS:
            if (submit_dns)
                return CGROUP_SKB_HANDLE(proto_tcp_dns);
        case TCP_PORT_SOCKS5:
            if (submit_socks5)
                return CGROUP_SKB_HANDLE(proto_tcp_socks5);
    }

    // We already probed for SSH traffic before, if the port was related to SSH. No need to probe
    // again.
    if (submit_ssh) {
        int ssh_proto = net_l7_is_ssh(ctx, md.header_size);
        if (ssh_proto) {
            return CGROUP_SKB_HANDLE(proto_tcp_ssh);
        }
    }

    // ... and by analyzing payload.
    if (submit_socks5) {
        int socks5_proto = net_l7_is_socks5(ctx, md.header_size);
        if (socks5_proto) {
            return CGROUP_SKB_HANDLE(proto_tcp_socks5);
        }
    }
    // ... continue with net_l7_is_protocol_xxx

done:
    return 1; // NOTE: might block TCP here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp)
{
    // Submit UDP base event if needed (only headers).

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_UDP, HEADERS);

    // Fastpath: return if no other L7 network events.

    if (!should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        goto done;

    // Guess layer 7 protocols ...

    u16 source = bpf_ntohs(nethdrs->protohdrs.udphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.udphdr.dest);

    // ... by src/dst ports

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:
            return CGROUP_SKB_HANDLE(proto_udp_dns);
    }

    // ... by analyzing payload
    // ...

    // ... continue with net_l7_is_protocol_xxx

done:
    return 1; // NOTE: might block UDP here if needed (return 0)
}

//
// SUPPORTED L7 NETWORK PROTOCOL (dns) HANDLERS
//

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_DNS, FULL);

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns)
{
    // submit DNS base event if needed (full packet)
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_DNS, FULL);

    return 1; // NOTE: might block DNS here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_socks5)
{
    u32 payload_len = ctx->len - md.header_size;

    // submit SOCKS5 base event if needed (full packet)
    // we only care about packets that have a payload though
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_SOCKS5) && payload_len > 0) {
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_SOCKS5, FULL);
    }

    return 1; // NOTE: might block SOCKS5 here if needed (return 0)
}

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_ssh)
{
    // TODO(patrick.pichler): this needs better handling, as i do not want to have this a network
    // base event
    u32 payload_len = ctx->len - md.header_size;

    // submit SSH base event if needed (full packet)
    // we only care about packets that have a payload though
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_SSH) && payload_len > 0) {
        cgroup_skb_submit_event(ctx, md, neteventctx, NET_PACKET_SSH, FULL);
    }

    return 1; // NOTE: might block SSH here if needed (return 0)
}

// That will allow to subscribe only to wanted events and make handing easier.
statfunc bool should_trace_sock_set_state(int old_state, int new_state)
{
    // Listen.
    if (old_state == TCP_CLOSE && new_state == TCP_LISTEN) {
        return true;
    }
    // Connect.
    if (old_state == TCP_SYN_SENT && new_state == TCP_ESTABLISHED) {
        return true;
    }
    // Connect error.
    if (old_state == TCP_SYN_SENT && new_state == TCP_CLOSE) {
        return true;
    }
    return false;
}

statfunc int bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops) {
	if (skops == NULL || !(skops->family == AF_INET || skops->family == AF_INET6))
		return 0;

	bpf_sock_ops_cb_flags_set(skops,  BPF_SOCK_OPS_STATE_CB_FLAG);
	return 0;
}

statfunc int handle_sock_state_change(struct bpf_sock_ops *skops, int old_state, int new_state) {
    // TODO(patrick.pichler): add logic for handling listening sockets
    if (!should_trace_sock_set_state(old_state, new_state)) {
        return 0;
    }

    struct bpf_sock *sk = skops->sk;
    if (!sk) {
        return 0;
    }

    struct net_task_context *netctx = bpf_sk_storage_get(&net_taskctx_map, sk, 0, 0);
    if (!netctx) {
        return 0;
    }

    event_data_t *e = find_next_free_scratch_buf(&net_heap_sock_state_event);
    // All scratch buffers are in use, there is nothing we can do.
    if (unlikely(e == NULL)) {
        metrics_increase(NO_FREE_SCRATCH_BUFFER_SOCKET_SET_STATE);
        return 0;
    }

    program_data_t p = {};
    p.scratch_idx = 1;
    p.ctx = skops;
    p.event = e;
    p.event->args_buf.offset = 0;
    p.event->args_buf.argnum = 0;
    p.event->context.ts = bpf_ktime_get_ns();;
    p.event->context.eventid = SOCK_SET_STATE;

    // Copy task context from correct user space thread.
    __builtin_memcpy(&p.event->context.task, &netctx->taskctx, sizeof(task_context_t));

    if (!should_trace(&p)) {
        goto cleanup;
    }

    tuple_t tuple = {};
    fill_tuple_from_bpf_sock(sk, &tuple);

    save_to_submit_buf(&p.event->args_buf, (void *) &old_state, sizeof(u32), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &new_state, sizeof(u32), 1);
    save_to_submit_buf(&p.event->args_buf, &tuple, sizeof(tuple), 2);

    do_ringbuf_submit(&events, &p, SOCK_SET_STATE, 0, false, EVENTS_RINGBUF_DISCARD);

cleanup:
    free_scratch_buf(e);
    return 0;
}

SEC("sockops")
int cgroup_sockops(struct bpf_sock_ops *skops) {
	u32 op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	    return bpf_sock_ops_establish_cb(skops);
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
        {
            // For listen we should handle the callback directly because it's
            // the first state will not work with bpf_sock_ops_cb_flags_set.
            return handle_sock_state_change(skops, TCP_CLOSE, TCP_LISTEN);
        }
	case BPF_SOCK_OPS_STATE_CB:
        {
            int old_state = skops->args[0];
            int new_state = skops->args[1];
            return handle_sock_state_change(skops, old_state, new_state);
        }
	}

	return 0;
}

SEC("raw_tracepoint/oom/mark_victim")
int oom_mark_victim(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 pid = ctx->args[0];

    u8 one = 1;
    bpf_map_update_elem(&oom_info, &pid, &one, BPF_ANY);

    return 0;
}

SEC("kprobe/tty_open")
int BPF_KPROBE(tty_open, struct inode *inode, struct file *filep)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    if (!should_trace((&p))) {
        return 0;
    }

    if (should_submit(TTY_WRITE, p.event)) {
        unsigned long ino = BPF_CORE_READ(inode, i_ino);
        u8 one = 1;
        bpf_map_update_elem(&tty_opened_files, &ino, &one, BPF_ANY);
    }

    if (should_submit(TTY_OPEN, p.event)) {
        void *file_path = get_path_str(__builtin_preserve_access_index(&filep->f_path));
        unsigned long ino = BPF_CORE_READ(inode, i_ino);
        dev_t dev = BPF_CORE_READ(inode, i_rdev);
        umode_t inode_mode = get_inode_mode_from_file(filep);

        save_str_to_buf(&p.event->args_buf, file_path, 0);
        save_to_submit_buf(&p.event->args_buf, &ino, sizeof(ino), 1);
        save_to_submit_buf(&p.event->args_buf, &inode_mode, sizeof(inode_mode), 2);
        save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev), 3);
        events_ringbuf_submit(&p, TTY_OPEN, 0);
    }

    return 0;
}

SEC("kprobe/tty_write")
int BPF_KPROBE(tty_write, struct kiocb *iocb, struct iov_iter *from)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    if (!should_trace((&p))) {
        return 0;
    }

    if (should_submit(TTY_WRITE, p.event)) {
        struct file *file = (struct file *) BPF_CORE_READ(iocb, ki_filp);
        u64 inode = get_inode_nr_from_file(file);
        if (!bpf_map_lookup_elem(&tty_opened_files, &inode)) {
            return 0;
        }
        bpf_map_delete_elem(&tty_opened_files, &inode);

        file_info_t file_info;
        file_info.pathname_p = get_path_str_cached(file);
        save_str_to_buf(&p.event->args_buf, file_info.pathname_p, 0);
        save_to_submit_buf(&p.event->args_buf, &inode, sizeof(u64), 1);

        return events_ringbuf_submit(&p, TTY_WRITE, 0);
    }

    return 0;
}
