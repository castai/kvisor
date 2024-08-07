#ifndef __COMMON_PID_TRANSLATION_H__
#define __COMMON_PID_TRANSLATION_H__

#define PID_NESTED_NAMESPACES_MAX 10

#include <vmlinux.h>
#include <common/common.h>

static __always_inline void get_pid_in_ns(uint64_t ns_pid_ino, uint32_t *pid) {
    unsigned int inum;

    // fallback to host pid, if no inode provided
    if (ns_pid_ino == 0) {
        uint64_t pid_tgid = bpf_get_current_pid_tgid();
        *pid = (u32)(pid_tgid >> 32);
        return;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // retrieve level nested namespaces
    unsigned int level = BPF_CORE_READ(task, group_leader, nsproxy, pid_ns_for_children, level);

    // match the level with pid ns inode
#pragma unroll
    for (int i = 0; i < PID_NESTED_NAMESPACES_MAX; i++) {
        if ((level - i) < 0) {
            break;
        }
        inum = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level - i].ns, ns.inum);
        if (inum == ns_pid_ino) {
            *pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level - i].nr);
            break;
        }
    }
}
#endif
