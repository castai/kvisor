#ifndef __COMMON_ARCH_H__
#define __COMMON_ARCH_H__

#include <vmlinux.h>

#include <bpf/bpf_tracing.h>

#include <common/common.h>

// PROTOTYPES

statfunc bool is_x86_compat(struct task_struct *);
statfunc bool is_arm64_compat(struct task_struct *);
statfunc bool is_compat(struct task_struct *);
statfunc int get_syscall_id_from_regs(struct pt_regs *);
statfunc struct pt_regs *get_task_pt_regs(struct task_struct *);

// FUNCTIONS

statfunc bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return BPF_CORE_READ(task, thread_info.status) & TS_COMPAT;
#else
    return false;
#endif
}

statfunc bool is_arm64_compat(struct task_struct *task)
{
#if defined(bpf_target_arm64)
    return BPF_CORE_READ(task, thread_info.flags) & _TIF_32BIT;
#else
    return false;
#endif
}

statfunc bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}

statfunc int get_syscall_id_from_regs(struct pt_regs *regs)
{
#if defined(bpf_target_x86)
    int id = BPF_CORE_READ(regs, orig_ax);
#elif defined(bpf_target_arm64)
    int id = BPF_CORE_READ(regs, syscallno);
#endif
    return id;
}

statfunc struct pt_regs *get_task_pt_regs(struct task_struct *task)
{
// THREAD_SIZE here is statistically defined and assumed to work for 4k page sizes.
#if defined(bpf_target_x86)
    void *__ptr = BPF_CORE_READ(task, stack) + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    return ((struct pt_regs *) __ptr) - 1;
#elif defined(bpf_target_arm64)
    return ((struct pt_regs *) (THREAD_SIZE + BPF_CORE_READ(task, stack)) - 1);
#endif
}

#define UNDEFINED_SYSCALL 1000
#define NO_SYSCALL        -1

#if defined(bpf_target_x86)
    #define SYSCALL_READ                   0
    #define SYSCALL_WRITE                  1
    #define SYSCALL_OPEN                   2
    #define SYSCALL_CLOSE                  3
    #define SYSCALL_FSTAT                  5
    #define SYSCALL_LSEEK                  8
    #define SYSCALL_MMAP                   9
    #define SYSCALL_MPROTECT               10
    #define SYSCALL_RT_SIGRETURN           15
    #define SYSCALL_IOCTL                  16
    #define SYSCALL_PREAD64                17
    #define SYSCALL_PWRITE64               18
    #define SYSCALL_READV                  19
    #define SYSCALL_WRITEV                 20
    #define SYSCALL_DUP                    32
    #define SYSCALL_DUP2                   33
    #define SYSCALL_SOCKET                 41
    #define SYSCALL_CONNECT                42
    #define SYSCALL_ACCEPT                 43
    #define SYSCALL_SENDTO                 44
    #define SYSCALL_RECVFROM               45
    #define SYSCALL_SENDMSG                46
    #define SYSCALL_RECVMSG                47
    #define SYSCALL_SHUTDOWN               48
    #define SYSCALL_BIND                   49
    #define SYSCALL_LISTEN                 50
    #define SYSCALL_GETSOCKNAME            51
    #define SYSCALL_GETPEERNAME            52
    #define SYSCALL_SETSOCKOPT             54
    #define SYSCALL_GETSOCKOPT             55
    #define SYSCALL_EXECVE                 59
    #define SYSCALL_EXIT                   60
    #define SYSCALL_FCNTL                  72
    #define SYSCALL_FLOCK                  73
    #define SYSCALL_FSYNC                  74
    #define SYSCALL_FDATASYNC              75
    #define SYSCALL_FTRUNCATE              77
    #define SYSCALL_GETDENTS               78
    #define SYSCALL_FCHDIR                 81
    #define SYSCALL_FCHMOD                 91
    #define SYSCALL_FCHOWN                 93
    #define SYSCALL_FSTATFS                138
    #define SYSCALL_READAHEAD              187
    #define SYSCALL_FSETXATTR              190
    #define SYSCALL_FGETXATTR              193
    #define SYSCALL_FLISTXATTR             196
    #define SYSCALL_FREMOVEXATTR           199
    #define SYSCALL_GETDENTS64             217
    #define SYSCALL_FADVISE64              221
    #define SYSCALL_EXIT_GROUP             231
    #define SYSCALL_EPOLL_WAIT             232
    #define SYSCALL_EPOLL_CTL              233
    #define SYSCALL_INOTIFY_ADD_WATCH      254
    #define SYSCALL_INOTIFY_RM_WATCH       255
    #define SYSCALL_OPENAT                 257
    #define SYSCALL_MKDIRAT                258
    #define SYSCALL_MKNODAT                259
    #define SYSCALL_FCHOWNAT               260
    #define SYSCALL_FUTIMESAT              261
    #define SYSCALL_NEWFSTATAT             262
    #define SYSCALL_UNLINKAT               263
    #define SYSCALL_SYMLINKAT              266
    #define SYSCALL_READLINKAT             267
    #define SYSCALL_FCHMODAT               268
    #define SYSCALL_FACCESSAT              269
    #define SYSCALL_SYNC_FILE_RANGE        277
    #define SYSCALL_VMSPLICE               278
    #define SYSCALL_UTIMENSAT              280
    #define SYSCALL_EPOLL_PWAIT            281
    #define SYSCALL_SIGNALFD               282
    #define SYSCALL_FALLOCATE              285
    #define SYSCALL_TIMERFD_SETTIME        286
    #define SYSCALL_TIMERFD_GETTIME        287
    #define SYSCALL_ACCEPT4                288
    #define SYSCALL_SIGNALFD4              289
    #define SYSCALL_DUP3                   292
    #define SYSCALL_PREADV                 295
    #define SYSCALL_PWRITEV                296
    #define SYSCALL_PERF_EVENT_OPEN        298
    #define SYSCALL_RECVMMSG               299
    #define SYSCALL_NAME_TO_HANDLE_AT      303
    #define SYSCALL_OPEN_BY_HANDLE_AT      304
    #define SYSCALL_SYNCFS                 306
    #define SYSCALL_SENDMMSG               307
    #define SYSCALL_SETNS                  308
    #define SYSCALL_FINIT_MODULE           313
    #define SYSCALL_EXECVEAT               322
    #define SYSCALL_PREADV2                327
    #define SYSCALL_PWRITEV2               328
    #define SYSCALL_PKEY_MPROTECT          329
    #define SYSCALL_STATX                  332
    #define SYSCALL_PIDFD_SEND_SIGNAL      424
    #define SYSCALL_IO_URING_ENTER         426
    #define SYSCALL_IO_URING_REGISTER      427
    #define SYSCALL_OPEN_TREE              428
    #define SYSCALL_FSCONFIG               431
    #define SYSCALL_FSMOUNT                432
    #define SYSCALL_FSPICK                 433
    #define SYSCALL_OPENAT2                437
    #define SYSCALL_FACCESSAT2             439
    #define SYSCALL_PROCESS_MADVISE        440
    #define SYSCALL_EPOLL_PWAIT2           441
    #define SYSCALL_MOUNT_SETATTR          442
    #define SYSCALL_QUOTACTL_FD            443
    #define SYSCALL_LANDLOCK_ADD_RULE      445
    #define SYSCALL_LANDLOCK_RESTRICT_SELF 446
    #define SYSCALL_PROCESS_MRELEASE       448
    #define SYSCALL_SOCKETCALL             473

#elif defined(bpf_target_arm64)
    #define SYSCALL_READ                   63
    #define SYSCALL_WRITE                  64
    #define SYSCALL_OPEN                   UNDEFINED_SYSCALL
    #define SYSCALL_CLOSE                  57
    #define SYSCALL_FSTAT                  80
    #define SYSCALL_LSEEK                  62
    #define SYSCALL_MMAP                   222
    #define SYSCALL_MPROTECT               226
    #define SYSCALL_RT_SIGRETURN           139
    #define SYSCALL_IOCTL                  29
    #define SYSCALL_PREAD64                67
    #define SYSCALL_PWRITE64               68
    #define SYSCALL_READV                  65
    #define SYSCALL_WRITEV                 66
    #define SYSCALL_DUP                    23
    #define SYSCALL_DUP2                   UNDEFINED_SYSCALL
    #define SYSCALL_SOCKET                 198
    #define SYSCALL_CONNECT                203
    #define SYSCALL_ACCEPT                 202
    #define SYSCALL_SENDTO                 206
    #define SYSCALL_RECVFROM               207
    #define SYSCALL_SENDMSG                211
    #define SYSCALL_RECVMSG                212
    #define SYSCALL_SHUTDOWN               210
    #define SYSCALL_BIND                   200
    #define SYSCALL_LISTEN                 201
    #define SYSCALL_GETSOCKNAME            204
    #define SYSCALL_GETPEERNAME            205
    #define SYSCALL_SETSOCKOPT             208
    #define SYSCALL_GETSOCKOPT             209
    #define SYSCALL_EXECVE                 221
    #define SYSCALL_EXIT                   93
    #define SYSCALL_FCNTL                  25
    #define SYSCALL_FLOCK                  32
    #define SYSCALL_FSYNC                  82
    #define SYSCALL_FDATASYNC              83
    #define SYSCALL_FTRUNCATE              46
    #define SYSCALL_GETDENTS               UNDEFINED_SYSCALL
    #define SYSCALL_FCHDIR                 50
    #define SYSCALL_FCHMOD                 52
    #define SYSCALL_FCHOWN                 55
    #define SYSCALL_FSTATFS                44
    #define SYSCALL_READAHEAD              213
    #define SYSCALL_FSETXATTR              7
    #define SYSCALL_FGETXATTR              10
    #define SYSCALL_FLISTXATTR             13
    #define SYSCALL_FREMOVEXATTR           16
    #define SYSCALL_GETDENTS64             61
    #define SYSCALL_FADVISE64              223
    #define SYSCALL_EXIT_GROUP             94
    #define SYSCALL_EPOLL_WAIT             UNDEFINED_SYSCALL
    #define SYSCALL_EPOLL_CTL              21
    #define SYSCALL_INOTIFY_ADD_WATCH      27
    #define SYSCALL_INOTIFY_RM_WATCH       28
    #define SYSCALL_OPENAT                 56
    #define SYSCALL_MKDIRAT                34
    #define SYSCALL_MKNODAT                33
    #define SYSCALL_FCHOWNAT               54
    #define SYSCALL_FUTIMESAT              UNDEFINED_SYSCALL
    #define SYSCALL_NEWFSTATAT             UNDEFINED_SYSCALL
    #define SYSCALL_UNLINKAT               35
    #define SYSCALL_SYMLINKAT              36
    #define SYSCALL_READLINKAT             78
    #define SYSCALL_FCHMODAT               53
    #define SYSCALL_FACCESSAT              48
    #define SYSCALL_SYNC_FILE_RANGE        84
    #define SYSCALL_VMSPLICE               75
    #define SYSCALL_UTIMENSAT              88
    #define SYSCALL_EPOLL_PWAIT            22
    #define SYSCALL_SIGNALFD               UNDEFINED_SYSCALL
    #define SYSCALL_FALLOCATE              47
    #define SYSCALL_TIMERFD_SETTIME        86
    #define SYSCALL_TIMERFD_GETTIME        87
    #define SYSCALL_ACCEPT4                242
    #define SYSCALL_SIGNALFD4              74
    #define SYSCALL_DUP3                   24
    #define SYSCALL_PREADV                 69
    #define SYSCALL_PWRITEV                70
    #define SYSCALL_PERF_EVENT_OPEN        241
    #define SYSCALL_RECVMMSG               243
    #define SYSCALL_NAME_TO_HANDLE_AT      264
    #define SYSCALL_OPEN_BY_HANDLE_AT      265
    #define SYSCALL_SYNCFS                 267
    #define SYSCALL_SENDMMSG               269
    #define SYSCALL_SETNS                  268
    #define SYSCALL_FINIT_MODULE           273
    #define SYSCALL_EXECVEAT               281
    #define SYSCALL_PREADV2                286
    #define SYSCALL_PWRITEV2               287
    #define SYSCALL_PKEY_MPROTECT          288
    #define SYSCALL_STATX                  291
    #define SYSCALL_PIDFD_SEND_SIGNAL      424
    #define SYSCALL_IO_URING_ENTER         426
    #define SYSCALL_IO_URING_REGISTER      427
    #define SYSCALL_OPEN_TREE              428
    #define SYSCALL_FSCONFIG               431
    #define SYSCALL_FSMOUNT                432
    #define SYSCALL_FSPICK                 433
    #define SYSCALL_OPENAT2                437
    #define SYSCALL_FACCESSAT2             439
    #define SYSCALL_PROCESS_MADVISE        440
    #define SYSCALL_EPOLL_PWAIT2           441
    #define SYSCALL_MOUNT_SETATTR          442
    #define SYSCALL_QUOTACTL_FD            443
    #define SYSCALL_LANDLOCK_ADD_RULE      445
    #define SYSCALL_LANDLOCK_RESTRICT_SELF 446
    #define SYSCALL_PROCESS_MRELEASE       448
    #define SYSCALL_SOCKETCALL             UNDEFINED_SYSCALL
#endif

#endif
