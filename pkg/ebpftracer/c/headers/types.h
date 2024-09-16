#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <common/consts.h>

#define PATH_MAX          4096
#define MAX_BIN_PATH_SIZE 256

typedef struct task_context {
    u64 start_time; // thread's start time
    u64 cgroup_id;
    u32 pid;           // PID as in the userspace term
    u32 tid;           // TID as in the userspace term
    u32 ppid;          // Parent PID as in the userspace term
    u32 host_pid;      // PID in host pid namespace
    u32 host_tid;      // TID in host pid namespace
    u32 host_ppid;     // Parent PID in host pid namespace
    u32 node_host_pid; // PID in same namespace as kubelet/container runtime is running
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    u64 leader_start_time; // task leader's monotonic start time
    u64 parent_start_time; // parent process task leader's monotonic start time
} task_context_t;

typedef struct event_context {
    u64 ts; // Timestamp
    task_context_t task;
    u32 eventid;
    s32 syscall; // The syscall which triggered the event
    s64 retval;
    u16 processor_id; // The ID of the processor which processed the event
} event_context_t;

enum event_id_e {
    // Net events IDs
    NET_PACKET_BASE = 700,
    NET_PACKET_IP,
    NET_PACKET_TCP,
    NET_PACKET_UDP,
    NET_PACKET_ICMP,
    NET_PACKET_ICMPV6,
    NET_PACKET_DNS,
    NET_PACKET_SOCKS5,
    NET_PACKET_SSH,
    NET_FLOW_BASE,
    MAX_NET_EVENT_ID,
    // Common event IDs
    RAW_SYS_ENTER,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    MAGIC_WRITE,
    CGROUP_MKDIR,
    CGROUP_RMDIR,
    SECURITY_BPRM_CHECK,
    SECURITY_SOCKET_CONNECT,
    SOCKET_DUP,
    LOAD_ELF_PHDRS,
    FILE_MODIFICATION,
    SOCK_SET_STATE,
    PROCESS_OOM_KILLED,
    TTY_OPEN,
    TTY_WRITE,
    STDIO_VIA_SOCKET,
    MAX_EVENT_ID,
};

typedef struct args {
    unsigned long args[6];
} args_t;

enum argument_type_e {
    NONE_T = 0UL,
    INT_T,
    UINT_T,
    LONG_T,
    ULONG_T,
    OFF_T_T,
    MODE_T_T,
    DEV_T_T,
    SIZE_T_T,
    POINTER_T,
    STR_T,
    STR_ARR_T,
    SOCKADDR_T,
    BYTES_T,
    U16_T,
    CRED_T,
    INT_ARR_2_T,
    UINT64_ARR_T,
    U8_T,
    TIMESPEC_T,
    TYPE_MAX = 255UL
};

enum internal_hook_e {
    EXEC_BINPRM = 80000,
};

typedef struct syscall_data {
    uint id;           // Current syscall id
    args_t args;       // Syscall arguments
    unsigned long ts;  // Timestamp of syscall entry
    unsigned long ret; // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;

#define MAX_CACHED_PATH_SIZE 64

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced; // indicates that syscall_data is valid
    u8 container_state;  // the state of the container the task resides in
} task_info_t;

typedef struct file_id {
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    file_id_t id;
} file_info_t;

typedef struct binary {
    u32 mnt_id;
    char path[MAX_BIN_PATH_SIZE];
} binary_t;

typedef struct io_data {
    void *ptr;
    unsigned long len;
    bool is_buf;
} io_data_t;

typedef struct proc_info {
    bool new_proc; // set if this process was started after tracee. Used with new_pid filter
    struct binary binary;
    u32 binary_no_mnt; // used in binary lookup when we don't care about mount ns. always 0.
    file_info_t interpreter;
} proc_info_t;

typedef struct bin_args {
    u8 type;
    u8 metadata[SEND_META_SIZE];
    char *ptr;
    loff_t start_off;
    unsigned int full_size;
    u8 iov_idx;
    u8 iov_len;
    struct iovec *vec;
} bin_args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct path_buf {
    u8 buf[PATH_MAX];
} path_buf_t;

typedef struct event_config {
    u64 param_types;
} event_config_t;

typedef struct args_buffer {
    u8 argnum;
    char args[ARGS_BUF_SIZE];
    u32 offset;
} args_buffer_t;

typedef struct event_data {
    event_context_t context;
    args_buffer_t args_buf;
    u64 param_types;
    u64 in_use;
} event_data_t;

#define MAX_EVENT_SIZE sizeof(event_context_t) + sizeof(u8) + ARGS_BUF_SIZE

#define BPF_MAX_LOG_FILE_LEN 72

enum bpf_log_level {
    BPF_LOG_LVL_DEBUG = -1,
    BPF_LOG_LVL_INFO,
    BPF_LOG_LVL_WARN,
    BPF_LOG_LVL_ERROR,
};

enum bpf_log_id {
    BPF_LOG_ID_UNSPEC = 0U, // enforce enum to u32

    // tracee functions
    BPF_LOG_ID_INIT_CONTEXT,

    // bpf helpers functions
    BPF_LOG_ID_MAP_LOOKUP_ELEM,
    BPF_LOG_ID_MAP_UPDATE_ELEM,
    BPF_LOG_ID_MAP_DELETE_ELEM,
    BPF_LOG_ID_GET_CURRENT_COMM,
    BPF_LOG_ID_TAIL_CALL,
    BPF_LOG_ID_MEM_READ,

    // hidden kernel module functions
    BPF_LOG_ID_HID_KER_MOD,
};

typedef struct bpf_log {
    s64 ret; // return value
    u32 cpu;
    u32 line;                        // line number
    char file[BPF_MAX_LOG_FILE_LEN]; // filename
} bpf_log_t;

typedef struct bpf_log_count {
    u32 count;
    u64 ts; // timestamp
} bpf_log_count_t;

typedef struct bpf_log_output {
    enum bpf_log_id id; // type
    enum bpf_log_level level;
    u32 count;
    u32 padding;
    struct bpf_log log;
} bpf_log_output_t;

typedef union scratch {
    bpf_log_output_t log_output;
    proc_info_t proc_info;
    task_info_t task_info;
} scratch_t;

typedef struct program_data {
    struct task_struct *task;
    task_info_t *task_info;
    proc_info_t *proc_info;
    event_data_t *event;
    u32 scratch_idx;
    void *ctx;
} program_data_t;

typedef struct network_connection_v4 {
    u32 local_address;
    u16 local_port;
    u32 remote_address;
    u16 remote_port;
} net_conn_v4_t;

typedef struct network_connection_v6 {
    struct in6_addr local_address;
    u16 local_port;
    struct in6_addr remote_address;
    u16 remote_port;
    u32 flowinfo;
    u32 scope_id;
} net_conn_v6_t;

typedef struct net_id {
    struct in6_addr address;
    u16 port;
    u16 protocol;
} net_id_t;

typedef struct file_mod_key {
    u32 host_pid;
    dev_t device;
    unsigned long inode;
} file_mod_key_t;

enum file_modification_op {
    FILE_MODIFICATION_SUBMIT = 0,
    FILE_MODIFICATION_DONE,
};

// Used to calculate syscall calls per cgroup.
typedef struct syscall_stats_key {
    u64 cgroup_id;
    u64 id;
} syscall_stats_key_t;

// Must be kept in sync with `EBPFMetrics` defined in metrics.go.
enum metric {
    UNKNOWN_METRIC = 0,

    NO_FREE_SCRATCH_BUFFER,
    NO_FREE_SCRATCH_BUFFER_SOCKET_SET_STATE,
    NO_FREE_SCRATCH_BUFFER_NETFLOWS,

    MAX_METRIC,
};

#endif
