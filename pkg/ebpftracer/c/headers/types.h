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
    FILE_MODIFICATION,
    SOCK_SET_STATE,
    PROCESS_OOM_KILLED,
    TTY_OPEN,
    TTY_WRITE,
    STDIO_VIA_SOCKET,
    PROC_FD_LINK_RESOLVED,
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

typedef struct config {
    int summary_map_index;
} config_t;

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

    SIGNAL_EVENTS_RINGBUF_DISCARD,
    EVENTS_RINGBUF_DISCARD,
    SKB_EVENTS_RINGBUF_DISCARD,

    SKB_CTX_CGROUP_FALLBACK,
    SKB_MISSING_EXISTING_CTX,

    MAX_METRIC,
};

// Network types

typedef union iphdrs_t {
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef union {
    // Used for bpf2go to generate a proper golang struct.
    __u8 raw[16];
    __u32 v4addr;
    __be32 u6_addr32[4];
} __attribute__((packed)) addr_t;

typedef struct {
    addr_t saddr;
    addr_t daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
} __attribute__((packed)) tuple_t;

union addr {
    __u8 raw[16];
    __be32 ipv6[4];
    __be32 ipv4;
} __attribute__((__packed__));

typedef struct process_identity {
    __u32 pid;
    __u64 pid_start_time;
    __u64 cgroup_id;
    // TODO(patrick.pichler): In the future we might want to get rid of comm and move it
    // to an enrichment stage in userspace. If we do this, we could probably also get rid
    // of it for event context.
    __u8 comm[TASK_COMM_LEN];
} __attribute__((__packed__)) process_identity_t;

struct traffic_summary {
    __u64 rx_packets;
    __u64 rx_bytes;

    __u64 tx_packets;
    __u64 tx_bytes;

    __u64 last_packet_ts;
    // In order for BTF to be generated for this struct, a dummy variable needs to
    // be created.
} __attribute__((__packed__)) traffic_summary_dummy;

struct ip_key {
    struct process_identity process_identity;

    tuple_t tuple;
    __u8 proto;

    // In order for BTF to be generated for this struct, a dummy variable needs to
    // be created.
} __attribute__((__packed__)) ip_key_dummy;

enum flow_direction {
    INGRESS,
    EGRESS,
};

// NOTE: proto header structs need full type in vmlinux.h (for correct skb copy)

typedef union protohdrs_t {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
    union {
        u8 tcp_extra[40]; // data offset might set it up to 60 bytes
    };
} protohdrs;

typedef struct nethdrs_t {
    iphdrs iphdrs;
    protohdrs protohdrs;
} nethdrs;

// cgroupctxmap

typedef enum net_packet {
    // Layer 3
    SUB_NET_PACKET_IP = 1 << 1,
    // Layer 4
    SUB_NET_PACKET_TCP = 1 << 2,
    SUB_NET_PACKET_UDP = 1 << 3,
    SUB_NET_PACKET_ICMP = 1 << 4,
    SUB_NET_PACKET_ICMPV6 = 1 << 5,
    // Layer 7
    SUB_NET_PACKET_DNS = 1 << 6,
    SUB_NET_PACKET_SOCKS5 = 1 << 8,
    SUB_NET_PACKET_SSH = 1 << 9,
} net_packet_t;

typedef struct net_event_contextmd {
    u32 header_size;
    u8 captured; // packet has already been captured
} __attribute__((__packed__)) net_event_contextmd_t;

// network related maps

typedef struct net_task_context {
    task_context_t taskctx;
} net_task_context_t;

// CONSTANTS
// Network return value (retval) codes

// Packet Direction (ingress/egress) Flag
#define packet_ingress (1 << 4)
#define packet_egress  (1 << 5)
// Flows (begin/end) Flags per Protocol
#define flow_tcp_begin  (1 << 6) // syn+ack flag or first flow packet
#define flow_tcp_sample (1 << 7) // sample with statistics after first flow
#define flow_tcp_end    (1 << 8) // fin flag or last flow packet

// payload size: full packets, only headers
#define FULL    65536 // 1 << 16
#define HEADERS 0     // no payload

// when guessing by src/dst ports, declare at network.h
#define TCP_PORT_SSH    22
#define UDP_PORT_DNS    53
#define TCP_PORT_DNS    53
#define TCP_PORT_SOCKS5 1080

// layer 7 parsing related constants
#define socks5_min_len 4
#define ssh_min_len    4 // the initial SSH messages always send `SSH-`

#endif
