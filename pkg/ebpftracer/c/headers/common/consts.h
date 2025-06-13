#ifndef __COMMON_CONSTS_H__
#define __COMMON_CONSTS_H__

// clang-format off

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE 4096       // max size of bytes array (arbitrarily chosen)
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define ARGS_BUF_SIZE       32000
#define SEND_META_SIZE      28

#define MAX_STR_ARR_ELEM      38 // TODO: turn this into global variables set w/ libbpfgo
#define MAX_PATH_COMPONENTS   20
#define MAX_BIN_CHUNKS        110

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

// clang-format on

#define FLOW_GROUPING_DROP_SRC_PORT (1 << 0)

typedef struct {
    u32 self_pid;
    u32 security_file_open_initial_burst;
    u64 pid_ns_id; // id of the pid namespace the node host PID will be translated to.
    u64 flow_sample_submit_interval_seconds;
    u64 flow_grouping;
    bool track_syscall_stats;
    bool export_metrics;
    bool cgroup_v1;
} global_config_t;

volatile const global_config_t global_config;

extern int LINUX_KERNEL_VERSION __kconfig;

#endif
