#ifndef __MAPS_H__
#define __MAPS_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <types.h>

#define SCRATCH_MAP_SIZE 4 // amount of scratch items to store per cpu

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_MAP_NO_KEY(_name, _type, _value_type, _max_entries)                                    \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_HASH_OF_MAPS(_name, _key_type, _value_type, _max_entries)                              \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH_OF_MAPS, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)                                  \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries)                                                \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                         \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries)                                                        \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

#define BPF_QUEUE(_name, _value_type, _max_entries)                                                \
    BPF_MAP_NO_KEY(_name, BPF_MAP_TYPE_QUEUE, _value_type, _max_entries)

#define BPF_STACK(_name, _value_type, _max_entries)                                                \
    BPF_MAP_NO_KEY(_name, BPF_MAP_TYPE_STACK, _value_type, _max_entries)

enum tail_call_id_e {
    TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT,
    MAX_TAIL_CALL
};

// clang-format off

BPF_HASH(args_map, u64, args_t, 10240);                                                 // persist args between function entry and return
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                                             // map 32bit to 64bit syscalls
BPF_LRU_HASH(proc_info_map, u32, proc_info_t, 30720);                                   // holds data for every process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);                                   // holds data for every task
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);                                             // percpu global buffer variables
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);                                              // store programs for tail calls
BPF_PROG_ARRAY(prog_array_tp, MAX_TAIL_CALL);                                           // store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);                                          // store syscall specific programs for tail calls from sys_enter
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);                                           // store syscall specific programs for tail calls from sys_exit
BPF_PROG_ARRAY(sys_enter_submit_tail, MAX_EVENT_ID);                                    // store program for submitting syscalls from sys_enter
BPF_PROG_ARRAY(sys_exit_submit_tail, MAX_EVENT_ID);                                     // store program for submitting syscalls from sys_exit
BPF_PROG_ARRAY(sys_enter_init_tail, MAX_EVENT_ID);                                      // store program for performing syscall tracking logic in sys_enter
BPF_PROG_ARRAY(sys_exit_init_tail, MAX_EVENT_ID);                                       // store program for performing syscall tracking logic in sys_exits
BPF_PERCPU_ARRAY(event_data_map, event_data_t, 1);                                      // persist event related data
BPF_PERCPU_ARRAY(netflows_data_map, event_data_t, SCRATCH_MAP_SIZE);                    // netflows scratch map
// TODO(patrick.pichler): think about removing this as well, we do not use it at all
BPF_HASH(logs_count, bpf_log_t, bpf_log_count_t, 4096);                                 // logs count
BPF_PERCPU_ARRAY(scratch_map, scratch_t, 2);                                            // scratch space to avoid allocating stuff on the stack
BPF_LRU_HASH(file_modification_map, file_mod_key_t, int, 10240);                        // hold file data to decide if should submit file modification event
BPF_LRU_HASH(io_file_path_cache_map, file_id_t, path_buf_t, 5);                         // store cache for IO operations path
BPF_HASH(events_map, u32, event_config_t, MAX_EVENT_ID);                                // map to persist event configuration data
BPF_LRU_HASH(syscall_stats_map, syscall_stats_key_t, u64, 65536);                       // holds syscalls stats per cgroup
BPF_LRU_HASH(dropped_binary_inodes, u64, u32, 8192);                                    // holds inodes of binaries that have been identified as dropped
BPF_HASH(oom_info, u32, u8, 1024);                                                      // marks PIDs as OOM
BPF_HASH(ignored_cgroups_map, u64, u64, 10240);                                         // marks cgroup ids as ignored, causing no more events to be emited for actions in those cgroups
BPF_LRU_HASH(pid_original_file_flags, pid_t, u16, 1024);                                // holds flags of the original executed file (used to detect e.g. dropped scripts)
BPF_LRU_HASH(tty_opened_files, u32, u8, 1024);                                          // holds inodes for opened tty files
BPF_LRU_HASH(cgroup_caps_cache, u64, caps_t, 1024);                                     // holds capabilities used by cgroup ids

// clang-format on

BPF_ARRAY(metrics, u64, MAX_METRIC); // map containing different metric counters
BPF_ARRAY(config_map, config_t, 1);

// TODO(patrick.pichler): think about maybe removing this
BPF_PERF_OUTPUT(logs, 1024);          // logs submission
BPF_PERF_OUTPUT(file_writes, 1024);   // file writes events submission
BPF_PERF_OUTPUT(signals, 1024);       // control plane signals submissions

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1); // Actual size is set in user space before loading.
} signal_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1); // Actual size is set in user space before loading.
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1); // Actual size is set in user space before loading.
} skb_events SEC(".maps");

// Network Maps

#define MAX_NETFLOWS 65535

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, int);
    __array(
        values, struct {
            __uint(type, BPF_MAP_TYPE_LRU_HASH);
            __uint(max_entries, MAX_NETFLOWS);
            __type(key, struct ip_key);
            __type(value, struct traffic_summary);
        });
} network_traffic_buffer_map SEC(".maps");

// Sockets task context. Used to get user space task context for network related events.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct net_task_context);
} net_taskctx_map SEC(".maps");

// We sadly need this second map to store context for existing sockets, as we cannot access the
// `sk_sock_storage` from an iterator without the help of the `bpf_sock_from_file` helper, which
// only is available starting from `5.11`.
//
// The idea of the socket_key is borrowed from inspektor-gadget. There are potential problems with
// it though, as it is based on the assumption that port+proto+network ns is unique, which is not
// always the case, as there is SO_REUSEPORT. Overall it should be good enough for our case though,
// as we currenlty cannot handle such cases anyway.
//
// TODO(patrick.pichler): replace this map with `bpf_sock_from_file` once we up our min kernel
// version to at least 5.11
BPF_HASH(existing_sockets_map, struct sock*, struct net_task_context, MAX_NETFLOWS);

BPF_PERCPU_ARRAY(net_heap_sock_state_event, event_data_t, SCRATCH_MAP_SIZE);

#endif /* __MAPS_H__ */
