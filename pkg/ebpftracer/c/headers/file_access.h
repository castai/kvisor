#ifndef __FILE_ACCESS_H__
#define __FILE_ACCESS_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <types.h>
#include <maps.h>
#include <common/filesystem.h>

#define MAX_FILE_ACCESS_ENTRIES 65535
// Max path len is limited to 4096 bytes, see https://github.com/torvalds/linux/blob/master/include/uapi/linux/limits.h#L13
// But in most cases it's a waste of memory as file paths are not that long.
// We can make this configurable in the feature if needed.
#define PATH_MAX_LEN	512

typedef struct file_access_config {
    int map_index;
} file_access_config_t;

struct file_access_key {
    u64 cgroup_id;
    u64 inode;
    u64 pid_start_time;
    u32 pid;
    u32 host_pid;
    u32 dev;

    // In order for BTF to be generated for this struct, a dummy variable needs to
    // be created.
} __attribute__((__packed__)) file_access_key_dummy;

struct file_access_stats {
    u64 reads;
    u8 filepath[PATH_MAX_LEN];
    u8 comm[TASK_COMM_LEN];
    // In order for BTF to be generated for this struct, a dummy variable needs to
    // be created.
} __attribute__((__packed__)) file_access_stats_dummy;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, int);
    __array(
        values, struct {
            __uint(type, BPF_MAP_TYPE_LRU_HASH);
            __uint(max_entries, MAX_FILE_ACCESS_ENTRIES);
            __type(key, struct file_access_key);
            __type(value, struct file_access_stats);
        });
} file_access_stats_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 2);
        __type(key, u32);
        __type(value, file_access_config_t);
} file_access_config_map SEC(".maps");

static struct file_access_stats zero_file_stats = {};

#define MAX_SEGMENT_LEN 64

statfunc void generalize_path(unsigned char *path) {
int seg_start = 0;

    #pragma unroll
    for (int i = 0; i < PATH_MAX_LEN; i++) {
        if (path[i] == '\0') {
            break;
        }

        if (path[i] == '/') {
            int seg_len = i - seg_start;

            if (seg_len > 12 && seg_len < MAX_SEGMENT_LEN) {
                int digits = 0;
                int alnum = 0;

                #pragma unroll
                for (int j = 0; j < MAX_SEGMENT_LEN; j++) {
                    if ((seg_start + j) >= i) {
                        break;
                    }

                    char c = path[seg_start + j];

                    if (c >= '0' && c <= '9') {
                        digits++;
                    }

                    if ((c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9')) {
                        alnum++;
                    }
                }

                if ((digits * 100 / seg_len > 80) || (alnum == seg_len)) {
                    path[seg_start] = '*';

                    #pragma unroll
                    for (int k = 1; k < MAX_SEGMENT_LEN; k++) {
                        if ((seg_start + k) >= i) {
                            break;
                        }
                        path[seg_start + k] = '\0';
                    }
                }
            }

            seg_start = i + 1;
        }
    }
}

statfunc void record_file_access(task_context_t *task_ctx, struct file *file)
{
    int zero = 0;
    file_access_config_t *config = bpf_map_lookup_elem(&file_access_config_map, &zero);
    if (!config)
        return;

    // Fill file access key.
    struct file_access_key key = {0};
    key.cgroup_id = task_ctx->cgroup_id;
    key.pid_start_time = task_ctx->leader_start_time;
    key.pid = task_ctx->pid;
    key.host_pid = task_ctx->host_pid;
    if (BPF_CORE_READ_INTO(&key.inode, file, f_inode, i_ino)) {
        return;
    }
    if (BPF_CORE_READ_INTO(&key.dev, file, f_inode, i_sb, s_dev)) {
        return;
    }

    void *sum_map = bpf_map_lookup_elem(&file_access_stats_map, &config->map_index);
    if (!sum_map)
        return;

    // Create initial file access map value if needed.
    struct file_access_stats *stats = bpf_map_lookup_elem(sum_map, &key);
    if (stats == NULL) {
        bpf_map_update_elem(sum_map, &key, &zero_file_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(sum_map, &key);
        if (stats == NULL) // Should not happen.
            return;

        bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
        void *file_path = get_path_str(__builtin_preserve_access_index(&file->f_path));
        bpf_probe_read_kernel_str(&stats->filepath, PATH_MAX_LEN, file_path);
        generalize_path(stats->filepath);
    }

    // Update stats.
    __sync_fetch_and_add(&stats->reads, 1);
}

#endif
