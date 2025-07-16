#ifndef __FILE_ACCESS_H__
#define __FILE_ACCESS_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <types.h>
#include <maps.h>
#include <common/filesystem.h>

#define MAX_FILE_ACCESS_ENTRIES 8192
#define PATH_MAX_LEN	256
#define MAX_ROOT_DIR_LEN 16

typedef struct file_access_config {
    int map_index;
} file_access_config_t;

struct file_access_key {
    u64 cgroup_id;
    u64 inode;
    u32 dev;

    // In order for BTF to be generated for this struct, a dummy variable needs to
    // be created.
} __attribute__((__packed__)) file_access_key_dummy;

struct file_access_stats {
    u32 reads;
    u8 filepath[PATH_MAX_LEN];
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

statfunc bool is_low_cardinality_file_access_path(void * path)
{
    char b[4];
    if (bpf_probe_read_kernel(&b, sizeof(b), path)) {
        return false;
    }
    if (b[0] == '/') {
         if (b[1] == 'u' && b[2] == 's' && b[3] == 'r') {
            return true;
        }
        if (b[1] == 'b' && b[2] == 'i' && b[3] == 'n') {
            return true;
        }
        if (b[1] == 'e' && b[2] == 't' && b[3] == 'c') {
            return true;
        }
        if (b[1] == 'o' && b[2] == 'p' && b[3] == 't') {
            return true;
        }
        if (b[1] == 'l' && b[2] == 'i' && b[3] == 'b') {
            return true;
        }
    }

    return false;
}

statfunc void keep_root_dir(buf_t *string_p, size_t buf_off)
{
#pragma unroll
    for (int i = 0; i < MAX_ROOT_DIR_LEN; i++) {
        char c = string_p->buf[buf_off+i & ((MAX_PERCPU_BUFSIZE >> 1) - 1)];
        if (i != 0 && c == '/') {
            // We found a first path segment.
            string_p->buf[buf_off+i+1 & ((MAX_PERCPU_BUFSIZE >> 1) - 1)] = '*';
            string_p->buf[buf_off+i+2 & ((MAX_PERCPU_BUFSIZE >> 1) - 1)] = 0; // Add NULL terminator.
            return;
        }
    }
    // First path segment is longer than 16 chars. Just replace 16'th char with a * and terminate.
    string_p->buf[buf_off+MAX_ROOT_DIR_LEN-2 & ((MAX_PERCPU_BUFSIZE >> 1) - 1)] = '*';
    string_p->buf[buf_off+MAX_ROOT_DIR_LEN-1 & ((MAX_PERCPU_BUFSIZE >> 1) - 1)] = 0; // Add NULL terminator.
}

typedef struct file_access_info {
    u64 inode;
    u32 dev;
    void * path;
} file_access_info_t;

statfunc u64 get_path_root_hash(void * path) {
    char b[MAX_ROOT_DIR_LEN];
    if (bpf_probe_read_kernel(&b, sizeof(b), path)) {
        return false;
    }

    // Calculate bash based on FNV for the first dir segment.
    u64 hash = 14695981039346656037ULL; // FNV offset basis.
#pragma unroll
    for (int i = 0; i < MAX_ROOT_DIR_LEN; i++) {
        char c = b[i];
        if (c == 0) {
            // Stop at NULL terminator. After that buffer can contain other random data.
            return hash;
        }
        hash ^= b[i]; // XOR in the byte.
        hash *= 1099511628211ULL;  // Multiply by FNV prime.
    }
    return hash;
}

statfunc bool get_file_access_info(struct file *file, file_access_info_t *out)
{
    // Collect full file path from file struct to a char buf.
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL) {
        return false;
    }
    struct path *path = __builtin_preserve_access_index(&file->f_path);
    size_t buf_off = get_path_str_buf(path, string_p);

    // Read inode and dev. It's needed for lookup key.
    if (BPF_CORE_READ_INTO(&out->inode, file, f_inode, i_ino)) {
        return false;
    }
    if (BPF_CORE_READ_INTO(&out->dev, file, f_inode, i_sb, s_dev)) {
        return false;
    }

    // Set initial file path to to full path. If it's considered as high cardinality path
    // then we will keep only first segment.
    out->path = &string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)];
    if (!is_low_cardinality_file_access_path(out->path)) {
        keep_root_dir(string_p, buf_off);
        // In such case just hash first path segment to uin64.
        out->inode = get_path_root_hash(out->path);
        out->dev = 0;
    }

    return true;
}

statfunc void record_file_access(task_context_t *task_ctx, struct file *file)
{
    int zero = 0;
    file_access_config_t *config = bpf_map_lookup_elem(&file_access_config_map, &zero);
    if (!config) {
        return;
    }

    file_access_info_t file_info = {0};
    if (!get_file_access_info(file, &file_info)) {
        return;
    }

    // Fill file access key.
    struct file_access_key key = {0};
    key.cgroup_id = task_ctx->cgroup_id;
    key.inode = file_info.inode;
    key.dev = file_info.dev;

    void *sum_map = bpf_map_lookup_elem(&file_access_stats_map, &config->map_index);
    if (!sum_map) {
        return;
    }

    // Create initial file access map value if needed.
    struct file_access_stats *stats = bpf_map_lookup_elem(sum_map, &key);
    if (stats == NULL) {
        bpf_map_update_elem(sum_map, &key, &zero_file_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(sum_map, &key);
        if (stats == NULL) {
            return;
        }
        bpf_probe_read_kernel_str(&stats->filepath, PATH_MAX_LEN, file_info.path);
    }

    // Update stats.
    __sync_fetch_and_add(&stats->reads, 1);
}

#endif
