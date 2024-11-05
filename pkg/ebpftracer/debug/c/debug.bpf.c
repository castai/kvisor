// +build ignore

// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <types.h>
#include <common/network.h>

char LICENSE[] SEC("license") = "GPL";

static volatile const pid_t target_pid SEC(".rodata.target_pid");
// For whatever reason the compiler doesn't but the bpf_map_fops variable
// in the .rodata section of the elf binary. This causes the rewrite in the
// go binary to fail. This can be fixed by forcing section via the SEC
// annotation.
static volatile const void *bpf_map_fops SEC(".rodata.bpf_map_fops");

struct socket_info {
    tuple_t tuple;
    __u16 family;
    __u8 proto;
    __u8 state;
    __u64 ino;
};

struct debug_socket_context {
    struct socket_info sock_info;
    struct net_task_context netctx;
};

// Dummy value to force BTF info to be generated for type.
volatile struct debug_socket_context dummy_debug_socket_context;

SEC("iter/bpf_sk_storage_map")
int debug_sockmap_iterator(struct bpf_iter__bpf_sk_storage_map *ctx)
{
    struct sock *sk = (struct sock *) ctx->sk;
    net_task_context_t *netctx = ctx->value;

    if (!sk || !netctx) {
        return 0;
    }

    struct debug_socket_context debugctx = {0};
    debugctx.netctx = *netctx;

    if (!fill_tuple(sk, &debugctx.sock_info.tuple)) {
        return 0;
    }

    BPF_CORE_READ_INTO(&debugctx.sock_info.proto, sk, sk_protocol);
    BPF_CORE_READ_INTO(&debugctx.sock_info.family, sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&debugctx.sock_info.ino, ctx, sk, sk_socket, file, f_inode, i_ino);
    BPF_CORE_READ_INTO(&debugctx.sock_info.state, ctx, sk, __sk_common.skc_state);

    bpf_seq_write(ctx->meta->seq, &debugctx, sizeof(debugctx));

    return 0;
}

#define BPF_OBJ_NAME_LEN 16U

struct process_bpf_map {
    u32 map_id;
    u8 name[BPF_OBJ_NAME_LEN];
};

// Dummy value to force BTF info to be generated for type.
volatile struct process_bpf_map dummy_bpf_map;

SEC("iter/task_file")
int iter_maps(struct bpf_iter__task_file *ctx)
{
    struct file *file = ctx->file;
    struct task_struct *task = ctx->task;

    if (!file || !task) {
        return 0;
    }

    // We are only intersted in maps for a specific PID.
    if (file->f_op != bpf_map_fops || task->pid != target_pid) {
        return 0;
    }

    struct bpf_map *m = file->private_data;
    if (BPF_CORE_READ(m, map_type) != BPF_MAP_TYPE_SK_STORAGE) {
        return 0;
    }

    struct process_bpf_map map = {0};

    BPF_CORE_READ_INTO(&map.map_id, m, id);
    BPF_CORE_READ_STR_INTO(&map.name, m, name);

    bpf_seq_write(ctx->meta->seq, &map, sizeof(map));

    return 0;
}
