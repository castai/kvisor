#ifndef __COMMON_BUFFER_H__
#define __COMMON_BUFFER_H__

#include <vmlinux.h>
#include <types.h>

#include <bpf/bpf_helpers.h>
#include <common/common.h>
#include <common/metrics.h>
#include <maps.h>

#include <common/context.h>
#include <common/network.h>

// PROTOTYPES

statfunc buf_t *get_buf(int);
statfunc int save_to_submit_buf(args_buffer_t *, void *, u32, u8);
statfunc int save_bytes_to_buf(args_buffer_t *, void *, u32, u8);
statfunc int save_str_to_buf(args_buffer_t *, void *, u8);
statfunc int add_u64_elements_to_buf(args_buffer_t *, const u64 __user *, int, volatile u32);
statfunc int save_u64_arr_to_buf(args_buffer_t *, const u64 __user *, int, u8);
statfunc int save_str_arr_to_buf(args_buffer_t *, const char __user *const __user *, u8);
statfunc int save_args_str_arr_to_buf(args_buffer_t *, const char *, const char *, int, u8);
statfunc int save_sockaddr_to_buf(args_buffer_t *, struct socket *, u8);
statfunc int save_args_to_submit_buf(event_data_t *, args_t *);

// FUNCTIONS

statfunc buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// biggest elem to be saved with 'save_to_submit_buf' should be defined here:
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

statfunc int save_to_submit_buf(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    barrier();
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Satisfy verifier
    if (buf->offset > ARGS_BUF_SIZE - (MAX_ELEMENT_SIZE + 1))
        return 0;

    // Read into buffer
    if (bpf_probe_read_kernel(&(buf->args[buf->offset + 1]), size, ptr) == 0) {
        // We update offset only if all writes were successful
        buf->offset += size + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_to_submit_buf_kernel(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    barrier();
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Satisfy verifier
    if (buf->offset > ARGS_BUF_SIZE - (MAX_ELEMENT_SIZE + 1))
        return 0;

    // Read into buffer
    if (bpf_probe_read_kernel(&(buf->args[buf->offset + 1]), size, ptr) == 0) {
        // We update offset only if all writes were successful
        buf->offset += size + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_bytes_to_buf(args_buffer_t *buf, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    if (size == 0)
        return 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    if (buf->offset > ARGS_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // Save size to buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 1]), sizeof(int), &size) != 0) {
        return 0;
    }

    if (buf->offset > ARGS_BUF_SIZE - (MAX_BYTES_ARR_SIZE + 1 + sizeof(int)))
        return 0;

    // Read bytes into buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 1 + sizeof(int)]),
                       size & (MAX_BYTES_ARR_SIZE - 1),
                       ptr) == 0) {
        // We update offset only if all writes were successful
        buf->offset += size + 1 + sizeof(int);
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_str_to_buf(args_buffer_t *buf, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Satisfy verifier for probe read
    if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
        return 0;

    // Read into buffer
    int sz = bpf_probe_read_str(&(buf->args[buf->offset + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        barrier();
        // Satisfy verifier for probe read
        if (buf->offset > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
            return 0;

        __builtin_memcpy(&(buf->args[buf->offset + 1]), &sz, sizeof(int));
        buf->offset += sz + sizeof(int) + 1;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int
add_u64_elements_to_buf(args_buffer_t *buf, const u64 __user *ptr, int len, volatile u32 count_off)
{
    // save count_off into a new variable to avoid verifier errors
    u32 off = count_off;
    u8 elem_num = 0;
#pragma unroll
    for (int i = 0; i < len; i++) {
        void *addr = &(buf->args[buf->offset]);
        if (buf->offset > ARGS_BUF_SIZE - sizeof(u64))
            // not enough space - return
            goto out;
        if (bpf_probe_read(addr, sizeof(u64), (void *) &ptr[i]) != 0)
            goto out;
        elem_num++;
        buf->offset += sizeof(u64);
    }
out:
    // save number of elements in the array
    if (off > (ARGS_BUF_SIZE - 1))
        return 0;

    u8 current_elem_num = buf->args[off];
    buf->args[off] = current_elem_num + elem_num;

    return 1;
}

statfunc int save_u64_arr_to_buf(args_buffer_t *buf, const u64 *ptr, int len, u8 index)
{
    // Data saved to submit buf: [index][u16 count][u64 1][u64 2][u64 3]...
    u16 restricted_len = (u16) len;
    u32 total_size = sizeof(u64) * restricted_len;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Save number of elements
    if (buf->offset + sizeof(index) > ARGS_BUF_SIZE - sizeof(restricted_len))
        return 0;
    __builtin_memcpy(
        &(buf->args[buf->offset + sizeof(index)]), &restricted_len, sizeof(restricted_len));

    if ((buf->offset + sizeof(index) + sizeof(restricted_len) > ARGS_BUF_SIZE - MAX_BYTES_ARR_SIZE))
        return 0;

    if (bpf_probe_read(&(buf->args[buf->offset + sizeof(index) + sizeof(restricted_len)]),
                       total_size & (MAX_BYTES_ARR_SIZE - 1),
                       (void *) ptr) != 0)
        return 0;

    buf->argnum++;
    buf->offset += sizeof(index) + sizeof(restricted_len) + total_size;

    return 1;
}

statfunc int save_str_arr_to_buf(args_buffer_t *buf, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    buf->args[buf->offset] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = buf->offset + 1;
    buf->offset += 2;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (buf->offset > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(buf->args[buf->offset + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (buf->offset > ARGS_BUF_SIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(buf->args[buf->offset]), sizeof(int), &sz);
            buf->offset += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (buf->offset > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(buf->args[buf->offset + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (buf->offset > ARGS_BUF_SIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(buf->args[buf->offset]), sizeof(int), &sz);
        buf->offset += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    buf->args[orig_off] = elem_num;
    buf->argnum++;
    return 1;
}

#define MAX_ARR_LEN 8192

statfunc int save_args_str_arr_to_buf(
    args_buffer_t *buf, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg_len][arg #][null delimited string array]
    // Note: This helper saves null (0x00) delimited string array into buf

    if (start >= end)
        return 0;

    int len = end - start;
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;

    // Save argument index
    if (buf->offset > ARGS_BUF_SIZE - 1)
        return 0;
    buf->args[buf->offset] = index;

    // Satisfy validator for probe read
    if ((buf->offset + 1) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save array length
    bpf_probe_read(&(buf->args[buf->offset + 1]), sizeof(int), &len);

    // Satisfy validator for probe read
    if ((buf->offset + 5) > ARGS_BUF_SIZE - sizeof(int))
        return 0;

    // Save number of arguments
    bpf_probe_read(&(buf->args[buf->offset + 5]), sizeof(int), &elem_num);

    // Satisfy validator for probe read
    if ((buf->offset + 9) > ARGS_BUF_SIZE - MAX_ARR_LEN)
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(buf->args[buf->offset + 9]), len & (MAX_ARR_LEN - 1), start) == 0) {
        // We update offset only if all writes were successful
        buf->offset += len + 9;
        buf->argnum++;
        return 1;
    }

    return 0;
}

statfunc int save_sockaddr_to_buf(args_buffer_t *buf, struct socket *sock, u8 index)
{
    struct sock *sk = get_socket_sock(sock);

    u16 family = get_sock_family(sk);
    if ((family != AF_INET) && (family != AF_INET6) && (family != AF_UNIX)) {
        return 0;
    }

    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        struct sockaddr_in local;

        get_network_details_from_sock_v4(sk, &net_details, 0);
        get_local_sockaddr_in_from_network_details(&local, &net_details, family);

        save_to_submit_buf(buf, (void *) &local, sizeof(struct sockaddr_in), index);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        struct sockaddr_in6 local;

        get_network_details_from_sock_v6(sk, &net_details, 0);
        get_local_sockaddr_in6_from_network_details(&local, &net_details, family);

        save_to_submit_buf(buf, (void *) &local, sizeof(struct sockaddr_in6), index);
    } else if (family == AF_UNIX) {
        struct unix_sock *unix_sk = (struct unix_sock *) sk;
        struct sockaddr_un sockaddr = get_unix_sock_addr(unix_sk);
        save_to_submit_buf(buf, (void *) &sockaddr, sizeof(struct sockaddr_un), index);
    }
    return 0;
}

#define DEC_ARG(n, enc_arg) ((enc_arg >> (8 * n)) & 0xFF)

statfunc int save_args_to_submit_buf(event_data_t *event, args_t *args)
{
    unsigned int i;
    unsigned int rc = 0;
    unsigned int arg_num = 0;
    short family = 0;

    if (event->param_types == 0)
        return 0;

#pragma unroll
    for (i = 0; i < 6; i++) {
        int size = 0;
        u8 type = DEC_ARG(i, event->param_types);
        u8 index = i;
        switch (type) {
            case NONE_T:
                break;
            case INT_T:
                size = sizeof(int);
                break;
            case UINT_T:
                size = sizeof(unsigned int);
                break;
            case OFF_T_T:
                size = sizeof(off_t);
                break;
            case DEV_T_T:
                size = sizeof(dev_t);
                break;
            case MODE_T_T:
                size = sizeof(mode_t);
                break;
            case LONG_T:
                size = sizeof(long);
                break;
            case ULONG_T:
                size = sizeof(unsigned long);
                break;
            case SIZE_T_T:
                size = sizeof(size_t);
                break;
            case POINTER_T:
                size = sizeof(void *);
                break;
            case U8_T:
                size = sizeof(u8);
                break;
            case U16_T:
                size = sizeof(u16);
                break;
            case STR_T:
                rc = save_str_to_buf(&(event->args_buf), (void *) args->args[i], index);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void *) args->args[i]);
                    switch (family) {
                        case AF_UNIX:
                            size = sizeof(struct sockaddr_un);
                            break;
                        case AF_INET:
                            size = sizeof(struct sockaddr_in);
                            break;
                        case AF_INET6:
                            size = sizeof(struct sockaddr_in6);
                            break;
                        default:
                            size = sizeof(short);
                    }
                    rc = save_to_submit_buf(
                        &(event->args_buf), (void *) (args->args[i]), size, index);
                } else {
                    rc = save_to_submit_buf(&(event->args_buf), &family, sizeof(short), index);
                }
                break;
            case INT_ARR_2_T:
                size = sizeof(int[2]);
                rc = save_to_submit_buf(&(event->args_buf), (void *) (args->args[i]), size, index);
                break;
            case TIMESPEC_T:
                size = sizeof(struct __kernel_timespec);
                rc = save_to_submit_buf(&(event->args_buf), (void *) (args->args[i]), size, index);
                break;
        }
        switch (type) {
            case NONE_T:
            case STR_T:
            case SOCKADDR_T:
            case INT_ARR_2_T:
            case TIMESPEC_T:
                break;
            default:
                rc = save_to_submit_buf(&(event->args_buf), (void *) &(args->args[i]), size, index);
                break;
        }
        if (rc > 0) {
            arg_num++;
            rc = 0;
        }
    }

    return arg_num;
}

#define events_ringbuf_submit(p, id, ret)        do_ringbuf_submit(&events, p, id, ret, true, EVENTS_RINGBUF_DISCARD)
#define signal_events_ringbuf_submit(p, id, ret) do_ringbuf_submit(&signal_events, p, id, ret, true, SIGNAL_EVENTS_RINGBUF_DISCARD)

statfunc int do_ringbuf_submit(void *target, program_data_t *p, u32 id, long ret, bool init_task_ctx, enum metric m) {

    p->event->context.eventid = id;
    p->event->context.retval = ret;

    if (init_task_ctx) {
        init_task_context(&p->event->context.task, p->task);
        // keep task_info updated
        bpf_probe_read_kernel(
            &p->task_info->context, sizeof(task_context_t), &p->event->context.task);
    }

    u32 size = sizeof(event_context_t) + sizeof(u8) +
               p->event->args_buf.offset; // context + argnum + arg buffer size

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    if (bpf_ringbuf_output(target, p->event, size, 0) < 0) {
        metrics_increase(m);
        return 1;
    }
    return 0;
}

statfunc event_data_t *find_next_free_scratch_buf(void *scratch_map)
{
#pragma unroll
    for (int i = 0; i < SCRATCH_MAP_SIZE; i++) {
        int scratch_idx = i;
        event_data_t *e = bpf_map_lookup_elem(scratch_map, &scratch_idx);
        if (unlikely(e == NULL)) {
            return NULL;
        }

        __sync_fetch_and_add(&e->in_use, 1);
        barrier();
        if (e->in_use > 1) {
            // The scratch buffer already in use, we need to skip this one.
            __sync_fetch_and_add(&e->in_use, -1);
            continue;
        } else {
            // We found a free scratch buffer.
            return e;
        }
    }

    metrics_increase(NO_FREE_SCRATCH_BUFFER);

    return NULL;
}

statfunc void free_scratch_buf(event_data_t *e)
{
    if (e == NULL) {
        return;
    }

    // We need to free the scratch buffer.
    __sync_fetch_and_sub(&e->in_use, 1);
}

statfunc event_data_t *init_netflows_event_data()
{
    event_data_t *e = find_next_free_scratch_buf(&netflows_data_map);
    if (unlikely(e == NULL)) {
        metrics_increase(NO_FREE_SCRATCH_BUFFER_NETFLOWS);
        return NULL;
    }

    e->context.ts = bpf_ktime_get_ns();
    e->args_buf.argnum = 0;
    e->args_buf.offset = 0;
    return e;
}

statfunc int net_events_perf_submit(void *ctx, u32 id, event_data_t *event)
{
    event->context.eventid = id;

    u32 size = sizeof(event_context_t) + sizeof(u8) +
               event->args_buf.offset; // context + argnum + arg buffer size

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, size);
}

#endif
