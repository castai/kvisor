//go:build ignore

#include "vmlinux_flavors.h"
#include "vmlinux_missing.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct netcontext_val {
    u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, u64);
    __type(value, struct netcontext_val);
} netcontext SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

enum
{
    kind_security_socket_connect = 1,
    kind_security_socket_sendmsg = 2,
    kind_inet_sock_set_state = 3,
};

struct event {
    u8 kind;
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
	u64 cookie;
};
struct event *unused __attribute__((unused));

static __always_inline void fill_tuple_from_sock(struct event *e, struct sock *sk) {
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->dport = sk->__sk_common.skc_dport;
    e->sport = bpf_htons(sk->__sk_common.skc_num);
}

SEC("fentry/security_socket_connect")
int BPF_PROG(security_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    struct sock *sk = sock->sk;
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	u64 cookie = bpf_get_socket_cookie(sk);
	bpf_printk("security_socket_connect %d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_security_socket_connect;
    e->cookie = cookie;
    fill_tuple_from_sock(e, sk);
    bpf_get_current_comm(&e->comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(e, 0);

    struct netcontext_val netctx = {0};
    bpf_get_current_comm(&netctx, TASK_COMM_LEN);
    bpf_map_update_elem(&netcontext, &cookie, &netctx, BPF_ANY);

	return 0;
}

SEC("fentry/security_socket_sendmsg")
int BPF_PROG(security_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    struct sock *sk = sock->sk;
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	u64 cookie = bpf_get_socket_cookie(sk);
    if (cookie == 1) {
        return 0;
    }
	bpf_printk("security_socket_sendmsg %d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_security_socket_sendmsg;
    e->cookie = cookie;
    fill_tuple_from_sock(e, sk);
    bpf_get_current_comm(&e->comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(e, 0);

    struct netcontext_val netctx = {0};
    bpf_get_current_comm(&netctx, TASK_COMM_LEN);
    bpf_map_update_elem(&netcontext, &cookie, &netctx, BPF_ANY);

	return 0;
}

SEC("fentry/security_socket_recvmsg")
int BPF_PROG(security_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size) {
    struct sock *sk = sock->sk;
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	u64 cookie = bpf_get_socket_cookie(sk);
    if (cookie == 1) {
        return 0;
    }
	bpf_printk("security_socket_recvmsg %d\n", cookie);

	return 0;
}

SEC("fentry/security_sk_clone")
int BPF_PROG(security_sk_clone, struct sock *sk, struct sock *newsk) {

	u64 cookie = bpf_get_socket_cookie(newsk);
	bpf_printk("security_sk_clone %d\n", cookie);

	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
{
    u64 cookie = bpf_get_socket_cookie(sk);
	bpf_printk("inet_sock_set_state %d, old=%d, new=%d\n", cookie, oldstate, newstate);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_inet_sock_set_state;
    e->cookie = cookie;
    fill_tuple_from_sock(e, sk);

    struct netcontext_val *netctx = bpf_map_lookup_elem(&netcontext, &cookie);
    if (netctx) {
        __builtin_memcpy(&e->comm, &netctx->comm, 16);
    }
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    switch (ctx->family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // PF_INET and PF_INET6 only
    }

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }
	bpf_printk("cgroup_skb ingress %d\n", cookie);
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    switch (ctx->family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1; // PF_INET and PF_INET6 only
    }

    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return 1;

	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }
	bpf_printk("cgroup_skb egress %d\n", cookie);

    return 1;
}
