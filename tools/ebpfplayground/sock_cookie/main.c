//go:build ignore

#include "vmlinux_flavors.h"
#include "vmlinux_missing.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct netcontext_val {
    u8 comm[16];
};

typedef union protohdrs_t {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    struct icmphdr icmphdr;
    struct icmp6hdr icmp6hdr;
    union {
        u8 tcp_extra[40]; // data offset might set it up to 60 bytes
    };
} protohdrs;

typedef union iphdrs_t {
    struct iphdr iphdr;
    struct ipv6hdr ipv6hdr;
} iphdrs;

typedef struct nethdrs_t {
    iphdrs iphdrs;
    protohdrs protohdrs;
} nethdrs;


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
    kind_cgroup_skb_egress = 4,
    kind_cgroup_skb_ingress = 5,
    kind_security_sk_clone = 6,
    kind_security_sk_clone_old = 7,
    kind_cgroup_sock_create = 8,
    kind_cgroup_connect4 = 9,
    kind_cgroup_sock_release = 10,
};

typedef union  {
    u32 v4addr;
    unsigned __int128 v6addr;
}  __attribute__((packed)) addr_t;

typedef struct {
    addr_t saddr;
    addr_t daddr;
    u16 sport;
    u16 dport;
    u16 family;
} __attribute__((packed)) tuple_t;

struct event {
    u32 kind;
	tuple_t tuple;
	u64 cookie;
	u8 curr_comm[16];
	u8 comm[16];
};
struct event *unused __attribute__((unused));

static __always_inline u16 get_inet_sport(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_sport);
}

static __always_inline u16 get_inet_dport(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_dport);
}

static __always_inline bool fill_tuple(struct sock *sk, tuple_t *tuple)
{
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    tuple->family = family;

    switch (family) {
        case AF_INET:
            BPF_CORE_READ_INTO(&tuple->saddr.v4addr, sk, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&tuple->daddr.v4addr, sk, __sk_common.skc_daddr);

            break;
        case AF_INET6:
            BPF_CORE_READ_INTO(
                &tuple->saddr.v6addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&tuple->daddr.v6addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;

        default:
            return false;
    }

    tuple->sport = bpf_ntohs(get_inet_sport((struct inet_sock *) sk));
    tuple->dport = bpf_ntohs(get_inet_dport((struct inet_sock *) sk));

    return true;
}

SEC("kprobe/security_sk_clone")
int BPF_KPROBE(trace_security_sk_clone)
{
    struct sock *osock = (void *) PT_REGS_PARM1(ctx);
    struct socket *osocket = BPF_CORE_READ(osock, sk_socket);

    struct sock *nsock = (void *) PT_REGS_PARM2(ctx);
    u64 oldinode = BPF_CORE_READ(osocket, file, f_inode, i_ino);
    struct socket *nsocket = BPF_CORE_READ(nsock, sk_socket);

    u64 newinode = BPF_CORE_READ(nsocket, file, f_inode, i_ino);
    bpf_printk("security_sk_clone old=%px, new=%px\n", osock, nsock);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_security_sk_clone;
    fill_tuple(nsock, &e->tuple);
    bpf_get_current_comm(&e->curr_comm, sizeof(e->curr_comm));
    bpf_ringbuf_submit(e, 0);


    struct event *e2;
    e2 = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e2) {
        return 0;
    }
    e2->kind = kind_security_sk_clone_old;
    fill_tuple(osock, &e2->tuple);
    bpf_get_current_comm(&e2->curr_comm, sizeof(e2->curr_comm));
    bpf_ringbuf_submit(e2, 0);

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
    fill_tuple(sk, &e->tuple);
    bpf_get_current_comm(&e->curr_comm, sizeof(e->curr_comm));

    struct netcontext_val *netctx = bpf_map_lookup_elem(&netcontext, &cookie);
    if (netctx) {
        __builtin_memcpy(&e->comm, &netctx->comm, sizeof(netctx->comm));
    }
    bpf_ringbuf_submit(e, 0);

    return 0;
}

static __always_inline u16 cgroup_skb_handler(struct __sk_buff *ctx, u8 event_kind) {
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

    void *dest;
    nethdrs hdrs = {0}, *nethdrs = &hdrs;

    u32 size = 0;
    u32 prev_hdr_size = 0;
    u32 family = ctx->family;

    switch (family) {
        case PF_INET:
            dest = &nethdrs->iphdrs.iphdr;
            size = get_type_size(struct iphdr);
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = get_type_size(struct ipv6hdr);
            break;
        default:
            return 1;
    }

    if (bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1))
        return 1;

    tuple_t tuple = {0};
    u32 ihl = 0;
    switch (family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4) // IPv4
                return 1;

            ihl = nethdrs->iphdrs.iphdr.ihl;
            if (ihl > 5) { // re-read IPv4 header if needed
                size -= get_type_size(struct iphdr);
                size += ihl * 4;
                bpf_skb_load_bytes_relative(ctx, 0, dest, size, 1);
            }

            switch (nethdrs->iphdrs.iphdr.protocol) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    prev_hdr_size = size;
                    size = get_type_size(struct tcphdr);
                    if (bpf_skb_load_bytes_relative(ctx, prev_hdr_size, dest, size, BPF_HDR_START_NET))
                        return 1;
                    tuple.sport = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
                    tuple.dport = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);
                    break;
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                    break;
                default:
                    return 1; // unsupported proto
            }

            tuple.saddr.v4addr = nethdrs->iphdrs.iphdr.saddr;
            tuple.daddr.v4addr = nethdrs->iphdrs.iphdr.daddr;
            tuple.family = AF_INET;

            break;

        case PF_INET6:
            // TODO: dual-stack IP implementation unsupported for now
            // https://en.wikipedia.org/wiki/IPv6_transition_mechanism
            if (nethdrs->iphdrs.ipv6hdr.version != 6) // IPv6
                return 1;

            switch (nethdrs->iphdrs.ipv6hdr.nexthdr) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_ICMPV6:
                    break;
                default:
                    return 1; // unsupported proto
            }
            break;

        default:
            return 1; // verifier
    }

	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }
	bpf_printk("cgroup_skb ingress cookie=%d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_cgroup_skb_ingress;
    e->cookie = cookie;
    e->tuple = tuple;
    struct netcontext_val *netctx = bpf_map_lookup_elem(&netcontext, &cookie);
    if (netctx) {
        __builtin_memcpy(&e->comm, &netctx->comm, sizeof(netctx->comm));
    }
    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_skb_handler(ctx, kind_cgroup_skb_ingress);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    return cgroup_skb_handler(ctx, kind_cgroup_skb_egress);
}

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }
    struct netcontext_val netctx = {0};
    bpf_get_current_comm(&netctx.comm, sizeof(netctx.comm));
    bpf_map_update_elem(&netcontext, &cookie, &netctx, BPF_ANY);

    bpf_printk("cgroup connect4 cookie=%d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_cgroup_connect4;
    e->cookie = cookie;
//    e->tuple.saddr.v4addr = BPF_CORE_READ(ctx, src_ip4);
//    //e->tuple.saddr.v6addr = BPF_CORE_READ(ctx, src_ip6);
//    e->tuple.daddr.v4addr = BPF_CORE_READ(ctx, dst_ip4);
//    e->tuple.sport = BPF_CORE_READ(ctx, src_port);
//    e->tuple.dport = BPF_CORE_READ(ctx, dst_port);
//    e->tuple.family = ctx->family;
    bpf_get_current_comm(&e->curr_comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }
    struct netcontext_val netctx = {0};
    bpf_get_current_comm(&netctx.comm, sizeof(netctx.comm));
    bpf_map_update_elem(&netcontext, &cookie, &netctx, BPF_ANY);

    bpf_printk("cgroup sock_create cookie=%d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_cgroup_sock_create;
    e->cookie = cookie;
    e->tuple.saddr.v4addr = BPF_CORE_READ(ctx, src_ip4);
    e->tuple.daddr.v4addr = BPF_CORE_READ(ctx, dst_ip4);
    e->tuple.sport = BPF_CORE_READ(ctx, src_port);
    e->tuple.dport = BPF_CORE_READ(ctx, dst_port);
    e->tuple.family = ctx->family;
    bpf_get_current_comm(&e->curr_comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
	u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie == 1) {
        return 1;
    }

    bpf_printk("cgroup sock_release cookie=%d\n", cookie);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    e->kind = kind_cgroup_sock_release;
    e->cookie = cookie;
    e->tuple.saddr.v4addr = BPF_CORE_READ(ctx, src_ip4);
    e->tuple.daddr.v4addr = BPF_CORE_READ(ctx, dst_ip4);
    e->tuple.sport = BPF_CORE_READ(ctx, src_port);
    e->tuple.dport = BPF_CORE_READ(ctx, dst_port);
    e->tuple.family = ctx->family;
    bpf_get_current_comm(&e->curr_comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 1;
}
