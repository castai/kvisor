#ifndef __COMMON_NETWORK_H__
#define __COMMON_NETWORK_H__

#include "types.h"
#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>

#include <common/common.h>

// TYPES

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

typedef struct net_event_context {
    event_context_t eventctx;
    u8 argnum;
    struct { // event arguments (needs packing), use anonymous struct to ...
        u8 index0;
        u32 bytes;
        // ... (payload sent by bpf_perf_event_output)
    } __attribute__((__packed__)); // ... avoid address-of-packed-member warns
    // members bellow this point are metadata (not part of event to be sent)
    net_event_contextmd_t md;
} __attribute__((__packed__)) net_event_context_t;

// network related maps

typedef struct net_task_context {
    task_context_t taskctx;
} net_task_context_t;

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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NETFLOWS);
    __type(key, struct bpf_sock *);
    __type(value, struct net_task_context);
} existing_sockets_map SEC(".maps");

// scratch area

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SCRATCH_MAP_SIZE); // simultaneous softirqs running per CPU (?)
    __type(key, u32);                      // per cpu index ... (always zero)
    __type(value, event_data_t);           // ... linked to a scratch area
} net_heap_sock_state_event SEC(".maps");

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

// PROTOTYPES

statfunc u32 get_inet_rcv_saddr(struct inet_sock *);
statfunc u32 get_inet_daddr(struct inet_sock *);
statfunc u16 get_inet_sport(struct inet_sock *);
statfunc u16 get_inet_num(struct inet_sock *);
statfunc u16 get_inet_dport(struct inet_sock *);
statfunc struct sock *get_socket_sock(struct socket *);
statfunc u16 get_sock_family(struct sock *);
statfunc u16 get_sock_protocol(struct sock *);
statfunc u16 get_sockaddr_family(struct sockaddr *);
statfunc struct in6_addr get_sock_v6_rcv_saddr(struct sock *);
statfunc struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *);
statfunc struct in6_addr get_sock_v6_daddr(struct sock *);
statfunc volatile unsigned char get_sock_state(struct sock *);
statfunc struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *);
statfunc struct sockaddr_un get_unix_sock_addr(struct unix_sock *);
statfunc int get_network_details_from_sock_v4(struct sock *, net_conn_v4_t *, int);
statfunc struct ipv6_pinfo *inet6_sk_own_impl(struct sock *, struct inet_sock *);
statfunc int get_network_details_from_sock_v6(struct sock *, net_conn_v6_t *, int);
statfunc int get_local_sockaddr_in_from_network_details(struct sockaddr_in *, net_conn_v4_t *, u16);
statfunc int
get_remote_sockaddr_in_from_network_details(struct sockaddr_in *, net_conn_v4_t *, u16);
statfunc int
get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *, net_conn_v6_t *, u16);
statfunc int
get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *, net_conn_v6_t *, u16);

// clang-format on

// FUNCTIONS

//
// Regular events related to network
//

statfunc u32 get_inet_rcv_saddr(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_rcv_saddr);
}

statfunc u32 get_inet_daddr(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_daddr);
}

statfunc u16 get_inet_sport(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_sport);
}

statfunc u16 get_inet_num(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_num);
}

statfunc u16 get_inet_dport(struct inet_sock *inet)
{
    return BPF_CORE_READ(inet, inet_dport);
}

statfunc struct sock *get_socket_sock(struct socket *socket)
{
    return BPF_CORE_READ(socket, sk);
}

statfunc u16 get_sock_family(struct sock *sock)
{
    return BPF_CORE_READ(sock, sk_family);
}

statfunc u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;

    // commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")
    struct sock___old *check = NULL;
    if (bpf_core_field_exists(check->__sk_flags_offset)) {
        check = (struct sock___old *) sock;
        bpf_core_read(&protocol, 1, (void *) (&check->sk_gso_max_segs) - 3);
    } else {
        protocol = BPF_CORE_READ(sock, sk_protocol);
    }

    return protocol;
}

statfunc u16 get_sockaddr_family(struct sockaddr *address)
{
    return BPF_CORE_READ(address, sa_family);
}

statfunc struct in6_addr get_sock_v6_rcv_saddr(struct sock *sock)
{
    return BPF_CORE_READ(sock, sk_v6_rcv_saddr);
}

statfunc struct in6_addr get_ipv6_pinfo_saddr(struct ipv6_pinfo *np)
{
    return BPF_CORE_READ(np, saddr);
}

statfunc struct in6_addr get_sock_v6_daddr(struct sock *sock)
{
    return BPF_CORE_READ(sock, sk_v6_daddr);
}

statfunc volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_core_read(
        (void *) &sk_state_own_impl, sizeof(sk_state_own_impl), (const void *) &sock->sk_state);
    return sk_state_own_impl;
}

statfunc struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_core_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

statfunc struct sockaddr_un get_unix_sock_addr(struct unix_sock *sock)
{
    struct unix_address *addr = BPF_CORE_READ(sock, addr);
    int len = BPF_CORE_READ(addr, len);
    struct sockaddr_un sockaddr = {};
    if (len <= sizeof(struct sockaddr_un)) {
        bpf_probe_read(&sockaddr, len, addr->name);
    }
    return sockaddr;
}

statfunc int get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = inet_sk(sk);

    if (!peer) {
        net_details->local_address = get_inet_rcv_saddr(inet);
        net_details->local_port = bpf_ntohs(get_inet_num(inet));
        net_details->remote_address = get_inet_daddr(inet);
        net_details->remote_port = get_inet_dport(inet);
    } else {
        net_details->remote_address = get_inet_rcv_saddr(inet);
        net_details->remote_port = bpf_ntohs(get_inet_num(inet));
        net_details->local_address = get_inet_daddr(inet);
        net_details->local_port = get_inet_dport(inet);
    }

    return 0;
}

statfunc struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk, struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

statfunc int get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    // inspired by 'inet6_getname(struct socket *sock, struct sockaddr *uaddr, int peer)'
    // reference: https://elixir.bootlin.com/linux/latest/source/net/ipv6/af_inet6.c#L509

    struct inet_sock *inet = inet_sk(sk);
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);

    struct in6_addr addr = {};
    addr = get_sock_v6_rcv_saddr(sk);
    if (ipv6_addr_any(&addr)) {
        addr = get_ipv6_pinfo_saddr(np);
    }

    // the flowinfo field can be specified by the user to indicate a network flow. how it is used by
    // the kernel, or whether it is enforced to be unique is not so obvious.  getting this value is
    // only supported by the kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any
    // case, leaving it with value of 0 won't affect our representation of network flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network interface from which
    // to send a packet. this only applies for link-local addresses, and is used only by the local
    // kernel.  getting this value is done by using the 'ipv6_iface_scope_id(const struct in6_addr
    // *addr, int iface)' function.  in any case, leaving it with value of 0 won't affect our
    // representation of network flows.
    net_details->scope_id = 0;

    if (peer) {
        net_details->local_address = get_sock_v6_daddr(sk);
        net_details->local_port = get_inet_dport(inet);
        net_details->remote_address = addr;
        net_details->remote_port = get_inet_sport(inet);
    } else {
        net_details->local_address = addr;
        net_details->local_port = get_inet_sport(inet);
        net_details->remote_address = get_sock_v6_daddr(sk);
        net_details->remote_port = get_inet_dport(inet);
    }

    return 0;
}

statfunc int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                        net_conn_v4_t *net_details,
                                                        u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

statfunc int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr,
                                                         net_conn_v4_t *net_details,
                                                         u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;

    return 0;
}

statfunc int get_local_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                         net_conn_v6_t *net_details,
                                                         u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->local_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->local_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

statfunc int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr,
                                                          net_conn_v6_t *net_details,
                                                          u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

statfunc bool fill_tuple_from_sock(struct sock *sk, tuple_t *tuple)
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
                &tuple->saddr.u6_addr32, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(
                &tuple->daddr.u6_addr32, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;

        default:
            return false;
    }

    tuple->sport = bpf_ntohs(get_inet_sport((struct inet_sock *) sk));
    tuple->dport = bpf_ntohs(get_inet_dport((struct inet_sock *) sk));

    return true;
}

statfunc bool fill_tuple_from_bpf_sock(struct bpf_sock *sk, tuple_t *tuple)
{
    tuple->family = sk->family;

    switch (sk->family) {
        case AF_INET:
            tuple->saddr.v4addr = sk->src_ip4;
            tuple->daddr.v4addr = sk->dst_ip4;

            break;
        case AF_INET6:
            __builtin_memcpy(tuple->saddr.u6_addr32, sk->src_ip6, 4);
            __builtin_memcpy(tuple->daddr.u6_addr32, sk->dst_ip6, 4);
            break;

        default:
            return false;
    }

    tuple->sport = sk->src_port;
    tuple->dport = bpf_ntohs(sk->dst_port); // Convert to host byte order (little endian).

    return true;
}

/*
 * Fills the given ip_key with the provided data. One thing to watch out for is, that the tuple
 * will have the local addr and port filled into the saddr/sport fields and remote will be in
 * daddr/dport.
 * TODO: Right now we do not track source and destination ports due high cardinality.
 */
statfunc bool load_ip_key(struct ip_key *key,
                          struct bpf_sock *sk,
                          nethdrs *nethdrs,
                          struct process_identity process_identity,
                          enum flow_direction flow_direction)
{
    if (unlikely(!key || !sk || !nethdrs)) {
        return false;
    }

    key->tuple.family = sk->family;

    __u8 proto = 0;

    switch (sk->family) {
        case AF_INET:
            proto = nethdrs->iphdrs.iphdr.protocol;

            // NOTE(patrick.pichler): The mismatch between saddr and daddr for ingress/egress is
            // on purpose, as we want to store the local addr/port in the saddr/sport and the
            // remote addr/port in daddr/dport.
            switch (flow_direction) {
                case INGRESS:
                    key->tuple.saddr.v4addr = nethdrs->iphdrs.iphdr.daddr;
                    key->tuple.daddr.v4addr = nethdrs->iphdrs.iphdr.saddr;
                    break;
                case EGRESS:
                    key->tuple.saddr.v4addr = nethdrs->iphdrs.iphdr.saddr;
                    key->tuple.daddr.v4addr = nethdrs->iphdrs.iphdr.daddr;
                    break;
            }
            break;
        case AF_INET6:
            proto = nethdrs->iphdrs.ipv6hdr.nexthdr;

            // NOTE(patrick.pichler): The mismatch between saddr and daddr for ingress/egress is
            // on purpose, as we want to store the local addr/port in the saddr/sport and the
            // remote addr/port in daddr/dport.
            switch (flow_direction) {
                case INGRESS:
                    __builtin_memcpy(key->tuple.saddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.daddr.in6_u.u6_addr32,
                                     4);
                    __builtin_memcpy(key->tuple.daddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.saddr.in6_u.u6_addr32,
                                     4);
                    break;
                case EGRESS:
                    __builtin_memcpy(key->tuple.saddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.saddr.in6_u.u6_addr32,
                                     4);
                    __builtin_memcpy(key->tuple.daddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.daddr.in6_u.u6_addr32,
                                     4);
                    break;
            }
            break;
        default:
            return false;
    }

    key->proto = proto;
    key->process_identity = process_identity;

    return true;
}

statfunc void
update_traffic_summary(struct traffic_summary *val, u64 bytes, enum flow_direction direction)
{
    if (unlikely(!val)) {
        return;
    }

    val->last_packet_ts = bpf_ktime_get_ns();

    switch (direction) {
        case INGRESS:
            __sync_fetch_and_add(&val->rx_bytes, bytes);
            __sync_fetch_and_add(&val->rx_packets, 1);
            break;
        case EGRESS:
            __sync_fetch_and_add(&val->tx_bytes, bytes);
            __sync_fetch_and_add(&val->tx_packets, 1);
            break;
    }
}

statfunc void record_netflow(struct __sk_buff *ctx,
                             task_context_t *task_ctx,
                             nethdrs *nethdrs,
                             enum flow_direction direction)
{
    process_identity_t identity = {
        .pid = task_ctx->pid,
        .pid_start_time = task_ctx->start_time,
        .cgroup_id = task_ctx->cgroup_id,
    };

    __builtin_memcpy(identity.comm, task_ctx->comm, sizeof(identity.comm));

    int zero = 0;
    config_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (!config)
        return;

    struct ip_key key = {0};

    if (!load_ip_key(&key, ctx->sk, nethdrs, identity, direction)) {
        return;
    }

    void *sum_map = bpf_map_lookup_elem(&network_traffic_buffer_map, &config->summary_map_index);
    if (!sum_map)
        return;

    struct traffic_summary *summary = bpf_map_lookup_elem(sum_map, &key);
    if (summary == NULL) {
        struct traffic_summary empty = {0};

        // We do not really care if the update fails, as it would mean, another thread added the
        // entry.
        bpf_map_update_elem(sum_map, &key, &empty, BPF_NOEXIST);

        summary = bpf_map_lookup_elem(sum_map, &key);
        if (summary == NULL) // Something went terribly wrong...
            return;
    }

    update_traffic_summary(summary, ctx->len, direction);
}

#endif
