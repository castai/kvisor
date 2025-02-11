#ifndef __COMMON_NETWORK_H__
#define __COMMON_NETWORK_H__

#include "types.h"
#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_endian.h>

#include <common/common.h>

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
statfunc bool fill_tuple(struct sock *sk, tuple_t *tuple);
statfunc bool fill_tuple_from_bpf_sock(struct bpf_sock *sk, tuple_t *tuple);

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

statfunc bool fill_tuple(struct sock *sk, tuple_t *tuple)
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
            // __builtin_memcpy is not compatible with bpf_sock so we have to copy the fields
            tuple->saddr.u6_addr32[0] = sk->src_ip6[0];
            tuple->saddr.u6_addr32[1] = sk->src_ip6[1];
            tuple->saddr.u6_addr32[2] = sk->src_ip6[2];
            tuple->saddr.u6_addr32[3] = sk->src_ip6[3];

            tuple->daddr.u6_addr32[0] = sk->dst_ip6[0];
            tuple->daddr.u6_addr32[1] = sk->dst_ip6[1];
            tuple->daddr.u6_addr32[2] = sk->dst_ip6[2];
            tuple->daddr.u6_addr32[3] = sk->dst_ip6[3];
            break;
        default:
            return false;
    }

    tuple->sport = sk->src_port;
    tuple->dport = bpf_ntohs(sk->dst_port); // Convert to host byte order (little endian).

    return true;
}

statfunc bool is_addr_public(const addr_t *addr, __u16 family) {
    switch (family) {
        case AF_INET: {
            __u32 be_addr = bpf_htonl(addr->v4addr); // Convert to network byte order

            // Private IPv4 ranges
            if ((be_addr >= 0x0A000000 && be_addr <= 0x0AFFFFFF) ||   // 10.0.0.0/8
                (be_addr >= 0xAC100000 && be_addr <= 0xAC1FFFFF) ||   // 172.16.0.0/12
                (be_addr >= 0xC0A80000 && be_addr <= 0xC0A8FFFF)) {  // 192.168.0.0/16
                return false;
            }

            // Loopback IPv4
            if (be_addr >= 0x7F000000 && be_addr <= 0x7F0000FF) { // 127.0.0.0/8
                return false;
            }

            // Multicast IPv4
            if (be_addr >= 0xE0000000 && be_addr <= 0xEFFFFFFF) { // 224.0.0.0/4
                return false;
            }

            // Link-local IPv4 - 169.254.0.0/16)
            if (be_addr >= 0xA9FE0000 && be_addr <= 0xA9FEFFFF) {
                return false;
            }

            return true; // Public IPv4
        }
        case AF_INET6: {
            // Loopback IPv6 ::1
            if (addr->u6_addr32[0] == 0 && addr->u6_addr32[1] == 0 &&
                addr->u6_addr32[2] == 0 && addr->u6_addr32[3] == bpf_htonl(1)) {
                return false;
            }

            // Link-local addresses fe80::/10
            if ((bpf_ntohl(addr->u6_addr32[0]) & 0xffc00000) == 0xfe800000) {
                return false;
            }

             // Site-local addresses fec0::/10 (deprecated, but still checked for coverage)
            if ((bpf_ntohl(addr->u6_addr32[0]) & 0xffc00000) == 0xfec00000) {
                return false;
            }

            // Unique local addresses fc00::/7- covers most private IPv6.

            if ((bpf_ntohl(addr->u6_addr32[0]) & 0xfe000000) == 0xfc000000) {
                 return false;
            }
            // Multicast addresses ff00::/8
            if ((bpf_ntohl(addr->u6_addr32[0]) & 0xff000000) == 0xff000000) {
                return false;
            }

            return true; // Public IPv6
        }
        default:
            // Unknown address family, treat as non-public to be safe.
            return false;
    }
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
                                     sizeof(key->tuple.saddr.u6_addr32));
                    __builtin_memcpy(key->tuple.daddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.saddr.in6_u.u6_addr32,
                                     sizeof(key->tuple.daddr.u6_addr32));
                    break;
                case EGRESS:
                    __builtin_memcpy(key->tuple.saddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.saddr.in6_u.u6_addr32,
                                     sizeof(key->tuple.saddr.u6_addr32));
                    __builtin_memcpy(key->tuple.daddr.u6_addr32,
                                     nethdrs->iphdrs.ipv6hdr.daddr.in6_u.u6_addr32,
                                     sizeof(key->tuple.daddr.u6_addr32));
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

#endif
