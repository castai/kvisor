#ifndef __COMMON_NAMESPACES_H__
#define __COMMON_NAMESPACES_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc u32 get_mnt_ns_id(struct nsproxy *);

// FUNCTIONS

statfunc u32 get_mnt_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, mnt_ns, ns.inum);
}

#endif
