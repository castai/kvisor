#ifndef __COMMON_SIGNATURES_H__
#define __COMMON_SIGNATURES_H__

#include <vmlinux.h>

#include <bpf/bpf_tracing.h>

#include <common/arguments.h>
#include <common/buffer.h>
#include <common/context.h>
#include <common/filtering.h>

statfunc bool is_stdio_via_socket(u64 socketfd, u16 sa_fam)
{
    if (socketfd != 0 && socketfd != 1 && socketfd != 2) {
        return false;
    }

    switch (sa_fam) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return false;
    }

    return true;
}

#endif
