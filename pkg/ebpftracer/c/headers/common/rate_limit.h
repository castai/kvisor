#ifndef __COMMON_RATELIMIT_H__
#define __COMMON_RATELIMIT_H__

#include <common/common.h>

typedef struct rate_limiter {
    u64 last_refill_time;
    u64 current_tokens;
    u32 rps;
    u32 burst;
} rate_limiter_t;

statfunc rate_limiter_t new_rate_limiter(u32 rps, u32 burst)
{
    rate_limiter_t limiter = {
        .last_refill_time = bpf_ktime_get_ns(),
        .current_tokens = burst,
        .rps = rps,
        .burst = burst,
    };
    return limiter;
}

statfunc bool rate_limiter_allow(rate_limiter_t *rt, u64 tokens_needed) {
    u64 current_time = bpf_ktime_get_ns();
    u64 time_delta_ns = current_time - rt->last_refill_time;

    // Refill tokens.
    u64 tokens_to_add = (time_delta_ns * rt->rps) / 1000000000ULL; // NS per second.
    rt->current_tokens += tokens_to_add;

    // Cap tokens at burst size.
    if (rt->current_tokens > rt->burst) {
        rt->current_tokens = rt->burst;
    }

    rt->last_refill_time = current_time;

    if (rt->current_tokens >= tokens_needed) {
        rt->current_tokens -= tokens_needed;
        return true;
    }
    return false;
}

#endif
