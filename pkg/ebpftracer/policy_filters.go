package ebpftracer

import (
	"errors"
	"time"

	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/net/iputil"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/samber/lo"
	"golang.org/x/time/rate"
)

var (
	ErrFilterPass              error = nil
	ErrFilterRateLimit               = errors.New("rate limit")
	ErrErrEmptyDNSResponse           = errors.New("empty dns response")
	ErrErrDNSDuplicateDetected       = errors.New("dns duplicate detected")
)

// GlobalPreEventFilterGenerator always returns the given filter on each generator invocation. This is useful,
// if you want some global filtering across cgroups.
func GlobalPreEventFilterGenerator(filter PreEventFilter) PreEventFilterGenerator {
	return func() PreEventFilter {
		return filter
	}
}

// GlobalEventFilterGenerator always returns the given filter on each generator invocation. This is useful,
// if you want some global filtering across cgroups.
func GlobalEventFilterGenerator(filter EventFilter) EventFilterGenerator {
	return func() EventFilter {
		return filter
	}
}

func FilterAnd(filtersGenerators ...EventFilterGenerator) EventFilterGenerator {
	return func() EventFilter {
		filters := lo.Map(filtersGenerators, func(generator EventFilterGenerator, index int) EventFilter {
			return generator()
		})

		return func(event *types.Event) error {
			for _, f := range filters {
				if err := f(event); err != nil {
					return err
				}
			}

			return ErrFilterPass
		}
	}
}

func RateLimit(spec RateLimitPolicy) EventFilterGenerator {
	return func() EventFilter {
		rateLimiter := newRateLimiter(spec)

		return func(event *types.Event) error {
			if rateLimiter.Allow() {
				return ErrFilterPass
			}

			return ErrFilterRateLimit
		}
	}
}

func RateLimitPrivateIP(spec RateLimitPolicy) EventFilterGenerator {
	return func() EventFilter {
		rateLimiter := newRateLimiter(spec)

		return func(event *types.Event) error {
			tcpArgs, ok := event.Args.(types.SockSetStateArgs)
			if !ok {
				return ErrFilterPass
			}
			if !iputil.IsPrivateNetwork(tcpArgs.Tuple.Dst.Addr()) {
				return ErrFilterPass
			}

			if rateLimiter.Allow() {
				return ErrFilterPass
			}

			return ErrFilterRateLimit
		}
	}
}

func SkipPrivateIP() EventFilterGenerator {
	return func() EventFilter {
		return func(event *types.Event) error {
			tcpArgs, ok := event.Args.(types.SockSetStateArgs)
			if !ok {
				return ErrFilterPass
			}
			if !iputil.IsPrivateNetwork(tcpArgs.Tuple.Dst.Addr()) {
				return ErrFilterPass
			}
			return ErrFilterRateLimit
		}
	}
}

func newRateLimiter(spec RateLimitPolicy) *rate.Limiter {
	var limit rate.Limit

	if spec.Interval != 0 {
		limit = rate.Every(spec.Interval)
		spec.Burst = 1
	} else {
		limit = rate.Limit(spec.Rate)
		if spec.Burst == 0 {
			spec.Burst = 1
		}
	}

	rateLimiter := rate.NewLimiter(limit, spec.Burst)
	return rateLimiter
}

// DeduplicateDNSEventsPreFilter skips sending dns events which are already in the local per cgroup cache.
func DeduplicateDNSEventsPreFilter(log *logging.Logger, size uint32, ttl time.Duration) PreEventFilterGenerator {
	type cacheValue struct{}

	return func() PreEventFilter {
		cache, err := freelru.New[uint64, cacheValue](size, func(key uint64) uint32 {
			return uint32(key) //nolint:gosec
		})
		// err is only ever returned on configuration issues. There is nothing we can really do here, besides
		// panicing and surfacing the error to the user.
		if err != nil {
			panic(err)
		}

		cache.SetLifetime(ttl)

		return func(ctx *types.EventContext, dec *decoder.Decoder) (types.Args, error) {
			if ctx.EventID != events.NetPacketDNSBase {
				return nil, ErrFilterPass
			}

			dns, details, err := dec.DecodeDNSAndDetails()
			if err != nil {
				return nil, err
			}

			// Cache dns by dns question. Cached records are dropped.
			cacheKey := xxhash.Sum64(dns.Questions[0].Name)
			if cache.Contains(cacheKey) {
				return nil, ErrErrDNSDuplicateDetected
			}
			cache.Add(cacheKey, cacheValue{})

			return types.NetPacketDNSBaseArgs{
				Payload: decoder.ToProtoDNS(&details, dns),
			}, ErrFilterPass
		}
	}
}
