package ebpftracer

import (
	"errors"
	"net/netip"

	"github.com/castai/kvisor/pkg/dnscache"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	"golang.org/x/time/rate"
)

var (
	FilterPass                    error = nil
	FilterErrRateLimit                  = errors.New("rate limit")
	FilterErrEmptyDNSResponse           = errors.New("empty dns response")
	FilterErrDNSDuplicateDetected       = errors.New("dns duplicate detected")
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

			return FilterPass
		}
	}
}

func RateLimit(spec RateLimitPolicy) EventFilterGenerator {
	return func() EventFilter {
		rateLimiter := newRateLimiter(spec)

		return func(event *types.Event) error {
			if rateLimiter.Allow() {
				return FilterPass
			}

			return FilterErrRateLimit
		}
	}
}

func RateLimitPrivateIP(spec RateLimitPolicy) EventFilterGenerator {
	return func() EventFilter {
		rateLimiter := newRateLimiter(spec)

		return func(event *types.Event) error {
			tcpArgs, ok := event.Args.(types.SockSetStateArgs)
			if !ok {
				return FilterPass
			}
			if !isPrivateNetwork(tcpArgs.Tuple.Dst.Addr()) {
				return FilterPass
			}

			if rateLimiter.Allow() {
				return FilterPass
			}

			return FilterErrRateLimit
		}
	}
}

func SkipPrivateIP() EventFilterGenerator {
	return func() EventFilter {
		return func(event *types.Event) error {
			tcpArgs, ok := event.Args.(types.SockSetStateArgs)
			if !ok {
				return FilterPass
			}
			if !isPrivateNetwork(tcpArgs.Tuple.Dst.Addr()) {
				return FilterPass
			}
			return FilterErrRateLimit
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
func DeduplicateDNSEventsPreFilter(log *logging.Logger, dnsCache *dnscache.Cache) PreEventFilterGenerator {
	return func() PreEventFilter {
		return func(ctx *types.EventContext, dec *decoder.Decoder) (types.Args, error) {
			if ctx.EventID != events.NetPacketDNSBase {
				return nil, FilterPass
			}

			dns, details, err := dec.DecodeDNSAndDetails()
			if err != nil {
				return nil, err
			}

			var question string
			var totalIPsFound, totalCachesFound int
			for _, answer := range dns.Answers {
				if len(answer.IP) == 0 {
					continue
				}
				ip, ok := netip.AddrFromSlice(answer.IP)
				if !ok {
					continue
				}
				totalIPsFound++
				key := dnsCache.CalcKey(ctx.CgroupID, ip)
				if _, found := dnsCache.Get(key); found {
					totalCachesFound++
				} else {
					// Since we need to make a copy of dns question, make it once only here if record is not found in the cache.
					if question == "" {
						question = string(dns.Questions[0].Name)
					}
					dnsCache.Add(key, question)
				}
			}
			if totalIPsFound == totalCachesFound && totalCachesFound != 0 {
				return nil, FilterErrDNSDuplicateDetected
			}

			return types.NetPacketDNSBaseArgs{
				Payload: decoder.ToProtoDNS(&details, dns),
			}, FilterPass
		}
	}
}

func isPrivateNetwork(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}
