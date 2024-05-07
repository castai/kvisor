package ebpftracer

import (
	"errors"
	"log/slog"
	"time"

	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cespare/xxhash"
	"github.com/elastic/go-freelru"
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

// PreRateLimit creates an pre event filter that limits the amount of events that will be
// processed accoring to the specified limits
func PreRateLimit(spec RateLimitPolicy) PreEventFilterGenerator {
	return func() PreEventFilter {
		rateLimiter := newRateLimiter(spec)

		return func(ctx *types.EventContext) error {
			if rateLimiter.Allow() {
				return FilterPass
			}

			return FilterErrRateLimit
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

// FilterEmptyDnsAnswers will drop any DNS event, that is missing an answer section
func FilterEmptyDnsAnswers(l *logging.Logger) EventFilterGenerator {
	return func() EventFilter {
		return func(event *types.Event) error {
			if event.Context.EventID != events.NetPacketDNSBase {
				return FilterPass
			}

			dnsEventArgs, ok := event.Args.(types.NetPacketDNSBaseArgs)
			if !ok {
				return FilterPass
			}

			if dnsEventArgs.Payload == nil {
				l.Warn("retreived invalid event for event type dns")
				return FilterPass
			}

			if len(dnsEventArgs.Payload.Answers) == 0 {
				return FilterErrEmptyDNSResponse
			}

			return FilterPass
		}
	}
}

// more hash function in https://github.com/elastic/go-freelru/blob/main/bench/hash.go
func hashStringXXHASH(s string) uint32 {
	return uint32(xxhash.Sum64String(s))
}

// DeduplicateDnsEvents creates a filter that will drop any DNS event with questions already seen in `ttl` time
func DeduplicateDnsEvents(l *logging.Logger, size uint32, ttl time.Duration) EventFilterGenerator {
	type cacheValue struct{}

	return func() EventFilter {
		cache, err := freelru.New[string, cacheValue](size, hashStringXXHASH)
		// err is only ever returned on configuration issues. There is nothing we can really do here, besides
		// panicing and surfacing the error to the user.
		if err != nil {
			panic(err)
		}

		cache.SetLifetime(ttl)

		return func(event *types.Event) error {
			if event.Context.EventID != events.NetPacketDNSBase {
				return FilterPass
			}

			dnsEventArgs, ok := event.Args.(types.NetPacketDNSBaseArgs)
			if !ok {
				return FilterPass
			}

			if dnsEventArgs.Payload == nil {
				l.Warn("received invalid event for event type dns")
				return FilterPass
			}

			cacheKey := dnsEventArgs.Payload.DNSQuestionDomain
			if cache.Contains(cacheKey) {
				if l.IsEnabled(slog.LevelDebug) {
					l.WithField("cachekey", cacheKey).Debug("dropping DNS event")
				}
				return FilterErrDNSDuplicateDetected
			}

			cache.Add(cacheKey, cacheValue{})

			return FilterPass
		}
	}
}
