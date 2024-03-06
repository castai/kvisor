package ebpftracer

import (
	"errors"
	"log/slog"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/hashicorp/golang-lru/v2/expirable"
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

		return func(event *castpb.Event) error {
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

		return func(event *castpb.Event) error {
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
		return func(event *castpb.Event) error {
			if event.GetEventType() != castpb.EventType_EVENT_DNS {
				return FilterPass
			}

			dnsEvent := event.GetDns()

			if dnsEvent == nil {
				l.Warn("retreived invalid event for event type dns")
				return FilterPass
			}

			if len(dnsEvent.Answers) == 0 {
				return FilterErrEmptyDNSResponse
			}

			return FilterPass
		}
	}
}

// DeduplicateDnsEvents creates a filter that will drop any DNS event with questions already seen in `ttl` time
func DeduplicateDnsEvents(l *logging.Logger, size int, ttl time.Duration) EventFilterGenerator {
	type cacheValue struct{}

	return func() EventFilter {
		cache := expirable.NewLRU[string, cacheValue](size, nil, ttl)

		return func(event *castpb.Event) error {
			if event.GetEventType() != castpb.EventType_EVENT_DNS {
				return FilterPass
			}

			dnsEvent := event.GetDns()

			if dnsEvent == nil {
				l.Warn("received invalid event for event type dns")
				return FilterPass
			}

			cacheKey := dnsEvent.DNSQuestionDomain
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
