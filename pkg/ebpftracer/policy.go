package ebpftracer

import (
	"time"

	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

type Policy struct {
	SystemEvents    []events.ID // List of events required for internal tasks such as cache cleanup
	SignatureEvents []events.ID
	Events          []*EventPolicy
	Output          PolicyOutputConfig
}

// PreEventFilter allows for filtering of events coming from the kernel before they are decoded.
// Parsed args should be returned if filter passes.
type PreEventFilter func(ctx *types.EventContext, decoder *decoder.Decoder) (types.Args, error)

// EventFilterGenerator Produces an pre event filter for each call
type PreEventFilterGenerator func() PreEventFilter

// EventFilter allows for filtering of events before they are send to the server
type EventFilter func(event *types.Event) error

// EventFilterGenerator Produces an event filter for each call
type EventFilterGenerator func() EventFilter

// KernelEventFilter is a placeholder and currently used for documentation purposes only.
// Each used filter is describer with explanation how it's implemented in the kernel.
type KernelEventFilter struct {
	Name        string
	Description string
}

type EventPolicy struct {
	ID                 events.ID
	PreFilterGenerator PreEventFilterGenerator
	FilterGenerator    EventFilterGenerator
	KernelFilters      []KernelEventFilter
}

// RateLimitPolicy allows to configure event rate limiting.
type RateLimitPolicy struct {
	// If interval is set rate limit can be used as interval based sampling. In such case burst is always 1.
	Interval time.Duration

	// Rate is events per second.
	Rate  float64
	Burst int
}

type LRUPolicy struct {
	Size int
}

type PolicyOutputConfig struct {
	RelativeTime bool
	ExecHash     bool

	ParseArguments    bool
	ParseArgumentsFDs bool
	EventsSorting     bool
}

func newCgroupEventPolicy(policy *EventPolicy) *cgroupEventPolicy {
	result := &cgroupEventPolicy{}

	if policy.PreFilterGenerator != nil {
		result.preFilter = policy.PreFilterGenerator()
	}

	if policy.FilterGenerator != nil {
		result.filter = policy.FilterGenerator()
	}

	return result
}

// cgroupEventPolicy is internal structure to work with event policies per cgroups.
type cgroupEventPolicy struct {
	preFilter PreEventFilter
	filter    EventFilter
}
