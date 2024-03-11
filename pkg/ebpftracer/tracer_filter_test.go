package ebpftracer

import (
	"context"
	"log/slog"
	"testing"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestAllowedByPolicyShouldBePerCgroup(t *testing.T) {
	r := require.New(t)

	callerMap := map[int]struct{}{}
	counter := 0

	var testPolicyFilterGenerator EventFilterGenerator = func() EventFilter {
		counter++

		// we need to capture the value of counter, as otherwise it will be the same for each invocation
		return func(c int) EventFilter {
			return func(event *castpb.Event) error {
				callerMap[c] = struct{}{}
				return FilterPass
			}
		}(counter)
	}

	tracer := buildTestTracer()
	applyTestPolicy(tracer, &Policy{
		Events: []*EventPolicy{
			{
				ID:              events.TestEvent,
				FilterGenerator: testPolicyFilterGenerator,
			},
		},
	})

	err := tracer.allowedByPolicy(events.TestEvent, 22, &castpb.Event{
		EventType:   castpb.EventType_UNKNOWN,
		Timestamp:   0,
		ProcessName: "test",
	})
	r.NoError(err)

	err = tracer.allowedByPolicy(events.TestEvent, 66, &castpb.Event{
		EventType:   castpb.EventType_UNKNOWN,
		Timestamp:   0,
		ProcessName: "test",
	})

	r.NoError(err)
	r.Len(callerMap, 2)
}

func TestAllowedByPrePolicyShouldBePerCgroup(t *testing.T) {
	r := require.New(t)
	callerMap := map[int]struct{}{}
	counter := 0

	var testPolicyFilterGenerator PreEventFilterGenerator = func() PreEventFilter {
		counter++

		// we need to capture the value of counter, as otherwise it will be the same for each invocation
		return func(c int) PreEventFilter {
			return func(ctx *types.EventContext) error {
				callerMap[c] = struct{}{}
				return FilterPass
			}
		}(counter)
	}

	tracer := buildTestTracer()
	applyTestPolicy(tracer, &Policy{
		Events: []*EventPolicy{
			{
				ID:                 events.TestEvent,
				PreFilterGenerator: testPolicyFilterGenerator,
			},
		},
	})

	err := tracer.allowedByPolicyPre(&types.EventContext{
		EventID:  events.TestEvent,
		CgroupID: 10,
	})
	r.NoError(err)

	err = tracer.allowedByPolicyPre(&types.EventContext{
		EventID:  events.TestEvent,
		CgroupID: 20,
	})

	r.NoError(err)
	r.Len(callerMap, 2)
}

type MockContainerClient struct {
	ContainerGetter func(ctx context.Context, cgroup uint64) (*containers.Container, error)
	CgroupCleaner   func(cgroup uint64)
}

func (c *MockContainerClient) GetContainerForCgroup(ctx context.Context, cgroup uint64) (*containers.Container, error) {
	if c.ContainerGetter == nil {
		return nil, nil
	}

	return c.ContainerGetter(ctx, cgroup)
}

func (c *MockContainerClient) CleanupCgroup(cgroup uint64) {
	if c.ContainerGetter == nil {
		return
	}

	c.CgroupCleaner(cgroup)
}

func buildTestTracer() *Tracer {
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	tracer := &Tracer{
		log: log,
		cfg: Config{
			EnrichEvent: func(er *enrichment.EnrichRequest) bool {
				return false
			},
			ContainerClient: &MockContainerClient{
				ContainerGetter: func(ctx context.Context, cg uint64) (*containers.Container, error) {
					return &containers.Container{
						CgroupID: cg,
						Cgroup: &cgroup.Cgroup{
							Id:      cg,
							Version: cgroup.V1,
						},
					}, nil
				},
			},
		},
		eventsChan:        make(chan *castpb.Event, 10),
		eventPoliciesMap:  map[events.ID]*EventPolicy{},
		cgroupEventPolicy: map[uint64]map[events.ID]*cgroupEventPolicy{},
		dnsPacketParser:   &layers.DNS{},
		eventsSet:         newEventsDefinitionSet(&tracerObjects{}),
	}
	return tracer
}

func applyTestPolicy(tracer *Tracer, policy *Policy) {
	tracer.policy = policy
	for _, event := range policy.Events {
		tracer.eventPoliciesMap[event.ID] = event
	}
}
