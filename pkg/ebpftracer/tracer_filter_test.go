package ebpftracer

import (
	"context"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/castai/logging"
)

func TestAllowedByPolicyShouldBePerCgroup(t *testing.T) {
	r := require.New(t)

	callerMap := map[int]struct{}{}
	counter := 0

	var testPolicyFilterGenerator EventFilterGenerator = func() EventFilter {
		counter++

		// we need to capture the value of counter, as otherwise it will be the same for each invocation
		return func(c int) EventFilter {
			return func(event *types.Event) error {
				callerMap[c] = struct{}{}
				return ErrFilterPass
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

	err := tracer.getFilterPolicy(events.TestEvent, 22).filter(&types.Event{})
	r.NoError(err)

	err = tracer.getFilterPolicy(events.TestEvent, 64).filter(&types.Event{})
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
			return func(ctx *types.EventContext, dec *decoder.Decoder) (types.Args, error) {
				callerMap[c] = struct{}{}
				return nil, ErrFilterPass
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

	_, err := tracer.getFilterPolicy(events.TestEvent, 22).preFilter(&types.EventContext{}, nil)
	r.NoError(err)

	_, err = tracer.getFilterPolicy(events.TestEvent, 64).preFilter(&types.EventContext{}, nil)
	r.NoError(err)

	r.NoError(err)
	r.Len(callerMap, 2)
}

var _ CgroupClient = MockCgroupClient{}

type MockCgroupClient struct {
	CgroupLoader            func(id cgroup.ID, path string)
	CgroupCleaner           func(cgroup cgroup.ID)
	DefaultHierarchyChecker func(hierarchyID uint32) bool
}

func (m MockCgroupClient) GetCgroupsRootPath() string {
	return "/sys/fs/cgroup"
}

func (m MockCgroupClient) IsDefaultHierarchy(hierarchyID uint32) bool {
	if m.DefaultHierarchyChecker != nil {
		return m.DefaultHierarchyChecker(hierarchyID)
	}

	return true
}

func (m MockCgroupClient) CleanupCgroup(cgroup cgroup.ID) {
	if m.CgroupCleaner != nil {
		m.CgroupCleaner(cgroup)
	}
}

func (m MockCgroupClient) LoadCgroup(id cgroup.ID, path string) bool {
	if m.CgroupLoader != nil {
		m.CgroupLoader(id, path)
	}
	return true
}

type MockContainerClient struct {
	ContainerGetter func(ctx context.Context, cgroup uint64) (*containers.Container, error)
	CgroupCleaner   func(cgroup uint64)
}

func (c *MockContainerClient) AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *containers.Container, rerrr error) {
	return nil, nil
}

func (c *MockContainerClient) GetOrLoadContainerByCgroupID(ctx context.Context, cgroup uint64) (*containers.Container, error) {
	if c.ContainerGetter == nil {
		return nil, nil
	}

	return c.ContainerGetter(ctx, cgroup)
}

func (c *MockContainerClient) CleanupByCgroupID(cgroup uint64) {
	if c.CgroupCleaner == nil {
		return
	}

	c.CgroupCleaner(cgroup)
}

type tracerOption func(*Tracer)

func buildTestTracer(options ...tracerOption) *Tracer {
	log := logging.New()

	tracer := &Tracer{
		log: log,
		cfg: Config{
			ContainerClient: &MockContainerClient{
				ContainerGetter: func(ctx context.Context, cg uint64) (*containers.Container, error) {
					return &containers.Container{
						CgroupID: cg,
						Cgroup: &cgroup.Cgroup{
							Id: cg,
						},
					}, nil
				},
			},
			CgroupClient:         &MockCgroupClient{},
			ProcessTreeCollector: processtree.NewNoop(),
		},
		eventsChan:        make(chan *types.Event, 10),
		eventPoliciesMap:  map[events.ID]*EventPolicy{},
		cgroupEventPolicy: map[uint64]map[events.ID]*cgroupEventPolicy{},
		dnsPacketParser:   &layers.DNS{},
		eventsSet:         newEventsDefinitionSet(&tracerObjects{}),
		removedCgroups:    make(map[uint64]struct{}),
	}

	for _, option := range options {
		option(tracer)
	}

	return tracer
}

func applyTestPolicy(tracer *Tracer, policy *Policy) {
	tracer.policy = policy
	for _, event := range policy.Events {
		tracer.eventPoliciesMap[event.ID] = event
	}
}
