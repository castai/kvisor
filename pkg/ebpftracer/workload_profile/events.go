package workloadprofile

import (
	"context"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

type WorkloadProfileEngine struct {
	log        *logging.Logger
	eventsChan chan *types.Event
}

type WorkloadProfileEngineConfig struct {
	InputChanSize int `validate:"required" json:"inputChanSize"`
}

func NewEngine(log *logging.Logger, cfg WorkloadProfileEngineConfig) *WorkloadProfileEngine {
	return &WorkloadProfileEngine{
		log:        log.WithField("component", "workload_profile_engine"),
		eventsChan: make(chan *types.Event, cfg.InputChanSize),
	}
}

func (e *WorkloadProfileEngine) Run(ctx context.Context) error {
	e.log.Infof("running")
	defer e.log.Infof("stopping")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event := <-e.Events():
			e.handleEvent(event)
		}
	}
}

func (e *WorkloadProfileEngine) Events() <-chan *types.Event {
	return e.eventsChan
}

func (e *WorkloadProfileEngine) QueueEvent(event *types.Event) {
	select {
	case e.eventsChan <- event:
	default:
	}
}

func (e *WorkloadProfileEngine) handleEvent(event *types.Event) {
	switch args := event.Args.(type) {
	case types.WorkloadProfileNewCapabilityArgs:
		e.log.Debugf("received workload profile new capability event: pod_name=%s, capability=%d, cgroup=%d",
			event.Container.PodName, args.Cap, event.Context.CgroupID)
	default:
		e.log.Errorf("unknown workload profile event: %d", event.Context.EventID)
	}
}
