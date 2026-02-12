package ebpftracer

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/httpmetrics"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/ebpf"
)

// ErrPanic indicating that the resulting error was caught from a panic
var ErrPanic = errors.New("encountered panic")

func (t *Tracer) decodeAndExportEvent(ctx context.Context, ebpfMsgDecoder *decoder.Decoder) (rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	var eventCtx types.EventContext
	if err := ebpfMsgDecoder.DecodeContext(&eventCtx); err != nil {
		return fmt.Errorf("decoding context: %w", err)
	}

	eventId := eventCtx.EventID
	def := t.eventsSet[eventCtx.EventID]
	metrics.AgentPulledEventsBytesTotal.WithLabelValues(def.name).Add(float64(ebpfMsgDecoder.BuffLen()))
	metrics.AgentPulledEventsTotal.WithLabelValues(def.name).Inc()

	// Process special events for cgroup creation and removal.
	// These are system events which are not send down via events pipeline.
	switch eventId {
	case events.CgroupMkdir:
		parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, eventId)
		if err != nil {
			return fmt.Errorf("parsing event %d args: %w", eventId, err)
		}
		return t.handleCgroupMkdirEvent(&eventCtx, parsedArgs)
	case events.CgroupRmdir:
		parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, eventId)
		if err != nil {
			return fmt.Errorf("parsing event %d args: %w", eventId, err)
		}
		return t.handleCgroupRmdirEvent(parsedArgs)
	default:
	}

	container, err := t.cfg.ContainerClient.GetOrLoadContainerByCgroupID(ctx, eventCtx.CgroupID)
	if err != nil {
		// We ignore any event not belonging to a container for now.
		if errors.Is(err, containers.ErrContainerNotFound) {
			err := t.MuteEventsFromCgroup(eventCtx.CgroupID, fmt.Sprintf("container not found during received event %s", def.name))
			if err != nil {
				return fmt.Errorf("cannot mute events for cgroup %d: %w", eventCtx.CgroupID, err)
			}
			return nil
		}
		return fmt.Errorf("cannot get container for cgroup %d: %w", eventCtx.CgroupID, err)
	}

	filterPolicy := t.getFilterPolicy(eventCtx.EventID, eventCtx.CgroupID)

	var parsedArgs types.Args
	if filterPolicy != nil && filterPolicy.preFilter != nil {
		parsedArgs, err = filterPolicy.preFilter(&eventCtx, ebpfMsgDecoder)
		if err != nil {
			metrics.AgentSkippedEventsTotal.WithLabelValues(def.name).Inc()
			return nil
		}
	}

	if parsedArgs == nil {
		parsedArgs, err = decoder.ParseArgs(ebpfMsgDecoder, eventId)
		if err != nil {
			return fmt.Errorf("parsing event %d args: %w", eventId, err)
		}
	}

	eventCtx.Ts = t.bootTime + eventCtx.Ts
	event := &types.Event{
		Context:   &eventCtx,
		Container: container,
		Args:      parsedArgs,
	}

	switch eventId {
	case events.SchedProcessExec:
		t.handleSchedProcessExecEvent(&eventCtx)
	case events.SchedProcessExit:
		t.handleSchedProcessExitEvent(&eventCtx)
	default:
	}

	if _, found := t.signatureEventMap[eventId]; found {
		t.cfg.SignatureEngine.QueueEvent(event)
	}

	// Do not process an event we do not have a policy set any further.
	if _, found := t.eventPoliciesMap[eventId]; !found && t.policy != nil {
		metrics.AgentSkippedEventsTotal.WithLabelValues(def.name).Inc()
		return nil
	}

	if filterPolicy != nil && filterPolicy.filter != nil {
		if err := filterPolicy.filter(event); err != nil {
			metrics.AgentSkippedEventsTotal.WithLabelValues(def.name).Inc()
			return nil
		}
	}

	// Fill dns cache from dns events
	if eventId == events.NetPacketDNSBase {
		if err := t.handleNetPacketDNSEvent(&eventCtx, parsedArgs); err != nil {
			t.log.Errorf("handling dns event: %v", err)
		}
	}

	// Process HTTP events for metrics collection
	if eventId == events.NetPacketHTTPBase {
		t.handleNetPacketHTTPEvent(event, parsedArgs)
	}

	select {
	case t.eventsChan <- event:
	default:
		metrics.AgentDroppedEventsTotal.WithLabelValues(def.name).Inc()
	}

	return nil
}

func (t *Tracer) handleCgroupMkdirEvent(eventCtx *types.EventContext, parsedArgs types.Args) error {
	args := parsedArgs.(types.CgroupMkdirArgs)
	// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
	if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
		return nil
	}

	t.log.Debugf("received cgroup mkdir event cgroup=%d, path=%s", args.CgroupId, args.CgroupPath)

	if !t.cfg.CgroupClient.LoadCgroup(args.CgroupId, args.CgroupPath) {
		return nil
	}
	if _, err := t.cfg.ContainerClient.AddContainerByCgroupID(context.Background(), args.CgroupId); err != nil {
		if errors.Is(err, containers.ErrContainerNotFound) {
			err := t.MuteEventsFromCgroup(eventCtx.CgroupID, fmt.Sprintf("container not found during mkdir, path=%s", args.CgroupPath))
			if err != nil {
				return fmt.Errorf("cannot mute events for cgroup %d: %w", eventCtx.CgroupID, err)
			}
			return nil
		}
		t.log.Errorf("cannot add container to cgroup=%d, path=%s: %v", args.CgroupId, args.CgroupPath, err)
	}
	return nil
}

func (t *Tracer) handleCgroupRmdirEvent(parsedArgs types.Args) error {
	args := parsedArgs.(types.CgroupRmdirArgs)

	t.queueCgroupForRemoval(args.CgroupId)
	err := t.UnmuteEventsFromCgroup(args.CgroupId)
	if err != nil {
		return fmt.Errorf("cannot remove cgroup %d from mute map: %w", args.CgroupId, err)
	}
	return nil
}

func (t *Tracer) handleSchedProcessExecEvent(eventCtx *types.EventContext) {
	if eventCtx.Pid == 1 {
		t.cfg.MountNamespacePIDStore.ForceAddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
	} else {
		t.cfg.MountNamespacePIDStore.AddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
	}
}

func (t *Tracer) handleSchedProcessExitEvent(eventCtx *types.EventContext) {
	if eventCtx.Pid == 1 {
		t.cfg.MountNamespacePIDStore.RemoveBucket(proc.NamespaceID(eventCtx.MntID))
	} else {
		t.cfg.MountNamespacePIDStore.RemoveFromBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
	}
}

func (t *Tracer) handleNetPacketDNSEvent(eventCtx *types.EventContext, parsedArgs types.Args) error {
	event := parsedArgs.(types.NetPacketDNSBaseArgs).Payload
	err := t.addDNSResponseToCache(eventCtx.CgroupID, event.Answers)
	return err
}

func (t *Tracer) handleNetPacketHTTPEvent(event *types.Event, parsedArgs types.Args) {
	if t.cfg.HTTPMetricsCollector == nil {
		return
	}
	args, ok := parsedArgs.(types.NetPacketHTTPBaseArgs)
	if !ok {
		t.log.Debugf("invalid HTTP event args type: %T", parsedArgs)
		return
	}
	t.cfg.HTTPMetricsCollector.ProcessHTTPEvent(event, args.Payload)
}

// SetHTTPMetricsCollector sets the HTTP metrics collector for the tracer
func (t *Tracer) SetHTTPMetricsCollector(collector *httpmetrics.Collector) {
	t.cfg.HTTPMetricsCollector = collector
}

func (t *Tracer) MuteEventsFromCgroup(cgroup uint64, reason string) error {
	t.log.Debugf("muting cgroup %d, reason: %s", cgroup, reason)
	return t.module.objects.IgnoredCgroupsMap.Put(cgroup, cgroup)
}

func (t *Tracer) MuteEventsFromCgroups(cgroups []uint64, reason string) error {
	t.log.Debugf("muting cgroups %v, reason: %s", cgroups, reason)

	kernelVersion, err := kernel.CurrentKernelVersion()
	if err != nil {
		return err
	}

	// The ebpf batch helpers are available since kernel version 5.6.
	if kernelVersion.Major > 5 || (kernelVersion.Major == 5 && kernelVersion.Minor >= 6) {
		_, err = t.module.objects.IgnoredCgroupsMap.BatchUpdate(cgroups, cgroups, &ebpf.BatchOptions{
			Flags: uint64(ebpf.UpdateAny),
		})

		if err != nil {
			t.log.Warnf("got error while trying to mute cgroups %v: %s", cgroups, err)
		}
	} else {
		for _, cgroup := range cgroups {
			err = t.module.objects.IgnoredCgroupsMap.Update(cgroup, cgroup, ebpf.UpdateAny)

			if err != nil {
				t.log.Warnf("got error while trying to delete cgroup %d from ignore map: %s", cgroup, err)
			}
		}
	}

	return nil
}

func (t *Tracer) UnmuteEventsFromCgroup(cgroup uint64) error {
	t.log.Debugf("unmuting cgroup %d", cgroup)

	err := t.module.objects.IgnoredCgroupsMap.Delete(cgroup)

	// We do not care if we try to remove a non existing cgroup.
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}

	return err
}
