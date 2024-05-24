package ebpftracer

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
)

// Error indicating that the resulting error was caught from a panic
var ErrPanic = errors.New("encountered panic")

func (t *Tracer) decodeAndHandleSignal(_ context.Context, data []byte) (rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, data)
	var signalCtx types.SignalContext
	if err := ebpfMsgDecoder.DecodeSignalContext(&signalCtx); err != nil {
		return err
	}
	parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, signalCtx.EventID)
	if err != nil {
		return fmt.Errorf("cannot parse event type %d: %w", signalCtx.EventID, err)
	}

	switch args := parsedArgs.(type) {
	case types.SignalCgroupMkdirArgs:
		// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
		if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
			return nil
		}

		t.cfg.CgroupClient.LoadCgroup(args.CgroupId, args.CgroupPath)

	case types.SignalCgroupRmdirArgs:
		// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
		if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
			return nil
		}

		t.queueCgroupForRemoval(args.CgroupId)
		err := t.UnmuteEventsFromCgroup(args.CgroupId)
		if err != nil {
			return fmt.Errorf("cannot remove cgroup %d from mute map: %w", args.CgroupId, err)
		}
	default:
		t.log.Warnf("unhandled signal: %d", signalCtx.EventID)
	}

	return nil
}

func (t *Tracer) decodeAndExportEvent(ctx context.Context, data []byte) (rerr error) {
	metrics.AgentPulledEventsBytesTotal.Add(float64(len(data)))

	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, data)
	var eventCtx types.EventContext
	if err := ebpfMsgDecoder.DecodeContext(&eventCtx); err != nil {
		return err
	}

	eventId := eventCtx.EventID
	parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, eventId)
	if err != nil {
		return fmt.Errorf("cannot parse event type %d: %w", eventId, err)
	}

	container, err := t.cfg.ContainerClient.GetContainerForCgroup(ctx, eventCtx.CgroupID)
	if err != nil {
		// We ignore any event not belonging to a container for now.
		if errors.Is(err, containers.ErrContainerNotFound) {
			err := t.MuteEventsFromCgroup(eventCtx.CgroupID)
			if err != nil {
				return fmt.Errorf("cannot mute events for cgroup %d: %w", eventCtx.CgroupID, err)
			}
			return nil
		}
		return fmt.Errorf("cannot get container for cgroup %d: %w", eventCtx.CgroupID, err)
	}

	eventCtx.Ts = t.bootTime + eventCtx.Ts
	event := &types.Event{
		Context:   &eventCtx,
		Container: container,
		Args:      parsedArgs,
	}

	if _, found := t.signatureEventMap[eventId]; found {
		t.cfg.SignatureEngine.QueueEvent(event)
	}

	// Do not parse event, if it is not registered. If there is no policy set, we treat is as to parse all the events
	if _, found := t.eventPoliciesMap[eventId]; !found && t.policy != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventId))}).Inc()
		return nil
	}

	// TODO: Move rate limit based policy to kernel side.
	if err := t.allowedByPolicyPre(&eventCtx); err != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventId))}).Inc()
		return nil
	}

	switch eventId {
	case events.SchedProcessExec:
		if eventCtx.Pid == 1 {
			t.cfg.MountNamespacePIDStore.ForceAddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		} else {
			t.cfg.MountNamespacePIDStore.AddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		}
	}

	if err := t.allowedByPolicy(eventId, eventCtx.CgroupID, event); err != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventCtx.EventID))}).Inc()
		return nil
	}

	switch eventId {
	case events.NetFlowBase:
		select {
		case t.netflowEventsChan <- event:
		default:
			def := t.eventsSet[eventCtx.EventID]
			metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: def.name}).Inc()
		}
	default:
		select {
		case t.eventsChan <- event:
		default:
			def := t.eventsSet[eventCtx.EventID]
			metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: def.name}).Inc()
		}
	}

	return nil
}

func (t *Tracer) MuteEventsFromCgroup(cgroup uint64) error {
	t.log.Infof("muting cgroup %d", cgroup)
	return t.module.objects.IgnoredCgroupsMap.Put(cgroup, cgroup)
}

func (t *Tracer) MuteEventsFromCgroups(cgroups []uint64) error {
	t.log.Infof("muting cgroups %v", cgroups)

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
	t.log.Infof("unmuting cgroup %d", cgroup)

	err := t.module.objects.IgnoredCgroupsMap.Delete(cgroup)

	// We do not care if we try to remove a non existing cgroup.
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}

	return err
}

func (t *Tracer) UnmuteEventsFromCgroups(cgroups []uint64) error {
	t.log.Infof("unmuting cgroup %v", cgroups)

	kernelVersion, err := kernel.CurrentKernelVersion()
	if err != nil {
		return err
	}

	// The ebpf batch helpers are available since kernel version 5.6.
	if kernelVersion.Major > 5 || (kernelVersion.Major == 5 && kernelVersion.Minor >= 6) {
		_, err = t.module.objects.IgnoredCgroupsMap.BatchDelete(cgroups, nil)
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.Warnf("got error while trying to delete cgroups %v from ignore map: %s", cgroups, err)
		}
	} else {
		for _, cgroup := range cgroups {
			err = t.module.objects.IgnoredCgroupsMap.Delete(cgroup)
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.log.Warnf("got error while trying to delete cgroup %d from ignore map: %s", cgroup, err)
			}
		}
	}

	return nil
}

func (t *Tracer) IsCgroupMuted(cgroup uint64) bool {
	var value uint64

	err := t.module.objects.IgnoredCgroupsMap.Lookup(cgroup, &value)

	return !errors.Is(err, ebpf.ErrKeyNotExist) && value > 0
}
