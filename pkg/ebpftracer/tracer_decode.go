package ebpftracer

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/castai/kvisor/pkg/system"
	"github.com/cilium/ebpf"
	"golang.org/x/net/context"
)

// Error indicating that the resulting error was caught from a panic
var ErrPanic = errors.New("encountered panic")

func decodeContextAndArgs(ebpfMsgDecoder *decoder.Decoder) (types.EventContext, types.Args, error) {
	var eventCtx types.EventContext
	if err := ebpfMsgDecoder.DecodeContext(&eventCtx); err != nil {
		return types.EventContext{}, nil, fmt.Errorf("decoding context: %w", err)
	}
	eventId := eventCtx.EventID
	parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, eventId)
	if err != nil {
		return types.EventContext{}, nil, fmt.Errorf("parsing event %d args: %w", eventId, err)
	}

	return eventCtx, parsedArgs, nil
}

func (t *Tracer) decodeAndExportEvent(ctx context.Context, ebpfMsgDecoder *decoder.Decoder) (rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	eventCtx, parsedArgs, err := decodeContextAndArgs(ebpfMsgDecoder)
	if err != nil {
		return err
	}
	eventId := eventCtx.EventID
	def := t.eventsSet[eventCtx.EventID]
	metrics.AgentPulledEventsBytesTotal.WithLabelValues(def.name).Add(float64(ebpfMsgDecoder.BuffLen()))
	metrics.AgentPulledEventsTotal.WithLabelValues(def.name).Inc()

	// Process special events for cgroup creation and removal.
	// These are system events which are not send down via events pipeline.
	switch eventId {
	case events.CgroupMkdir:
		args := parsedArgs.(types.CgroupMkdirArgs)
		// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
		if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
			return nil
		}
		t.cfg.CgroupClient.LoadCgroup(args.CgroupId, args.CgroupPath)
		if _, err := t.cfg.ContainerClient.AddContainerByCgroupID(context.Background(), args.CgroupId); err != nil {
			if errors.Is(err, containers.ErrContainerNotFound) {
				err := t.MuteEventsFromCgroup(eventCtx.CgroupID)
				if err != nil {
					return fmt.Errorf("cannot mute events for cgroup %d: %w", eventCtx.CgroupID, err)
				}
				return nil
			}
			t.log.Errorf("cannot add container to cgroup %d: %b", args.CgroupId, err)
		}
		return nil
	case events.CgroupRmdir:
		args := parsedArgs.(types.CgroupRmdirArgs)

		t.queueCgroupForRemoval(args.CgroupId)
		err := t.UnmuteEventsFromCgroup(args.CgroupId)
		if err != nil {
			return fmt.Errorf("cannot remove cgroup %d from mute map: %w", args.CgroupId, err)
		}
		return nil
	default:
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

	rawEventTime := eventCtx.Ts
	eventCtx.Ts = t.bootTime + eventCtx.Ts
	event := &types.Event{
		Context:   &eventCtx,
		Container: container,
		Args:      parsedArgs,
	}

	switch eventId {
	case events.SchedProcessExec:
		if eventCtx.Pid == 1 {
			t.cfg.MountNamespacePIDStore.ForceAddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		} else {
			t.cfg.MountNamespacePIDStore.AddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		}

		parentStartTime := time.Duration(0)
		if eventCtx.Ppid != 0 {
			// We only set the parent start time, if we know the parent PID comes from the same NS.
			parentStartTime = time.Duration(eventCtx.ParentStartTime) * time.Nanosecond // nolint:gosec
		}
		execArgs, ok := parsedArgs.(types.SchedProcessExecArgs)
		if !ok {
			t.log.Errorf("expected types.SchedProcessExecArgs, but got: %t", parsedArgs)
			return nil
		}
		processStartTime := time.Duration(eventCtx.StartTime) * time.Nanosecond // nolint:gosec

		t.cfg.ProcessTreeCollector.ProcessStarted(
			system.GetBootTime().Add(time.Duration(rawEventTime)), // nolint:gosec
			container.ID,
			processtree.Process{
				PID:             proc.PID(eventCtx.Pid),
				StartTime:       processStartTime.Truncate(time.Second),
				PPID:            proc.PID(eventCtx.Ppid),
				ParentStartTime: parentStartTime.Truncate(time.Second),
				Args:            execArgs.Argv,
				FilePath:        execArgs.Filepath,
			},
		)

	case events.SchedProcessExit, events.ProcessOomKilled:
		// We only care about process exits and not threads.
		if eventCtx.HostPid == eventCtx.HostTid {
			parentStartTime := time.Duration(0)
			if eventCtx.Ppid != 0 {
				// We only set the parent start time, if we know the parent PID comes from the same NS.
				parentStartTime = time.Duration(eventCtx.ParentStartTime) * time.Nanosecond // nolint:gosec
			}

			t.cfg.ProcessTreeCollector.ProcessExited(
				system.GetBootTime().Add(time.Duration(rawEventTime)), // nolint:gosec
				container.ID,
				processtree.ToProcessKeyNs(
					proc.PID(eventCtx.Pid),
					eventCtx.StartTime),
				processtree.ToProcessKey(proc.PID(eventCtx.Ppid), parentStartTime),
				eventCtx.Ts,
			)
		}

	case events.SchedProcessFork:
		forkArgs := parsedArgs.(types.SchedProcessForkArgs)

		// ChildPID equals ParentPID indicates that the child is probably a thread. We do not care about threads.
		if forkArgs.ChildNsPid != forkArgs.ParentNsPid {
			parentStartTime := uint64(0)
			if forkArgs.UpParentPid != 0 {
				parentStartTime = forkArgs.UpParentStartTime
			}

			t.cfg.ProcessTreeCollector.ProcessForked(
				// We always assume the child start time as the event timestamp for forks.
				system.GetBootTime().Add(time.Duration(forkArgs.ChildStartTime)), // nolint:gosec
				container.ID,
				processtree.ToProcessKeyNs(proc.PID(forkArgs.ParentNsPid), parentStartTime),        // nolint:gosec
				processtree.ToProcessKeyNs(proc.PID(forkArgs.ChildNsPid), forkArgs.ChildStartTime), //nolint:gosec
			)
		}
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

	// TODO: Move rate limit based policy to kernel side.
	if err := t.allowedByPolicyPre(&eventCtx); err != nil {
		metrics.AgentSkippedEventsTotal.WithLabelValues(def.name).Inc()
		return nil
	}

	if err := t.allowedByPolicy(eventId, eventCtx.CgroupID, event); err != nil {
		metrics.AgentSkippedEventsTotal.WithLabelValues(def.name).Inc()
		return nil
	}

	switch eventId {
	case events.NetFlowBase:
		select {
		case t.netflowEventsChan <- event:
		default:
			metrics.AgentDroppedEventsTotal.WithLabelValues(def.name).Inc()
		}
	default:
		select {
		case t.eventsChan <- event:
		default:
			metrics.AgentDroppedEventsTotal.WithLabelValues(def.name).Inc()
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
