package processtree

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/prometheus/client_golang/prometheus"
)

type ProcessAction int

const (
	ProcessUnknown ProcessAction = iota
	ProcessExec
	ProcessFork
	ProcessExit
)

func (a ProcessAction) String() string {
	switch a {
	case ProcessExec:
		return "ProcessExec"
	case ProcessFork:
		return "ProcessFork"
	case ProcessExit:
		return "ProcessExit"
	}
	return "Unknown"
}

type ProcessTreeEvent struct {
	Initial bool
	Events  []ProcessEvent
}

type ProcessEvent struct {
	Timestamp   time.Time
	ContainerID string
	Process     Process
	Action      ProcessAction
}

type ProcessEventListener func(e ProcessEvent)

type Process struct {
	PID             proc.PID
	StartTime       time.Duration
	PPID            proc.PID
	ParentStartTime time.Duration
	Args            []string
	FilePath        string
	ExitTime        uint64
}

func (p Process) Exited() bool {
	return p.ExitTime > 0
}

type ProcessTreeCollector interface {
	ProcessStarted(eventTime time.Time, containerID string, p Process)
	ProcessForked(eventTime time.Time, containerID string, parent ProcessKey, processKey ProcessKey)
	ProcessExited(eventTime time.Time, containerID string, processKey ProcessKey, parentProcessKey ProcessKey, exitTime uint64)
	Events() <-chan ProcessTreeEvent
}

type containerClient interface {
	LoadContainerTasks(ctx context.Context) ([]containers.ContainerProcess, error)
}

type ProcessTreeCollectorImpl struct {
	log              *logging.Logger
	proc             *proc.Proc
	containersClient containerClient
	eventSink        chan ProcessTreeEvent
}

func New(log *logging.Logger, p *proc.Proc, containersClient containerClient) (*ProcessTreeCollectorImpl, error) {
	return &ProcessTreeCollectorImpl{
		log:              log,
		proc:             p,
		containersClient: containersClient,
		eventSink:        make(chan ProcessTreeEvent, 1000),
	}, nil
}

type ProcessKey struct {
	PID proc.PID
	// NOTE: StartTime will be stored in seconds since boot, since this is the best resolution we can get everywhere
	// we need. This should still be good enough to identify a process.
	StartTime time.Duration
}

func (k ProcessKey) Empty() bool {
	return k.PID == 0 && k.StartTime == 0
}

func (k ProcessKey) String() string {
	return fmt.Sprintf("%d - %s", k.PID, k.StartTime)
}

func ToProcessKey(pid proc.PID, startTime time.Duration) ProcessKey {
	return ProcessKey{
		PID:       pid,
		StartTime: startTime.Truncate(time.Second),
	}
}

func ToProcessKeyNs(pid proc.PID, startTimeNs uint64) ProcessKey {
	return ProcessKey{
		PID:       pid,
		StartTime: time.Duration(startTimeNs).Truncate(time.Second),
	}
}

func (c *ProcessTreeCollectorImpl) Init(ctx context.Context) error {
	processes, err := c.containersClient.LoadContainerTasks(ctx)
	if err != nil {
		return err
	}

	processTrees := map[string]map[ProcessKey]Process{}

	numProcesses := 0

	for _, p := range processes {
		procProcesses, err := c.proc.SnapshotProcessTree(p.PID)
		if err != nil {
			return err
		}

		processesMap := make(map[ProcessKey]Process)

		for _, process := range procProcesses {
			numProcesses++
			key := ToProcessKey(process.PID, process.StartTime)

			processToAdd := Process{
				PID:       process.PID,
				StartTime: process.StartTime,
				Args:      process.Args,
				FilePath:  process.FilePath,
			}

			if ind, found := slices.BinarySearchFunc(procProcesses, process.PPID, func(e proc.Process, pid proc.PID) int {
				return cmp.Compare(e.PID, pid)
			}); found {
				parent := procProcesses[ind]
				processToAdd.PPID = parent.PID
				processToAdd.ParentStartTime = parent.StartTime
			}

			processesMap[key] = processToAdd
		}

		processTrees[p.ContainerID] = processesMap
	}

	eventsToFire := make([]ProcessEvent, numProcesses)
	now := time.Now().UTC()

	i := 0
	// In order to get all the known process infos upstream, we treat send an exec event for
	// each process we encountered in proc.
	for container, processes := range processTrees {
		for _, process := range processes {
			eventsToFire[i] = ProcessEvent{
				// We take the current time for the init event timestamp to indicate that this comes from an event update.
				Timestamp:   now,
				ContainerID: container,
				Process:     process,
				Action:      ProcessExec,
			}
			i++
		}
	}

	c.fireEvents(ProcessTreeEvent{
		Initial: true,
		Events:  eventsToFire,
	})

	return nil
}

func (c *ProcessTreeCollectorImpl) ProcessStarted(eventTime time.Time, containerID string, p Process) {
	c.fireEvent(ProcessEvent{
		Timestamp:   eventTime,
		ContainerID: containerID,
		Process:     p,
		Action:      ProcessExec,
	})
}

func (c *ProcessTreeCollectorImpl) ProcessForked(eventTime time.Time, containerID string, parent ProcessKey, processKey ProcessKey) {
	var process Process

	process = Process{
		PID:             processKey.PID,
		StartTime:       processKey.StartTime,
		PPID:            parent.PID,
		ParentStartTime: parent.StartTime,
	}

	c.fireEvent(ProcessEvent{
		Timestamp:   eventTime,
		ContainerID: containerID,
		Process:     process,
		Action:      ProcessFork,
	})
}

func (c *ProcessTreeCollectorImpl) ProcessExited(eventTime time.Time, containerID string, processKey ProcessKey, parentProcessKey ProcessKey, exitTime uint64) {
	c.fireEvent(ProcessEvent{
		Timestamp:   eventTime,
		ContainerID: containerID,
		Process: Process{
			PID:             processKey.PID,
			StartTime:       processKey.StartTime,
			PPID:            parentProcessKey.PID,
			ParentStartTime: parentProcessKey.StartTime,
			ExitTime:        exitTime,
		},
		Action: ProcessExit,
	})
}

func (c *ProcessTreeCollectorImpl) Events() <-chan ProcessTreeEvent {
	return c.eventSink
}

func (c *ProcessTreeCollectorImpl) fireEvent(e ProcessEvent) {
	c.log.Debugf("fire process tree event %s (%s): pid: %d, startTime: %s, ppid: %d, parentStartTime: %s, containerID: %s", e.Action.String(),
		e.Timestamp.Format(time.RFC3339), e.Process.PID, e.Process.StartTime, e.Process.PPID, e.Process.ParentStartTime, e.ContainerID)
	select {
	case c.eventSink <- ProcessTreeEvent{
		Initial: false,
		Events:  []ProcessEvent{e},
	}:
	default:
		metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: "process_tree"}).Inc()
	}
}

func (c *ProcessTreeCollectorImpl) fireEvents(event ProcessTreeEvent) {
	if c.log.IsEnabled(slog.LevelDebug) {
		c.log.Debugf("fire process tree event (initial %t) ---", event.Initial)
		for _, e := range event.Events {
			c.log.Debugf("process event %s (%s): pid: %d, startTime: %s, ppid: %d, parentStartTime: %s, containerID: %s", e.Action.String(),
				e.Timestamp.Format(time.RFC3339), e.Process.PID, e.Process.StartTime, e.Process.PPID, e.Process.ParentStartTime, e.ContainerID)
		}
		c.log.Debugf("fire process tree event (initial %t) done ---", event.Initial)
	}
	select {
	case c.eventSink <- event:
	default:
		metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: "process_tree"}).Inc()
	}
}
