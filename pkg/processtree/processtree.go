package processtree

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
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

type ProcessTreeCollector interface {
	Events() <-chan ProcessTreeEvent
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

func (e ProcessEvent) String() string {
	return fmt.Sprintf("%s ts: %s, pid: %d, startTime: %d, ppid: %d, parentStartTime: %d, containerID: %s",
		e.Action.String(),
		e.Timestamp.Format(time.RFC3339),
		e.Process.PID,
		uint64(e.Process.StartTime.Seconds()),
		e.Process.PPID,
		uint64(e.Process.ParentStartTime.Seconds()),
		e.ContainerID,
	)
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

type containerClient interface {
	LoadContainerTasks(ctx context.Context) ([]containers.ContainerProcess, error)
}

type ProcessTreeCollectorImpl struct {
	log              *logging.Logger
	proc             *proc.Proc
	containersClient containerClient
}

func New(log *logging.Logger, p *proc.Proc, containersClient containerClient) *ProcessTreeCollectorImpl {
	return &ProcessTreeCollectorImpl{
		log:              log,
		proc:             p,
		containersClient: containersClient,
	}
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

func (c *ProcessTreeCollectorImpl) GetCurrentProcesses(ctx context.Context) ([]ProcessEvent, error) {
	processes, err := c.containersClient.LoadContainerTasks(ctx)
	if err != nil {
		return nil, err
	}

	processTrees := map[string]map[ProcessKey]Process{}

	numProcesses := 0

	for _, p := range processes {
		procProcesses, err := c.proc.SnapshotProcessTree(p.PID)
		if err != nil {
			c.log.Warnf("cannot snapshot process tree for PID %d: %v", p.PID, err)
			continue
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

	events := make([]ProcessEvent, numProcesses)
	now := time.Now().UTC()

	i := 0
	// In order to get all the known process infos upstream, we treat send an exec event for
	// each process we encountered in proc.
	for container, processes := range processTrees {
		for _, process := range processes {
			events[i] = ProcessEvent{
				// We take the current time for the init event timestamp to indicate that this comes from an event update.
				Timestamp:   now,
				ContainerID: container,
				Process:     process,
				Action:      ProcessExec,
			}
			i++
		}
	}
	return events, nil
}
