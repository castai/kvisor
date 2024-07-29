package processtree

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestInitProcessTree(t *testing.T) {
	t.Run("can generate process tree from proc filesystem", func(t *testing.T) {
		r := require.New(t)

		fs := os.DirFS("./testdata/simple_proc/")

		containerID1 := "container-1"
		containerID2 := "container-2"

		tree, err := New(logging.New(&logging.Config{}), proc.NewFromFS(fs.(proc.ProcFS)),
			&dummyContainerClient{
				loadContainerTaskFn: func(ctx context.Context) ([]containers.ContainerProcess, error) {
					return []containers.ContainerProcess{
						{
							ContainerID: containerID1,
							PID:         99,
						},
						{
							ContainerID: containerID2,
							PID:         100,
						},
					}, nil
				},
			})
		r.NoError(err)

		err = tree.Init(context.TODO())
		r.NoError(err)

		events := consumeAll(tree.eventSink)
		r.Len(events, 1)

		processTreeEvent := events[0]
		r.True(processTreeEvent.Initial)
		r.Len(processTreeEvent.Events, 6)

		now := time.Now()

		processEvents := lo.Map(processTreeEvent.Events, func(item ProcessEvent, index int) ProcessEvent {
			// We do not care about timestamp in this test.
			item.Timestamp = now
			return item
		})

		r.ElementsMatch([]ProcessEvent{
			{
				Timestamp:   now,
				ContainerID: containerID1,
				Process: Process{
					PID:             1,
					StartTime:       212080000000000,
					PPID:            0,
					ParentStartTime: 0,
					Args:            []string{"bash"},
				},
				Action: ProcessExec,
			},
			{
				Timestamp:   now,
				ContainerID: containerID1,
				Process: Process{
					PID:             11,
					StartTime:       212088000000000,
					PPID:            1,
					ParentStartTime: 212080000000000,
					Args:            []string{"sleep", "1000"},
				},
				Action: ProcessExec,
			},
			{
				Timestamp:   now,
				ContainerID: containerID1,
				Process: Process{
					PID:             24,
					StartTime:       212108000000000,
					PPID:            0,
					ParentStartTime: 0,
					Args:            []string{"bash"},
				},
				Action: ProcessExec,
			},
			{
				Timestamp:   now,
				ContainerID: containerID2,
				Process: Process{
					PID:             1,
					StartTime:       179502000000000,
					PPID:            0,
					ParentStartTime: 0,
					Args:            []string{"cat"},
				},
				Action: ProcessExec,
			},
			{
				Timestamp:   now,
				ContainerID: containerID2,
				Process: Process{
					PID:             90,
					StartTime:       211630000000000,
					PPID:            0,
					ParentStartTime: 0,
					Args:            []string{"bash"},
				},
				Action: ProcessExec,
			},
			{
				Timestamp:   now,
				ContainerID: containerID2,
				Process: Process{
					PID:             100,
					StartTime:       211811000000000,
					PPID:            90,
					ParentStartTime: 211630000000000,
					Args:            []string{"sleep", "1000"},
				},
				Action: ProcessExec,
			},
		}, processEvents)

	})
}

func consumeAll[T any](c <-chan T) []T {
	var result []T

	for {
		select {
		case e := <-c:
			result = append(result, e)

		default:
			return result
		}
	}
}

type dummyContainerClient struct {
	loadContainerTaskFn func(ctx context.Context) ([]containers.ContainerProcess, error)
}

func (d *dummyContainerClient) LoadContainerTasks(ctx context.Context) ([]containers.ContainerProcess, error) {
	if d.loadContainerTaskFn == nil {
		return nil, nil
	}

	return d.loadContainerTaskFn(ctx)
}

var _ containerClient = (*dummyContainerClient)(nil)
