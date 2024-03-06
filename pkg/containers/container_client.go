package containers

import (
	"context"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"
	"github.com/samber/lo"
)

func newContainerClient(address string) (*containerClient, error) {
	client, err := containerd.New(address, containerd.WithTimeout(10*time.Second), containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return nil, err
	}
	return &containerClient{
		client: client,
	}, nil
}

// containerClient wraps container runtime specific implementations. For we support only containerd.
type containerClient struct {
	client *containerd.Client
}

func (c *containerClient) getContainerPids(ctx context.Context, containerID string) ([]uint32, error) {
	res, err := c.client.TaskService().ListPids(ctx, &tasks.ListPidsRequest{ContainerID: containerID})
	if err != nil {
		return nil, err
	}
	return lo.Map(res.GetProcesses(), func(item *task.ProcessInfo, index int) uint32 {
		return item.GetPid()
	}), nil
}
