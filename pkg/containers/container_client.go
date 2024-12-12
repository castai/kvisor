package containers

import (
	"time"

	"github.com/containerd/containerd"
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
