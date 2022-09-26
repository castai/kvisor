package kubebench

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type PodLogProvider interface {
	GetLogReader(ctx context.Context, podName string) (io.ReadCloser, error)
}

func NewPodLogReader(client kubernetes.Interface) clientsetProvider {
	return clientsetProvider{
		client: client,
	}
}

type clientsetProvider struct {
	client kubernetes.Interface
}

func (r clientsetProvider) GetLogReader(ctx context.Context, podName string) (io.ReadCloser, error) {
	req := r.client.CoreV1().Pods(castAINamespace).GetLogs(podName, &corev1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("error in opening stream: %v", err)
	}
	return podLogs, nil
}
