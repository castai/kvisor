package kube

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type PodLogProvider interface {
	GetLogReader(ctx context.Context, podNs, podName string) (io.ReadCloser, error)
}

func NewPodLogReader(client kubernetes.Interface) PodLogProvider {
	return &clientsetPodLogsReader{
		client: client,
	}
}

type clientsetPodLogsReader struct {
	client kubernetes.Interface
}

func (r clientsetPodLogsReader) GetLogReader(ctx context.Context, podNs, podName string) (io.ReadCloser, error) {
	req := r.client.CoreV1().Pods(podNs).GetLogs(podName, &corev1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("error in opening stream: %w", err)
	}
	return podLogs, nil
}
