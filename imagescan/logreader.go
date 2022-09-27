package imagescan

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type podLogProvider interface {
	GetLogReader(ctx context.Context, podName string) (io.ReadCloser, error)
}

func newPodLogReader(client kubernetes.Interface) clientsetPodLogsReader {
	return clientsetPodLogsReader{
		client: client,
	}
}

type clientsetPodLogsReader struct {
	client kubernetes.Interface
}

func (r clientsetPodLogsReader) GetLogReader(ctx context.Context, podName string) (io.ReadCloser, error) {
	req := r.client.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("error in opening stream: %v", err)
	}
	return podLogs, nil
}
