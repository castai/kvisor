package kube

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type IssueType string

const (
	OOMKilled    IssueType = "OOMKilled"
	ImagePull    IssueType = "ErrImagePull"
	ProcessError IssueType = "Error"
)

type Issue struct {
	Ts            time.Time
	Type          IssueType
	Message       string
	ContainerName string
	ImageName     string
	ContainerID   string
	PodUID        types.UID
}

func (c *Client) detectIssues(pod *Pod) {
	k8sPod := pod.Pod
	for _, cont := range k8sPod.Status.ContainerStatuses {
		if issue, found := detectContainerIssue(k8sPod, cont); found {
			select {
			case c.issues <- issue:
			default:
				c.log.Warn("issues chan is full, dropping event")
			}
		}
	}
	for _, cont := range k8sPod.Status.InitContainerStatuses {
		if issue, found := detectContainerIssue(k8sPod, cont); found {
			select {
			case c.issues <- issue:
			default:
				c.log.Warn("issues chan is full, dropping event")
			}
		}
	}
}

func detectContainerIssue(pod *corev1.Pod, cont corev1.ContainerStatus) (Issue, bool) {
	if cont.State.Running != nil {
		return Issue{}, false
	}
	waiting := cont.State.Waiting
	if waiting != nil {
		switch IssueType(waiting.Reason) {
		case OOMKilled, ImagePull, ProcessError:
			return Issue{
				Ts:            time.Now().UTC(),
				Type:          IssueType(waiting.Reason),
				Message:       waiting.Message,
				ContainerName: cont.Name,
				ImageName:     cont.Image,
				ContainerID:   GetContainerID(cont.ContainerID),
				PodUID:        pod.UID,
			}, true
		}
	}
	terminated := cont.State.Terminated
	if terminated != nil && terminated.ExitCode != 0 {
		msg := terminated.Message
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", terminated.ExitCode)
		}
		switch IssueType(terminated.Reason) {
		case OOMKilled, ImagePull, ProcessError:
			return Issue{
				Ts:            time.Now().UTC(),
				Type:          IssueType(terminated.Reason),
				Message:       msg,
				ContainerName: cont.Name,
				ImageName:     cont.Image,
				ContainerID:   GetContainerID(cont.ContainerID),
				PodUID:        pod.UID,
			}, true
		}
	}
	return Issue{}, false
}
