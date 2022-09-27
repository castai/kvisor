package imagescan

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"time"

	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/labels"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	batchv1typed "k8s.io/client-go/kubernetes/typed/batch/v1"

	imgcollectorconfig "github.com/castai/sec-agent/cmd/imgcollector/config"
	"github.com/castai/sec-agent/config"
)

const (
	ns = "castai-sec"
)

type imageScanner interface {
	ScanImage(ctx context.Context, cfg ScanImageParams) (err error)
}

func NewImageScanner(client kubernetes.Interface, cfg config.Config) *Scanner {
	return &Scanner{
		podLogProvider:   newPodLogReader(client),
		client:           client,
		jobCheckInterval: 5 * time.Second,
		cfg:              cfg,
	}
}

type Scanner struct {
	podLogProvider   podLogProvider
	client           kubernetes.Interface
	cfg              config.Config
	jobCheckInterval time.Duration
}

type ScanImageParams struct {
	ImageName         string
	ImageID           string
	ContainerID       string
	NodeName          string
	ResourceIDs       []string
	Tolerations       []corev1.Toleration
	DeleteFinishedJob bool
	WaitForCompletion bool
}

func getContainerRuntime(containerID string) (string, bool) {
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return "", false
	}
	return parts[0], true
}

func (s *Scanner) ScanImage(ctx context.Context, params ScanImageParams) (rerr error) {
	if params.ImageID == "" {
		return errors.New("image ID is required")
	}
	if params.ImageName == "" {
		return errors.New("image name is required")
	}
	if params.ContainerID == "" {
		return errors.New("container ID is required")
	}
	if len(params.ResourceIDs) == 0 {
		return errors.New("resource ids are required")
	}

	jobName := genJobName(params.ImageName)
	vols := volumesAndMounts{}
	mode := imgcollectorconfig.Mode(s.cfg.Features.ImageScan.Mode)
	containerRuntime, ok := getContainerRuntime(params.ContainerID)
	if !ok {
		return fmt.Errorf("failed to find container runtime, container_id=%s", params.ContainerID)
	}

	if mode == "" || mode == imgcollectorconfig.ModeDockerDaemon || mode == imgcollectorconfig.ModeContainerdDaemon {
		switch containerRuntime {
		case "docker":
			vols.volumes = append(vols.volumes, corev1.Volume{
				Name: "docker-sock",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/docker.sock",
						Type: lo.ToPtr(corev1.HostPathSocket),
					},
				},
			})
			vols.mounts = append(vols.mounts, corev1.VolumeMount{
				Name:      "docker-sock",
				ReadOnly:  true,
				MountPath: "/var/run/docker.sock",
			})
			mode = imgcollectorconfig.ModeDockerDaemon
		case "containerd":
			vols.volumes = append(vols.volumes, corev1.Volume{
				Name: "containerd-sock",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/containerd/containerd.sock",
						Type: lo.ToPtr(corev1.HostPathSocket),
					},
				},
			})
			vols.mounts = append(vols.mounts, corev1.VolumeMount{
				Name:      "containerd-sock",
				ReadOnly:  true,
				MountPath: "/run/containerd/containerd.sock",
			})
			mode = imgcollectorconfig.ModeContainerdDaemon
		}
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "COLLECTOR_IMAGE_ID",
			Value: params.ImageID,
		},
		{
			Name:  "COLLECTOR_IMAGE_NAME",
			Value: params.ImageName,
		},
		{
			Name:  "COLLECTOR_TIMEOUT",
			Value: "5m",
		},
		{
			Name:  "COLLECTOR_MODE",
			Value: string(mode),
		},
		{
			Name:  "COLLECTOR_DOCKER_OPTION_PATH",
			Value: s.cfg.Features.ImageScan.DockerOptionsPath,
		},
		{
			Name:  "COLLECTOR_RESOURCE_IDS",
			Value: strings.Join(params.ResourceIDs, ","),
		},
		{
			Name: "API_URL",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "castai-sec-agent",
					},
					Key: "API_URL",
				},
			},
		},
		{
			Name: "API_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "castai-sec-agent",
					},
					Key: "API_KEY",
				},
			},
		},
		{
			Name: "CLUSTER_ID",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "castai-sec-agent",
					},
					Key: "CLUSTER_ID",
				},
			},
		},
	}

	jobSpec := scanJobSpec(
		s.cfg.Features.ImageScan.CollectorImage,
		s.cfg.Features.ImageScan.CollectorImagePullPolicy,
		params.NodeName,
		jobName,
		envVars,
		vols,
		params.Tolerations,
	)
	jobs := s.client.BatchV1().Jobs(ns)

	if params.DeleteFinishedJob {
		defer func() {
			if err := jobs.Delete(ctx, jobSpec.Name, metav1.DeleteOptions{
				PropagationPolicy: lo.ToPtr(metav1.DeletePropagationBackground),
			}); err != nil && !apierrors.IsNotFound(err) {
				rerr = err
			}
		}()
	}

	// If job already exist wait for completion and exit.
	_, err := jobs.Get(ctx, jobSpec.Name, metav1.GetOptions{})
	if err == nil {
		return s.waitForCompletion(ctx, jobs, jobName)
	}

	// Create new job and wait for completion.
	_, err = jobs.Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if params.WaitForCompletion {
		return s.waitForCompletion(ctx, jobs, jobName)
	}
	return nil
}

func (s *Scanner) waitForCompletion(ctx context.Context, jobs batchv1typed.JobInterface, jobName string) error {
	return wait.PollUntilWithContext(ctx, s.jobCheckInterval, func(ctx context.Context) (done bool, err error) {
		job, err := jobs.Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return true, err
			}
			return false, nil
		}
		done = lo.ContainsBy(job.Status.Conditions, func(v batchv1.JobCondition) bool {
			return v.Status == corev1.ConditionTrue && v.Type == batchv1.JobComplete
		})
		if done {
			return true, nil
		}
		failed := lo.ContainsBy(job.Status.Conditions, func(v batchv1.JobCondition) bool {
			return v.Status == corev1.ConditionTrue && v.Type == batchv1.JobFailed
		})
		if failed {
			jobPods, err := s.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"job-name": jobName}.String()})
			if err != nil {
				return true, err
			}
			if len(jobPods.Items) == 0 {
				return true, errors.New("job pod not found")
			}
			jobPod := jobPods.Items[0]
			logsStream, err := s.podLogProvider.GetLogReader(ctx, jobPod.Name)
			if err != nil {
				return true, fmt.Errorf("creating logs stream: %w", err)
			}
			defer logsStream.Close()
			logs, err := io.ReadAll(logsStream)
			if err != nil {
				return true, fmt.Errorf("reading logs")
			}
			return true, fmt.Errorf("scan job failed: %s", string(logs))
		}
		return false, nil
	})
}

type volumesAndMounts struct {
	volumes []corev1.Volume
	mounts  []corev1.VolumeMount
}

func genJobName(imageName string) string {
	h := fnv.New128()
	h.Write([]byte(imageName))
	imgHash := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("imgscan-%s", imgHash)
}

func scanJobSpec(
	collectorImage, collectorImagePullPolicy, nodeName, jobName string,
	envVars []corev1.EnvVar,
	vol volumesAndMounts,
	tolerations []corev1.Toleration,
) *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: ns,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
			BackoffLimit:            lo.ToPtr(int32(0)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeName:      nodeName,
					RestartPolicy: "Never",
					Priority:      lo.ToPtr(int32(0)),
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "kubernetes.io/os",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{"linux"},
											},
										},
									},
								},
							},
						},
					},
					Tolerations: tolerations,
					Containers: []corev1.Container{
						{
							Name:            "collector",
							Image:           collectorImage,
							ImagePullPolicy: corev1.PullPolicy(collectorImagePullPolicy),
							Env:             envVars,
							VolumeMounts:    vol.mounts,
							Resources: corev1.ResourceRequirements{
								Limits: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("100Mi"),
								},
							},
						},
					},
					Volumes: vol.volumes,
				},
			},
		},
	}
}
