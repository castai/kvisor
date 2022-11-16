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
	"github.com/castai/sec-agent/log"
)

type imageScanner interface {
	ScanImage(ctx context.Context, cfg ScanImageParams) (err error)
}

func NewImageScanner(client kubernetes.Interface, cfg config.Config, deltaState *deltaState) *Scanner {
	return &Scanner{
		podLogProvider:   log.NewPodLogReader(client),
		client:           client,
		jobCheckInterval: 5 * time.Second,
		cfg:              cfg,
		deltaState:       deltaState,
	}
}

type Scanner struct {
	podLogProvider   log.PodLogProvider
	client           kubernetes.Interface
	cfg              config.Config
	jobCheckInterval time.Duration
	deltaState       *deltaState
}

type ScanImageParams struct {
	ImageName                   string
	ImageID                     string
	ContainerRuntime            string
	NodeName                    string
	ResourceIDs                 []string
	Tolerations                 []corev1.Toleration
	DeleteFinishedJob           bool
	WaitForCompletion           bool
	WaitDurationAfterCompletion time.Duration
}

func (s *Scanner) ScanImage(ctx context.Context, params ScanImageParams) (rerr error) {
	if params.ImageID == "" {
		return errors.New("image ID is required")
	}
	if params.ImageName == "" {
		return errors.New("image name is required")
	}
	if params.ContainerRuntime == "" {
		return errors.New("container runtime is required")
	}
	if len(params.ResourceIDs) == 0 {
		return errors.New("resource ids are required")
	}
	if params.NodeName == "" {
		return errors.New("node name is required")
	}
	if s.cfg.ImageScan.BlobsCachePort == 0 {
		return errors.New("blobs cache port is required")
	}
	if s.cfg.PodNamespace == "" {
		return errors.New("pod namespace is required")
	}

	jobName := genJobName(params.ImageName)
	vols := volumesAndMounts{}
	mode := imgcollectorconfig.Mode(s.cfg.ImageScan.Mode)
	containerRuntime := params.ContainerRuntime

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
		default:
			return fmt.Errorf("unsupported container runtime: %s", containerRuntime)
		}
	}

	if mode == imgcollectorconfig.ModeContainerdHostFS {
		switch containerRuntime {
		case "docker":
			return fmt.Errorf("unsupported container runtime: %s for mode %s", containerRuntime, mode)
		case "containerd":
			vols.volumes = append(vols.volumes, corev1.Volume{
				Name: "containerd-content",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: imgcollectorconfig.ContainerdContentDir,
						Type: lo.ToPtr(corev1.HostPathDirectory),
					},
				},
			})
			vols.mounts = append(vols.mounts, corev1.VolumeMount{
				Name:      "containerd-content",
				ReadOnly:  true,
				MountPath: imgcollectorconfig.ContainerdContentDir,
			})
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
			Value: s.cfg.ImageScan.DockerOptionsPath,
		},
		{
			Name:  "COLLECTOR_RESOURCE_IDS",
			Value: strings.Join(params.ResourceIDs, ","),
		},
		{
			Name:  "API_URL",
			Value: s.cfg.API.URL,
		},
		{
			Name: "API_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "castai-cluster-controller",
					},
					Key: "API_KEY",
				},
			},
		},
		{
			Name:  "CLUSTER_ID",
			Value: s.cfg.API.ClusterID,
		},
	}

	if s.cfg.PodIP != "" {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "COLLECTOR_BLOBS_CACHE_URL",
			Value: fmt.Sprintf("http://%s:%d", s.cfg.PodIP, s.cfg.ImageScan.BlobsCachePort),
		})
	}

	jobSpec := scanJobSpec(
		s.cfg.PodNamespace,
		s.cfg.ImageScan.Image.Name,
		s.cfg.ImageScan.Image.PullPolicy,
		params.NodeName,
		jobName,
		envVars,
		vols,
		params.Tolerations,
		s.cfg.ImageScan,
	)
	jobs := s.client.BatchV1().Jobs(s.cfg.PodNamespace)

	if params.DeleteFinishedJob {
		defer func() {
			// Useful to keep job for a while to troubleshoot issues.
			if params.WaitDurationAfterCompletion != 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(params.WaitDurationAfterCompletion):
				}
			}

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
		return s.waitForCompletion(ctx, jobs, jobName, params.NodeName)
	}

	// Create new job and wait for completion.
	_, err = jobs.Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if params.WaitForCompletion {
		return s.waitForCompletion(ctx, jobs, jobName, params.NodeName)
	}
	return nil
}

func (s *Scanner) waitForCompletion(ctx context.Context, jobs batchv1typed.JobInterface, jobName, nodeName string) error {
	return wait.PollUntilWithContext(ctx, s.jobCheckInterval, func(ctx context.Context) (done bool, err error) {
		job, err := jobs.Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return true, err
			}
			return false, nil
		}

		// If node is removed we should stop.
		if _, found := s.deltaState.getNode(nodeName); !found {
			return true, fmt.Errorf("node %s not found for scan job", nodeName)
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
			jobPods, err := s.client.CoreV1().Pods(s.cfg.PodNamespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"job-name": jobName}.String()})
			if err != nil {
				return true, err
			}
			if len(jobPods.Items) == 0 {
				return true, errors.New("job pod not found")
			}
			jobPod := jobPods.Items[0]
			logsStream, err := s.podLogProvider.GetLogReader(ctx, s.cfg.PodNamespace, jobPod.Name)
			if err != nil {
				return true, fmt.Errorf("creating logs stream for failed job: %w", err)
			}
			defer logsStream.Close()
			logs, err := io.ReadAll(logsStream)
			if err != nil {
				return true, fmt.Errorf("reading failed job logs: %w", err)
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
	ns, collectorImage, collectorImagePullPolicy, nodeName, jobName string,
	envVars []corev1.EnvVar,
	vol volumesAndMounts,
	tolerations []corev1.Toleration,
	cfg config.ImageScan,
) *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "castai",
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
			BackoffLimit:            lo.ToPtr(int32(0)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeName:      nodeName,
					RestartPolicy: corev1.RestartPolicyNever,
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
									corev1.ResourceCPU:    resource.MustParse(cfg.CPULimit),
									corev1.ResourceMemory: resource.MustParse(cfg.MemoryLimit),
								},
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    resource.MustParse(cfg.CPURequest),
									corev1.ResourceMemory: resource.MustParse(cfg.MemoryRequest),
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
