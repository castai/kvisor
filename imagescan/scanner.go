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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	batchv1typed "k8s.io/client-go/kubernetes/typed/batch/v1"

	imgcollectorconfig "github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/config"
	"github.com/castai/kvisor/log"
)

const (
	nonRootUserID = int64(65532)
)

var (
	errJobPodNotFound = errors.New("job pod not found")
)

type imageScanner interface {
	ScanImage(ctx context.Context, cfg ScanImageParams) (err error)
}

func NewImageScanner(client kubernetes.Interface, cfg config.Config) *Scanner {
	return &Scanner{
		podLogProvider:   log.NewPodLogReader(client),
		client:           client,
		jobCheckInterval: 5 * time.Second,
		cfg:              cfg,
	}
}

type Scanner struct {
	podLogProvider   log.PodLogProvider
	client           kubernetes.Interface
	cfg              config.Config
	jobCheckInterval time.Duration
}

type ScanImageParams struct {
	ImageName                   string // Example: ghcr.io/castai/kvisor/kvisor:8889dc92d6c69420a811de4fc67e619a30c028e9
	ImageID                     string // Example: ghcr.io/castai/kvisor/kvisor@sha256:2db087348c66274941013a3163036b1ca09da03ea64e9f9cdd79b8f647e4fe44
	ContainerRuntime            string
	Mode                        string
	NodeName                    string
	ResourceIDs                 []string
	DeleteFinishedJob           bool
	WaitForCompletion           bool
	WaitDurationAfterCompletion time.Duration
	Architecture                string
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
	if s.cfg.PodNamespace == "" {
		return errors.New("pod namespace is required")
	}

	jobName := genJobName(params.ImageName)
	vols := volumesAndMounts{}
	mode := imgcollectorconfig.Mode(params.Mode)
	containerRuntime := params.ContainerRuntime

	switch containerRuntime {
	case "docker":
		if mode == "" {
			mode = imgcollectorconfig.ModeDaemon
		}
		if mode == imgcollectorconfig.ModeDaemon {
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
		}
	case "containerd":
		if mode == "" {
			mode = imgcollectorconfig.ModeHostFS
		}
		if mode == imgcollectorconfig.ModeHostFS {
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
		} else if mode == imgcollectorconfig.ModeDaemon {
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
		}
		if s.cfg.ImageScan.PullSecret != "" {
			vols.volumes = append(vols.volumes, corev1.Volume{
				Name: "pull-secret",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: s.cfg.ImageScan.PullSecret,
					},
				},
			})
			vols.mounts = append(vols.mounts, corev1.VolumeMount{
				Name:      "pull-secret",
				ReadOnly:  true,
				MountPath: imgcollectorconfig.SecretMountPath,
			})
		}
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "GOMEMLIMIT",
			Value: "1800MiB",
		},
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
			Name:  "COLLECTOR_RUNTIME",
			Value: containerRuntime,
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
			Name:  "KVISOR_SERVER_API_URL",
			Value: s.cfg.ImageScan.APIUrl,
		},
		{
			Name:  "COLLECTOR_IMAGE_ARCHITECTURE",
			Value: params.Architecture,
		},
	}

	if s.cfg.ImageScan.PullSecret != "" {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "COLLECTOR_PULL_SECRET",
			Value: s.cfg.ImageScan.PullSecret,
		})
	}

	podAnnotations := map[string]string{}
	if s.cfg.ImageScan.ProfileEnabled {
		if s.cfg.ImageScan.PhlareEnabled {
			podAnnotations["phlare.grafana.com/scrape"] = "true"
			podAnnotations["phlare.grafana.com/port"] = "6060"
		}
		envVars = append(envVars, corev1.EnvVar{
			Name:  "COLLECTOR_PPROF_ADDR",
			Value: ":6060",
		})
	}

	tolerations := []corev1.Toleration{
		{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		},
	}

	jobSpec := scanJobSpec(
		s.cfg.PodNamespace,
		params.NodeName,
		jobName,
		envVars,
		podAnnotations,
		vols,
		tolerations,
		s.cfg.ImageScan,
	)
	jobs := s.client.BatchV1().Jobs(s.cfg.PodNamespace)

	if params.DeleteFinishedJob {
		defer func() {
			// Useful to keep job for a while to troubleshoot issues.
			if params.WaitDurationAfterCompletion != 0 {
				select {
				case <-ctx.Done():
					rerr = ctx.Err()
					return
				case <-time.After(params.WaitDurationAfterCompletion):
				}
			}

			if err := jobs.Delete(ctx, jobSpec.Name, metav1.DeleteOptions{
				PropagationPolicy: lo.ToPtr(metav1.DeletePropagationBackground),
			}); err != nil && !apierrors.IsNotFound(err) {
				rerr = fmt.Errorf("deleting finished job: %w", err)
			}
		}()
	}

	// If job already exist wait for completion and exit.
	_, err := jobs.Get(ctx, jobSpec.Name, metav1.GetOptions{})
	if err == nil {
		if err := s.waitForCompletion(ctx, jobs, jobName); err != nil {
			return fmt.Errorf("job already exist, wait for completion: %w", err)
		}
		return nil
	}

	// Create new job and wait for completion.
	_, err = jobs.Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating job: %w", err)
	}

	if params.WaitForCompletion {
		if err := s.waitForCompletion(ctx, jobs, jobName); err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			jobPod, _ := s.getJobPod(ctx, jobName)
			if jobPod != nil {
				conds := getPodConditionsString(jobPod.Status.Conditions)
				return fmt.Errorf("wait for completion, pod_conditions=%s: %w", conds, err)
			}
			return fmt.Errorf("wait for completion: %w", err)
		}
	}
	return nil
}

func getPodConditionsString(conditions []corev1.PodCondition) string {
	var condStrings []string
	for _, condition := range conditions {
		reason := condition.Reason
		if reason == "" {
			reason = condition.Message
		}
		condStrings = append(condStrings, fmt.Sprintf("[type=%s, status=%s, reason=%s]", condition.Type, condition.Status, reason))
	}
	return strings.Join(condStrings, ", ")
}

func (s *Scanner) waitForCompletion(ctx context.Context, jobs batchv1typed.JobInterface, jobName string) error {
	return wait.PollUntilContextCancel(ctx, s.jobCheckInterval, false, func(ctx context.Context) (done bool, err error) {
		job, err := jobs.Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
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
			jobPod, err := s.getJobPod(ctx, jobName)
			if err != nil {
				return true, err
			}
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

func (s *Scanner) getJobPod(ctx context.Context, jobName string) (*corev1.Pod, error) {
	jobPods, err := s.client.CoreV1().Pods(s.cfg.PodNamespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"job-name": jobName}.String()})
	if err != nil {
		return nil, err
	}
	if len(jobPods.Items) == 0 {
		return nil, errJobPodNotFound
	}
	if l := len(jobPods.Items); l != 1 {
		return nil, fmt.Errorf("expected to get one job pod, got %d", l)
	}
	return &jobPods.Items[0], nil
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
	ns, nodeName, jobName string,
	envVars []corev1.EnvVar,
	annotations map[string]string,
	vol volumesAndMounts,
	tolerations []corev1.Toleration,
	cfg config.ImageScan,
) *batchv1.Job {
	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: ns,
			Annotations: map[string]string{
				"autoscaling.cast.ai/disposable": "true",
			},
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "castai",
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
			BackoffLimit:            lo.ToPtr(int32(0)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"kubernetes.io/hostname": nodeName,
					},
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
					Tolerations:                  tolerations,
					AutomountServiceAccountToken: lo.ToPtr(false),
					ServiceAccountName:           cfg.ServiceAccountName,
					Containers: []corev1.Container{
						{
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                lo.ToPtr(nonRootUserID),
								RunAsNonRoot:             lo.ToPtr(true),
								AllowPrivilegeEscalation: lo.ToPtr(false),
							},
							Name:            "collector",
							Image:           cfg.Image.Name,
							ImagePullPolicy: corev1.PullPolicy(cfg.Image.PullPolicy),
							Env:             envVars,
							VolumeMounts:    vol.mounts,
							Resources:       corev1.ResourceRequirements{},
						},
					},
					Volumes: vol.volumes,
				},
			},
		},
	}

	if cfg.CPULimit != "" {
		cpuLimit := resource.MustParse(cfg.CPULimit)
		if job.Spec.Template.Spec.Containers[0].Resources.Limits == nil {
			job.Spec.Template.Spec.Containers[0].Resources.Limits = map[corev1.ResourceName]resource.Quantity{}
		}
		job.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = cpuLimit
	}

	if cfg.CPURequest != "" {
		cpuRequest := resource.MustParse(cfg.CPURequest)
		if job.Spec.Template.Spec.Containers[0].Resources.Requests == nil {
			job.Spec.Template.Spec.Containers[0].Resources.Requests = map[corev1.ResourceName]resource.Quantity{}
		}
		job.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = cpuRequest
	}

	if cfg.MemoryRequest != "" {
		memRequest := resource.MustParse(cfg.MemoryRequest)
		if job.Spec.Template.Spec.Containers[0].Resources.Requests == nil {
			job.Spec.Template.Spec.Containers[0].Resources.Requests = map[corev1.ResourceName]resource.Quantity{}
		}
		job.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = memRequest
	}

	if cfg.MemoryLimit != "" {
		memLimit := resource.MustParse(cfg.MemoryLimit)
		if job.Spec.Template.Spec.Containers[0].Resources.Limits == nil {
			job.Spec.Template.Spec.Containers[0].Resources.Limits = map[corev1.ResourceName]resource.Quantity{}
		}
		job.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceMemory] = memLimit
	}
	return job
}
