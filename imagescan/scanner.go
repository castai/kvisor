package imagescan

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/samber/lo"
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
	ScanImage(ctx context.Context, cfg ScanImageConfig) (err error)
}

func NewImageScanner(client kubernetes.Interface, cfg config.Config) *Scanner {
	return &Scanner{
		client:           client,
		jobCheckInterval: 5 * time.Second,
	}
}

type Scanner struct {
	client           kubernetes.Interface
	cfg              config.Config
	jobCheckInterval time.Duration
}

type ScanImageConfig struct {
	ImageName         string
	ImageID           string
	NodeName          string
	DeleteFinishedJob bool
	WaitForCompletion bool
}

func (s *Scanner) ScanImage(ctx context.Context, cfg ScanImageConfig) (rerr error) {
	h := fnv.New128()
	h.Write([]byte(cfg.ImageName))
	imgHash := hex.EncodeToString(h.Sum(nil))
	jobName := fmt.Sprintf("imgscan-%s", imgHash)

	mode := imgcollectorconfig.Mode(s.cfg.Features.ImageScan.Mode)
	if mode == "" {
		imgParts := strings.Split(cfg.ImageID, "://")
		containerRuntime := imgParts[0]
		switch containerRuntime {
		case "docker":
			mode = imgcollectorconfig.ModeDockerDaemon
		case "containerd":
			mode = imgcollectorconfig.ModeContainerdDaemon
		}
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "ARTIFACTS_COLLECTOR_IMAGE_ID",
			Value: cfg.ImageID,
		},
		{
			Name:  "ARTIFACTS_COLLECTOR_IMAGE_NAME",
			Value: cfg.ImageName,
		},
		{
			Name:  "ARTIFACTS_COLLECTOR_TIMEOUT",
			Value: "5m",
		},
		{
			Name:  "ARTIFACTS_COLLECTOR_MODE",
			Value: string(mode),
		},
		{
			Name:  "ARTIFACTS_COLLECTOR_API_URL",
			Value: s.cfg.Features.ImageScan.ImageCollectorImage,
		},
		{
			Name:  "ARTIFACTS_COLLECTOR_DOCKER_OPTION_PATH",
			Value: s.cfg.Features.ImageScan.DockerOptionsPath,
		},
	}

	jobSpec := scanJobSpec(s.cfg.Features.ImageScan.ImageCollectorImage, cfg.NodeName, jobName, envVars)
	jobs := s.client.BatchV1().Jobs(ns)

	if cfg.DeleteFinishedJob {
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

	if cfg.WaitForCompletion {
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
			return true, errors.New("image scan job failed")
		}
		return false, nil
	})
}

// TODO: Pass imageName or imageID dependency on actual job implementation.
func scanJobSpec(collectorImage, nodeName, jobName string, envVars []corev1.EnvVar) *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: ns,
			Labels:    map[string]string{"app": "castai-image-scan"},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
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
					// TODO: Tolerations
					Containers: []corev1.Container{
						{
							Name:  "image-collector",
							Image: collectorImage,
							Env:   envVars,
							// TODO: Mount /var/lib/docker/image/overlay2 for images parsing.
							VolumeMounts: []corev1.VolumeMount{},
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
					// TODO: Mount /var/lib/docker/image/overlay2 for images parsing.
					Volumes: []corev1.Volume{},
				},
			},
		},
	}
}
