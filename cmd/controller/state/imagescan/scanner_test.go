package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestScanner(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	ns := "castai-sec"

	t.Run("create scan job", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		r := require.New(t)

		client := fake.NewSimpleClientset()
		scanner := NewImageScanner(client, Config{
			CPURequest:          "500m",
			CPULimit:            "2",
			MemoryRequest:       "100Mi",
			MemoryLimit:         "2Gi",
			ProfileEnabled:      true,
			PhlareEnabled:       true,
			Mode:                "",
			CastaiSecretRefName: "castai-kvisor",
			CastaiGRPCAddress:   "api.cast.ai:443",
			CastaiClusterID:     "abcd",
		}, ns)
		scanner.jobCheckInterval = 1 * time.Microsecond

		err := scanner.ScanImage(ctx, ScanImageParams{
			ImageName:        "test-image",
			ImageID:          "test-image@sha2566282b5ec0c18cfd723e40ef8b98649a47b9388a479c520719c615acc3b073504",
			ContainerRuntime: "containerd",
			Mode:             "hostfs",
			NodeName:         "n1",
			ResourceIDs:      []string{"p1", "p2"},
			Architecture:     "amd64",
			Os:               "linux",
			ScanImageDetails: kube.ImageDetails{
				AgentImageName: "imgcollector:1.0.0",
			},
		})
		r.NoError(err)

		jobs, err := client.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		r.NoError(err)
		r.Len(jobs.Items, 1)
		r.Equal(batchv1.Job{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Job",
				APIVersion: "batch/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"autoscaling.cast.ai/disposable": "true",
				},
				Name:      "castai-imgscan-1ba98dcd098ba64e9b2fe4dafc7a5c85",
				Namespace: ns,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "castai",
				},
			},
			Spec: batchv1.JobSpec{
				TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
				BackoffLimit:            lo.ToPtr(int32(0)),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"phlare.grafana.com/port":   "6060",
							"phlare.grafana.com/scrape": "true",
						},
					},
					Spec: corev1.PodSpec{
						RestartPolicy: "Never",
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
								PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
									{
										Weight: 1,
										Preference: corev1.NodeSelectorTerm{
											MatchExpressions: []corev1.NodeSelectorRequirement{
												{
													Key:      "kubernetes.io/hostname",
													Operator: corev1.NodeSelectorOpIn,
													Values:   []string{"n1"},
												},
											},
										},
									},
								},
							},
						},
						Tolerations: []corev1.Toleration{
							{
								Operator: corev1.TolerationOpExists,
								Key:      "scheduling.cast.ai/spot",
							},
						},
						AutomountServiceAccountToken: lo.ToPtr(false),
						Containers: []corev1.Container{
							{
								Name:  "collector",
								Image: "imgcollector:1.0.0",
								Command: []string{
									"/usr/local/bin/kvisor-agent",
								},
								Args: []string{
									"image-scan",
								},
								EnvFrom: []corev1.EnvFromSource{
									{
										SecretRef: &corev1.SecretEnvSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "castai-kvisor",
											},
										},
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "GOMEMLIMIT",
										Value: "1800MiB",
									},
									{
										Name:  "COLLECTOR_IMAGE_ID",
										Value: "test-image@sha2566282b5ec0c18cfd723e40ef8b98649a47b9388a479c520719c615acc3b073504",
									},
									{
										Name:  "COLLECTOR_IMAGE_NAME",
										Value: "test-image",
									},
									{
										Name:  "COLLECTOR_TIMEOUT",
										Value: "5m",
									},
									{
										Name:  "COLLECTOR_MODE",
										Value: "hostfs",
									},
									{
										Name:  "COLLECTOR_RUNTIME",
										Value: "containerd",
									},
									{
										Name:  "COLLECTOR_RESOURCE_IDS",
										Value: "p1,p2",
									},
									{
										Name:  "COLLECTOR_IMAGE_ARCHITECTURE",
										Value: "amd64",
									},
									{
										Name:  "COLLECTOR_IMAGE_OS",
										Value: "linux",
									},
									{
										Name:  "CASTAI_API_GRPC_ADDR",
										Value: "api.cast.ai:443",
									},
									{
										Name:  "CASTAI_CLUSTER_ID",
										Value: "abcd",
									},
									{
										Name:  "COLLECTOR_PPROF_ADDR",
										Value: ":6060",
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "containerd-content",
										ReadOnly:  true,
										MountPath: "/var/lib/containerd/io.containerd.content.v1.content",
									},
								},
								Resources: corev1.ResourceRequirements{
									Limits: map[corev1.ResourceName]resource.Quantity{
										corev1.ResourceCPU:    resource.MustParse("2"),
										corev1.ResourceMemory: resource.MustParse("2Gi"),
									},
									Requests: map[corev1.ResourceName]resource.Quantity{
										corev1.ResourceCPU:    resource.MustParse("500m"),
										corev1.ResourceMemory: resource.MustParse("100Mi"),
									},
								},
								SecurityContext: &corev1.SecurityContext{
									RunAsUser:                lo.ToPtr(nonRootUserID),
									RunAsNonRoot:             lo.ToPtr(true),
									AllowPrivilegeEscalation: lo.ToPtr(false),
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "containerd-content",
								VolumeSource: corev1.VolumeSource{
									HostPath: &corev1.HostPathVolumeSource{
										Path: "/var/lib/containerd/io.containerd.content.v1.content",
										Type: lo.ToPtr(corev1.HostPathDirectory),
									},
								},
							},
						},
					},
				},
			},
			Status: batchv1.JobStatus{},
		}, jobs.Items[0])
	})

	t.Run("delete already completed job", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		r := require.New(t)

		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "castai-imgscan-1ba98dcd098ba64e9b2fe4dafc7a5c85",
				Namespace: ns,
			},
			Spec: batchv1.JobSpec{},
			Status: batchv1.JobStatus{
				Conditions: []batchv1.JobCondition{
					{
						Type:   batchv1.JobComplete,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		client := fake.NewSimpleClientset(job)
		scanner := NewImageScanner(client, Config{
			CPURequest:    "500m",
			CPULimit:      "2",
			MemoryRequest: "100Mi",
			MemoryLimit:   "2Gi",
		}, ns)
		scanner.jobCheckInterval = 1 * time.Microsecond

		err := scanner.ScanImage(ctx, ScanImageParams{
			ImageName:         "test-image",
			ImageID:           "test-image@sha2566282b5ec0c18cfd723e40ef8b98649a47b9388a479c520719c615acc3b073504",
			ContainerRuntime:  "containerd",
			Mode:              "hostfs",
			NodeName:          "n1",
			ResourceIDs:       []string{"p1", "p2"},
			DeleteFinishedJob: true,
			ScanImageDetails: kube.ImageDetails{
				AgentImageName: "imgcollector:1.0.0",
			},
		})
		r.NoError(err)

		_, err = client.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		r.True(apierrors.IsNotFound(err))
	})

	t.Run("get failed job error with detailed reason", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		r := require.New(t)

		jobPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      "img-scan",
				Labels: map[string]string{
					"job-name": "castai-imgscan-1ba98dcd098ba64e9b2fe4dafc7a5c85",
				},
			},
			Status: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{
						Type:   corev1.PodReady,
						Status: corev1.ConditionFalse,
						Reason: "no cpu",
					},
					{
						Type:   corev1.PodScheduled,
						Status: corev1.ConditionFalse,
						Reason: "no cpu",
					},
				},
			},
		}

		client := fake.NewSimpleClientset(jobPod)
		scanner := NewImageScanner(client, Config{}, ns)
		scanner.jobCheckInterval = 1 * time.Microsecond

		err := scanner.ScanImage(ctx, ScanImageParams{
			ImageName:         "test-image",
			ImageID:           "test-image@sha2566282b5ec0c18cfd723e40ef8b98649a47b9388a479c520719c615acc3b073504",
			ContainerRuntime:  "containerd",
			Mode:              "hostfs",
			NodeName:          "n1",
			ResourceIDs:       []string{"p1", "p2"},
			WaitForCompletion: true,
			ScanImageDetails: kube.ImageDetails{
				AgentImageName: "imgcollector:1.0.0",
			},
		})
		r.ErrorContains(err, "[type=Ready, status=False, reason=no cpu], [type=PodScheduled, status=False, reason=no cpu]")
	})
}
