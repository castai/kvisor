package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/sec-agent/config"
)

func TestScanner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("create scan job", func(t *testing.T) {
		t.Skip()
		// TODO: Finish test.

		r := require.New(t)

		client := fake.NewSimpleClientset()
		scanner := NewImageScanner(client, config.Config{})
		scanner.jobCheckInterval = 1 * time.Microsecond

		err := scanner.ScanImage(ctx, ScanImageConfig{
			ImageName: "test-image",
			NodeName:  "n1",
		})
		r.NoError(err)

		jobs, err := client.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		r.NoError(err)
		r.Len(jobs.Items, 1)
		r.Equal(batchv1.Job{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "imgscan-1ba98dcd098ba64e9b2fe4dafc7a5c85",
				Namespace: ns,
			},
			Spec: batchv1.JobSpec{
				TTLSecondsAfterFinished: lo.ToPtr(int32(100)),
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeName:      "test",
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
								Image: "image-name",
								Env:   []corev1.EnvVar{},
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
			Status: batchv1.JobStatus{
				Conditions: []batchv1.JobCondition{
					//{
					//	Type:   batchv1.JobComplete,
					//	Status: corev1.ConditionTrue,
					//},
				},
			},
		}, jobs.Items[0])
	})

	t.Run("delete already completed job", func(t *testing.T) {
		r := require.New(t)

		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "imgscan-1ba98dcd098ba64e9b2fe4dafc7a5c85",
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
		scanner := NewImageScanner(client, config.Config{})
		scanner.jobCheckInterval = 1 * time.Microsecond

		err := scanner.ScanImage(ctx, ScanImageConfig{
			ImageName:         "test-image",
			NodeName:          "n1",
			DeleteFinishedJob: true,
		})
		r.NoError(err)

		_, err = client.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		r.True(apierrors.IsNotFound(err))
	})
}
