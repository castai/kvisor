package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/sec-agent/config"
)

func TestScanner(t *testing.T) {
	r := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("delete already completed job", func(t *testing.T) {
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
			ImageName: "test-image",
			NodeName:  "n1",
		})
		r.NoError(err)

		_, err = client.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		r.True(apierrors.IsNotFound(err))
	})
}
