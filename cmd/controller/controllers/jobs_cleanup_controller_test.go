package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestJobsCleanupController(t *testing.T) {
	r := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := logging.NewTestLog()
	ns := "castai-agent"

	oldJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "old-job",
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "castai",
			},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-11 * time.Minute)),
		},
	}

	newJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-job",
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "castai",
			},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Minute)),
		},
	}

	clientset := fake.NewSimpleClientset(oldJob, newJob)

	gc := NewJobsCleanupController(log, clientset, JobsCleanupConfig{
		CleanupInterval: 1 * time.Millisecond,
		CleanupJobAge:   10 * time.Minute,
		Namespace:       ns,
	})
	go func() {
		err := gc.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			r.Error(err)
		}
	}()

	r.Eventually(func() bool {
		jobs, err := clientset.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		r.NoError(err)
		return len(jobs.Items) == 1 && jobs.Items[0].Name == newJob.Name
	}, 3*time.Second, 1*time.Millisecond)
}
