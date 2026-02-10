package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/castai/logging"
	"github.com/samber/lo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type JobsCleanupConfig struct {
	CleanupInterval time.Duration `validate:"required" json:"cleanupInterval"`
	CleanupJobAge   time.Duration `validate:"required" json:"cleanupJobAge"`
	Namespace       string        `validate:"required" json:"namespace"`
}

func NewJobsCleanupController(log *logging.Logger, clientset kubernetes.Interface, cfg JobsCleanupConfig) *JobsCleanupController {
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 10 * time.Minute
	}
	if cfg.CleanupJobAge == 0 {
		cfg.CleanupJobAge = 10 * time.Minute
	}
	return &JobsCleanupController{
		log:       log.WithField("component", "jobs_cleanup"),
		clientset: clientset,
		cfg:       cfg,
	}
}

type JobsCleanupController struct {
	log       *logging.Logger
	clientset kubernetes.Interface
	cfg       JobsCleanupConfig
}

func (c *JobsCleanupController) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.cfg.CleanupInterval):
			func() {
				ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel()
				if err := c.cleanupJobs(ctx); err != nil && !errors.Is(err, context.Canceled) {
					c.log.Errorf("jobs cleanup: %v", err)
				}
			}()
		}
	}
}

func (c *JobsCleanupController) cleanupJobs(ctx context.Context) error {
	selector := labels.Set{"app.kubernetes.io/managed-by": "castai"}.String()
	jobs, err := c.clientset.BatchV1().Jobs(c.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return fmt.Errorf("list jobs for cleanup: %w", err)
	}

	cleanupOlderThan := time.Now().UTC().Add(-c.cfg.CleanupJobAge)

	for _, job := range jobs.Items {
		if job.CreationTimestamp.Time.UTC().Before(cleanupOlderThan) {
			if err := c.clientset.BatchV1().Jobs(c.cfg.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
				GracePeriodSeconds: lo.ToPtr(int64(0)),
				PropagationPolicy:  lo.ToPtr(metav1.DeletePropagationBackground),
			}); err != nil {
				return fmt.Errorf("deleting old job: %w", err)
			}
			c.log.Infof("deleted old job %q", job.Name)
		}
	}
	return nil
}
