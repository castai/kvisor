package jobsgc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	CleanupInterval time.Duration
	CleanupJobAge   time.Duration
	Namespace       string
}

func NewGC(log logrus.FieldLogger, clientset kubernetes.Interface, cfg Config) *GC {
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 10 * time.Minute
	}
	if cfg.CleanupJobAge == 0 {
		cfg.CleanupJobAge = 10 * time.Minute
	}
	return &GC{
		log:       log,
		clientset: clientset,
		cfg:       cfg,
	}
}

type GC struct {
	log       logrus.FieldLogger
	clientset kubernetes.Interface
	cfg       Config
}

func (g *GC) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(g.cfg.CleanupInterval):
			func() {
				ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel()
				if err := g.cleanupJobs(ctx); err != nil && !errors.Is(err, context.Canceled) {
					g.log.Errorf("jobs cleanup: %v", err)
				}
			}()
		}
	}
}

func (g *GC) cleanupJobs(ctx context.Context) error {
	selector := labels.Set{"app.kubernetes.io/managed-by": "castai"}.String()
	jobs, err := g.clientset.BatchV1().Jobs(g.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return fmt.Errorf("list jobs for cleanup: %w", err)
	}

	cleanupOlderThan := time.Now().UTC().Add(-g.cfg.CleanupJobAge)

	for _, job := range jobs.Items {
		if job.CreationTimestamp.Time.UTC().Before(cleanupOlderThan) {
			if err := g.clientset.BatchV1().Jobs(g.cfg.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
				GracePeriodSeconds: lo.ToPtr(int64(0)),
				PropagationPolicy:  lo.ToPtr(metav1.DeletePropagationBackground),
			}); err != nil {
				return fmt.Errorf("deleting old job: %w", err)
			}
			g.log.Infof("deleted old job %q", job.Name)
		}
	}
	return nil
}
