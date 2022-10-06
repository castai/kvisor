package gke

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	containerpb "google.golang.org/genproto/googleapis/container/v1"

	"github.com/castai/sec-agent/config"

	container "cloud.google.com/go/container/apiv1"
)

func NewScanner(log logrus.FieldLogger) (*Scanner, error) {
	clusterClient, err := container.NewClusterManagerClient(context.TODO())
	if err != nil {
		return nil, err
	}

	return &Scanner{
		log:           log,
		clusterClient: clusterClient,
	}, nil
}

type Scanner struct {
	log           logrus.FieldLogger
	cfg           config.CloudScan
	clusterClient *container.ClusterManagerClient
}

func (s *Scanner) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.ScanInterval):
			if err := s.scan(ctx); err != nil {
				s.log.Errorf("gke cloud scan failed: %v", err)
			}
		}
	}
}

func (s *Scanner) scan(ctx context.Context) error {
	s.clusterClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		ProjectId: "",
		Zone:      "",
		ClusterId: "",
		Name:      "",
	})
	return nil
}
