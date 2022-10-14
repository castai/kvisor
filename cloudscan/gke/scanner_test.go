package gke

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/iam"
	"github.com/googleapis/gax-go/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	containerpb "google.golang.org/genproto/googleapis/container/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

func TestScanner(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	clusterName := "projects/my-project/locations/eu-central-1/clusters/test-cluster"

	clusterClient := &mockClusterClient{
		clusters: map[string]*containerpb.Cluster{
			clusterName: &containerpb.Cluster{},
		},
	}
	iamClient := &mockIAMClient{}
	castaiClient := &mockCastaiClient{}

	s := Scanner{
		log: log,
		cfg: config.CloudScan{
			Enabled:      true,
			ScanInterval: 1 * time.Millisecond,
			GKE: &config.CloudScanGKE{
				ClusterName: clusterName,
			},
		},
		clusterClient: clusterClient,
		iamClient:     iamClient,
		castaiClient:  castaiClient,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	s.Start(ctx)

	r.NotNil(castaiClient.sentReport)
	check := castaiClient.sentReport.Checks[0]
	r.Equal(castai.CloudScanCheck{
		ID:     "511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider",
		Manual: true,
		Failed: false,
	}, check)
}

type mockClusterClient struct {
	clusters map[string]*containerpb.Cluster
}

func (m *mockClusterClient) GetCluster(ctx context.Context, req *containerpb.GetClusterRequest, opts ...gax.CallOption) (*containerpb.Cluster, error) {
	v, ok := m.clusters[req.Name]
	if !ok {
		return nil, errors.New("cluster not found")
	}
	return v, nil
}

type mockIAMClient struct {
}

func (m *mockIAMClient) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iam.Policy, error) {
	return nil, nil
}

type mockCastaiClient struct {
	sentReport *castai.CloudScanReport
}

func (m *mockCastaiClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error {
	m.sentReport = report
	return nil
}
