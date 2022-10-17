package gke

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/googleapis/gax-go/v2"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	containerpb "google.golang.org/genproto/googleapis/container/v1"

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
			clusterName: {
				Name: "test-cluster",
				MasterAuth: &containerpb.MasterAuth{
					Username:  "user", //nolint:staticcheck
					Password:  "pass", //nolint:staticcheck
					ClientKey: "key",
				},
				LoggingService:    "none",
				MonitoringService: "none",
				AddonsConfig: &containerpb.AddonsConfig{
					KubernetesDashboard: &containerpb.KubernetesDashboard{}, //nolint:staticcheck
				},
				NodePools: []*containerpb.NodePool{
					{
						Name: "pool-1",
						Config: &containerpb.NodeConfig{
							Metadata: map[string]string{
								"disable-legacy-endpoints": "false",
							},
							ImageType:              "FAKE",
							WorkloadMetadataConfig: nil,
							ShieldedInstanceConfig: &containerpb.ShieldedInstanceConfig{
								EnableSecureBoot:          false,
								EnableIntegrityMonitoring: false,
							},
						},
						Management: &containerpb.NodeManagement{
							AutoUpgrade: false,
							AutoRepair:  false,
						},
					},
				},
				EnableKubernetesAlpha: true,
				LegacyAbac:            &containerpb.LegacyAbac{Enabled: true},
				NetworkConfig:         &containerpb.NetworkConfig{EnableIntraNodeVisibility: false},
			},
		},
	}
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
		castaiClient:  castaiClient,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	s.Start(ctx)

	r.NotNil(castaiClient.sentReport)

	failedCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return v.Failed })
	r.Equal(16, failedCount)
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

type mockCastaiClient struct {
	sentReport *castai.CloudScanReport
}

func (m *mockCastaiClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error {
	m.sentReport = report
	return nil
}
