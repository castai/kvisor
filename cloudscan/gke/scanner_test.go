package gke

import (
	"context"
	"errors"
	"os"
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

func TestParseInfoFromCluster(t *testing.T) {
	r := require.New(t)

	project, loc := parseInfoFromClusterName("projects/my-project/locations/eu-central-1/clusters/test-cluster")

	r.Equal("my-project", project)
	r.Equal("eu-central-1", loc)
}

func TestScannerLocal(t *testing.T) {
	credentialsFile := os.Getenv("GCP_CREDENTIALS_FILE")
	if credentialsFile == "" {
		t.Skip()
	}
	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName == "" {
		t.Skip()
	}

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	castaiClient := &mockCastaiClient{}
	s, err := NewScanner(log, config.CloudScan{
		GKE: &config.CloudScanGKE{
			ClusterName:     clusterName,
			CredentialsFile: credentialsFile,
		},
	}, castaiClient)
	r.NoError(err)

	r.NoError(s.scan(ctx))
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
