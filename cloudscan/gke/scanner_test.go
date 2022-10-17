package gke

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/googleapis/gax-go/v2"
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
				Name:                           "test-cluster",
				MasterAuth:                     nil,
				LoggingService:                 "",
				MonitoringService:              "",
				Network:                        "",
				ClusterIpv4Cidr:                "",
				AddonsConfig:                   nil,
				Subnetwork:                     "",
				NodePools:                      nil,
				Locations:                      nil,
				EnableKubernetesAlpha:          false,
				ResourceLabels:                 nil,
				LabelFingerprint:               "",
				LegacyAbac:                     nil,
				NetworkPolicy:                  nil,
				IpAllocationPolicy:             nil,
				MasterAuthorizedNetworksConfig: nil,
				MaintenancePolicy:              nil,
				BinaryAuthorization:            nil,
				Autoscaling:                    nil,
				NetworkConfig:                  nil,
				DefaultMaxPodsConstraint:       nil,
				ResourceUsageExportConfig:      nil,
				AuthenticatorGroupsConfig:      nil,
				PrivateClusterConfig:           nil,
				DatabaseEncryption:             nil,
				VerticalPodAutoscaling:         nil,
				ShieldedNodes:                  nil,
				ReleaseChannel:                 nil,
				WorkloadIdentityConfig:         nil,
				MeshCertificates:               nil,
				NotificationConfig:             nil,
				ConfidentialNodes:              nil,
				IdentityServiceConfig:          nil,
				SelfLink:                       "",
				Zone:                           "",
				Endpoint:                       "",
				InitialClusterVersion:          "",
				CurrentMasterVersion:           "",
				CurrentNodeVersion:             "",
				CreateTime:                     "",
				Status:                         0,
				StatusMessage:                  "",
				NodeIpv4CidrSize:               0,
				ServicesIpv4Cidr:               "",
				InstanceGroupUrls:              nil,
				CurrentNodeCount:               0,
				ExpireTime:                     "",
				Location:                       "",
				EnableTpu:                      false,
				TpuIpv4CidrBlock:               "",
				Conditions:                     nil,
				Autopilot:                      nil,
				Id:                             "",
				NodePoolDefaults:               nil,
				LoggingConfig:                  nil,
				MonitoringConfig:               nil,
				NodePoolAutoConfig:             nil,
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
