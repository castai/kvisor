package gke

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/binaryauthorization/apiv1/binaryauthorizationpb"
	"cloud.google.com/go/container/apiv1/containerpb"
	"cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"github.com/davecgh/go-spew/spew"
	"github.com/googleapis/gax-go/v2"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/config"
)

func TestScannerFailAutomatedChecks(t *testing.T) {
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
							ServiceAccount: "default",
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
	serviceUsageClient := &mockServiceUsageClient{
		services: map[string]*serviceusagepb.Service{
			"projects/test/services/containerscanning.googleapis.com":   {},
			"projects/test/services/binaryauthorization.googleapis.com": {},
		},
	}
	binauthClient := &mockBinauthClient{
		policy: map[string]*binaryauthorizationpb.Policy{
			"projects/test/policy": {},
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
		project:            "test",
		clusterClient:      clusterClient,
		castaiClient:       castaiClient,
		serviceUsageClient: serviceUsageClient,
		binauthzClient:     binauthClient,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	s.Start(ctx)

	r.NotNil(castaiClient.sentReport)

	r.Len(castaiClient.sentReport.Checks, 38)
	failedCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return !v.Passed })
	r.Equal(36, failedCount)
	check := castaiClient.sentReport.Checks[0]
	r.Equal(castai.CloudScanCheck{
		ID: "4.3.1",
	}, check)

	failedAutomatedChecks := lo.Map(lo.Filter(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck, _ int) bool {
		return !v.Passed && v.Automated
	}), func(v castai.CloudScanCheck, _ int) string {
		return v.ID
	})
	r.Equal([]string{
		"5.2.1",
		"5.4.1",
		"5.4.2",
		"5.5.1",
		"5.5.2",
		"5.5.3",
		"5.5.6",
		"5.5.7",
		"5.6.1",
		"5.6.2",
		"5.7.1",
		"5.8.1",
		"5.8.2",
		"5.8.4",
		"5.10.1",
		"5.10.2",
		"5.10.5",
	}, failedAutomatedChecks)
}

func TestScannerPassAutomatedChecks(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	clusterName := "projects/my-project/locations/eu-central-1/clusters/test-cluster"

	clusterClient := &mockClusterClient{
		clusters: map[string]*containerpb.Cluster{
			clusterName: {
				Name:              "test-cluster",
				MasterAuth:        &containerpb.MasterAuth{},
				LoggingService:    "enabled",
				MonitoringService: "enabled",
				AddonsConfig:      &containerpb.AddonsConfig{},
				IpAllocationPolicy: &containerpb.IPAllocationPolicy{
					UseIpAliases: true,
				},
				BinaryAuthorization: &containerpb.BinaryAuthorization{
					EvaluationMode: containerpb.BinaryAuthorization_PROJECT_SINGLETON_POLICY_ENFORCE,
				},
				NodePools: []*containerpb.NodePool{
					{
						Name: "pool-1",
						Config: &containerpb.NodeConfig{
							Metadata: map[string]string{
								"disable-legacy-endpoints": "true",
							},
							ImageType: "COS",
							WorkloadMetadataConfig: &containerpb.WorkloadMetadataConfig{
								Mode: containerpb.WorkloadMetadataConfig_GKE_METADATA,
							},
							ShieldedInstanceConfig: &containerpb.ShieldedInstanceConfig{
								EnableSecureBoot:          true,
								EnableIntegrityMonitoring: true,
							},
							ServiceAccount: "custom",
						},
						Management: &containerpb.NodeManagement{
							AutoUpgrade: true,
							AutoRepair:  true,
						},
					},
				},
				EnableKubernetesAlpha: false,
				LegacyAbac:            &containerpb.LegacyAbac{Enabled: false},
				NetworkConfig:         &containerpb.NetworkConfig{EnableIntraNodeVisibility: true},
			},
		},
	}
	serviceUsageClient := &mockServiceUsageClient{
		services: map[string]*serviceusagepb.Service{
			"projects/test/services/containerscanning.googleapis.com": {
				State: serviceusagepb.State_ENABLED,
			},
			"projects/test/services/binaryauthorization.googleapis.com": {
				State: serviceusagepb.State_ENABLED,
			},
		},
	}
	binauthClient := &mockBinauthClient{
		policy: map[string]*binaryauthorizationpb.Policy{
			"projects/test/policy": {},
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
		project:            "test",
		clusterClient:      clusterClient,
		castaiClient:       castaiClient,
		serviceUsageClient: serviceUsageClient,
		binauthzClient:     binauthClient,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	s.Start(ctx)

	r.NotNil(castaiClient.sentReport)

	failedAutomatedChecks := lo.Map(lo.Filter(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck, _ int) bool {
		return !v.Passed && v.Automated
	}), func(v castai.CloudScanCheck, _ int) string {
		return v.ID
	})
	r.Empty(failedAutomatedChecks)
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
	}, false, castaiClient)
	r.NoError(err)

	r.NoError(s.scan(ctx))
	spew.Dump(castaiClient.sentReport.Checks)
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

type mockServiceUsageClient struct {
	services map[string]*serviceusagepb.Service
}

func (m *mockServiceUsageClient) GetService(ctx context.Context, req *serviceusagepb.GetServiceRequest, opts ...gax.CallOption) (*serviceusagepb.Service, error) {
	v, ok := m.services[req.Name]
	if ok {
		return v, nil
	}
	return nil, fmt.Errorf("service %q not found", req.Name)
}

type mockBinauthClient struct {
	policy map[string]*binaryauthorizationpb.Policy
}

func (m *mockBinauthClient) GetPolicy(ctx context.Context, req *binaryauthorizationpb.GetPolicyRequest, opts ...gax.CallOption) (*binaryauthorizationpb.Policy, error) {
	v, ok := m.policy[req.Name]
	if ok {
		return v, nil
	}
	return nil, fmt.Errorf("policy %q not found", req.Name)
}
