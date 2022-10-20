package eks

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

func TestScanner(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	clusterName := "projects/my-project/locations/eu-central-1/clusters/test-cluster"

	eksClient := &mockCloudClient{
		response: &eks.DescribeClusterOutput{
			Cluster: &types.Cluster{
				ResourcesVpcConfig: &types.VpcConfigResponse{},
			},
			ResultMetadata: middleware.Metadata{},
		},
	}
	castaiClient := &mockCastaiClient{}

	s := Scanner{
		log: log,
		cfg: &config.CloudScan{
			Enabled:      true,
			ScanInterval: 1 * time.Millisecond,
			EKS: &config.CloudScanEKS{
				ClusterName: clusterName,
			},
		},
		eksClient:    eksClient,
		castaiClient: castaiClient,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	s.Start(ctx)

	r.NotNil(castaiClient.sentReport)

	failedCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return v.Failed })
	r.Equal(2, failedCount)
	manualCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return v.Manual })
	r.Equal(11, manualCount)
	check := castaiClient.sentReport.Checks[0]
	r.Equal(castai.CloudScanCheck{
		ID:     "5.1.1",
		Manual: true,
		Failed: false,
	}, check)
}

type mockCastaiClient struct {
	sentReport *castai.CloudScanReport
}

func (m *mockCastaiClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error {
	m.sentReport = report
	return nil
}

type mockCloudClient struct {
	response *eks.DescribeClusterOutput
}

func (m *mockCloudClient) DescribeCluster(context.Context, *eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
	return m.response, nil
}
