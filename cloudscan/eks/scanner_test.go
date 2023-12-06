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

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/config"
)

func TestScanner(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	clusterName := "test-cluster"

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

	failedCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return !v.Passed })
	r.Equal(14, failedCount)
	manualCount := lo.CountBy(castaiClient.sentReport.Checks, func(v castai.CloudScanCheck) bool { return !v.Automated })
	r.Equal(12, manualCount)
	check := castaiClient.sentReport.Checks[0]
	r.Equal(castai.CloudScanCheck{ID: "4.3.1"}, check)
}

type mockCastaiClient struct {
	sentReport *castai.CloudScanReport
}

func (m *mockCastaiClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport, opts ...castai.Option) error {
	m.sentReport = report
	return nil
}

type mockCloudClient struct {
	response *eks.DescribeClusterOutput
}

func (m *mockCloudClient) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return m.response, nil
}
