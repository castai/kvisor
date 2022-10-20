package eks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	json "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

type Scanner struct {
	cfg          *config.CloudScan
	log          logrus.FieldLogger
	eksClient    eksClient
	castaiClient castaiClient
}

type eksClient interface {
	DescribeCluster(context.Context, *eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error)
}

type castaiClient interface {
	SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error
}

func NewScanner(log logrus.FieldLogger, cfg config.CloudScan, eksClient eksClient, client castaiClient) *Scanner {
	return &Scanner{
		cfg:          &cfg,
		log:          log,
		eksClient:    eksClient,
		castaiClient: client,
	}
}

func (s *Scanner) Start(ctx context.Context) {
	for {
		s.log.Info("scanning cloud")
		if err := s.scan(ctx); err != nil {
			s.log.Errorf("aws cloud scan failed: %v", err)
		} else {
			s.log.Info("aws cloud scan finished")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.ScanInterval):
		}
	}
}

func (s *Scanner) scan(ctx context.Context) error {
	cluster, err := s.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: lo.ToPtr(s.cfg.EKS.ClusterName)})
	if err != nil {
		return fmt.Errorf("describe cluster: %w", err)
	}

	checks := []check{
		check511EnsureImageVulnerabilityScanningUsingAmazonECRImageScanningOrThirdPartyProvider(),
		check512MinimizeUserAccessToAmazonECR(),
		check513MinimizeClusterAccessToReadOnlyForAmazonECR(),
		check514MinimizeContainerRegistriesToOnlyThoseApproved(),
		check521PreferUsingManagedIdentitiesForWorkloads(),
		check531EnsureKubernetesSecretsAreEncryptedUsingCustomerMasterKeysCMKsManagedInAWSKMS(cluster),
		check541RestrictAccessToTheControlPlaneEndpoint(),
		check542EnsureClustersAreCreatedWithPrivateEndpointEnabledAndPublicAccessDisabled(cluster),
		check543EnsureClustersAreCreatedWithPrivateNodes(),
		check544EnsureNetworkPolicyIsEnabledAndSetAsAppropriate(),
		check545EncryptTrafficToHTTPSLoadBalancersWithTLSCertificates(),
		check551ManageKubernetesRBACUsersWithAWSIAMAuthenticatorForKubernetes(),
		check561ConsiderFargateForRunningUntrustedWorkloads(),
	}

	report := &castai.CloudScanReport{
		Checks: make([]castai.CloudScanCheck, 0, len(checks)),
	}

	for _, c := range checks {
		if c.validate != nil {
			c.validate(&c)
		}
		var err error
		var contextBytes json.RawMessage
		if c.context != nil {
			contextBytes, err = json.Marshal(c.context)
			if err != nil {
				return err
			}
		}
		report.Checks = append(report.Checks, castai.CloudScanCheck{
			ID:      c.id,
			Manual:  c.manual,
			Failed:  c.failed,
			Context: contextBytes,
		})
	}

	if err := s.castaiClient.SendCISCloudScanReport(ctx, report); err != nil {
		return err
	}

	return nil
}
