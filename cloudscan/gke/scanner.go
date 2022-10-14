package gke

import (
	"context"
	"time"

	"cloud.google.com/go/iam"
	"github.com/googleapis/gax-go/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"

	containerv1 "cloud.google.com/go/container/apiv1"
	iamv1 "cloud.google.com/go/iam/admin/apiv1"
	containerpb "google.golang.org/genproto/googleapis/container/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
)

type clusterClient interface {
	GetCluster(ctx context.Context, req *containerpb.GetClusterRequest, opts ...gax.CallOption) (*containerpb.Cluster, error)
}

type iamClient interface {
	GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iam.Policy, error)
}

type castaiClient interface {
	SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error
}

func NewScanner(log logrus.FieldLogger, cfg config.CloudScan, client castaiClient) (*Scanner, error) {
	ctx := context.Background()

	var opts []option.ClientOption
	if cfg.GKE.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.GKE.CredentialsFile))
	}
	if cfg.GKE.ServiceAccountName != "" {
		opts = append(opts, option.WithTokenSource(newMetadataTokenSource()))
	}
	clusterClient, err := containerv1.NewClusterManagerClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	iamClient, err := iamv1.NewIamClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		log:           log,
		cfg:           cfg,
		clusterClient: clusterClient,
		iamClient:     iamClient,
		castaiClient:  client,
	}, nil
}

type check struct {
	id          string
	description string
	manual      bool

	failed   bool
	validate func() error
}

type Scanner struct {
	log           logrus.FieldLogger
	cfg           config.CloudScan
	clusterClient clusterClient
	iamClient     iamClient
	castaiClient  castaiClient
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
	_, err := s.clusterClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: s.cfg.GKE.ClusterName,
	})
	if err != nil {
		return err
	}

	checks := []check{check511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider(),
		check512MinimizeuseraccesstoGCR(),
		check513MinimizeclusteraccesstoreadonlyforGCR(),
		check514MinimizeContainerRegistriestoonlythoseapproved(),
		check521EnsureGKEclustersarenotrunningusingtheComputeEnginedefaultserviceaccount(),
		check522PreferusingdedicatedGCPServiceAccountsandWorkloadIdentity(),
		check531EnsureKubernetesSecretsareencryptedusingkeysmanagedinCloudKMS(),
		check541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled(),
		check542EnsuretheGKEMetadataServerisEnabled(),
		check1551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages(),
		check552EnsureNodeAutoRepairisenabledforGKEnodes(),
		check553EnsureNodeAutoUpgradeisenabledforGKEnodes(),
		check554WhencreatingNewClustersAutomateGKEversionmanagementusingReleaseChannels(),
		check555EnsureShieldedGKENodesareEnabled(),
		check556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled(),
		check557EnsureSecureBootforShieldedGKENodesisEnabled(),
		check561EnableVPCFlowLogsandIntranodeVisibility(),
		check562EnsureuseofVPCnativeclusters(),
		check563EnsureMasterAuthorizedNetworksisEnabled(),
		check564EnsureclustersarecreatedwithPrivateEndpointEnabledandPublicAccessDisabled(),
		check565EnsureclustersarecreatedwithPrivateNodes(),
		check566ConsiderfirewallingGKEworkernodes(),
		check567EnsureNetworkPolicyisEnabledandsetasappropriate(),
		check568EnsureuseofGooglemanagedSSLCertificates(),
		check571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled(),
		check572EnableLinuxauditdlogging(),
		check581EnsureBasicAuthenticationusingstaticpasswordsisDisabled(),
		check582EnsureauthenticationusingClientCertificatesisDisabled(),
		check583ManageKubernetesRBACuserswithGoogleGroupsforGKE(),
		check584EnsureLegacyAuthorizationABACisDisabled(),
		check591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD(),
		check5101EnsureKubernetesWebUIisDisabled(),
		check5102EnsurethatAlphaclustersarenotusedforproductionworkloads(),
		check5103EnsurePodSecurityPolicyisEnabledandsetasappropriate(),
		check5104ConsiderGKESandboxforrunninguntrustedworkloads(),
		check5105EnsureuseofBinaryAuthorization(),
		check5106EnableCloudSecurityCommandCenterCloudSCC(),
	}

	report := &castai.CloudScanReport{
		Checks: make([]castai.CloudScanCheck, 0, len(checks)),
	}
	for _, c := range checks {
		if !c.manual {
			if err := c.validate(); err != nil {
				return err
			}
		}
		report.Checks = append(report.Checks, castai.CloudScanCheck{
			ID:     c.id,
			Manual: c.manual,
			Failed: c.failed,
		})
	}

	if err := s.castaiClient.SendCISCloudScanReport(ctx, report); err != nil {
		return err
	}

	return nil
}
