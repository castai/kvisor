package gke

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/googleapis/gax-go/v2"
	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"

	containerv1 "cloud.google.com/go/container/apiv1"
	serviceusagepb "google.golang.org/genproto/googleapis/api/serviceusage/v1"
	containerpb "google.golang.org/genproto/googleapis/container/v1"

	serviceusagev1 "cloud.google.com/go/serviceusage/apiv1"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/config"
	"github.com/castai/sec-agent/metrics"
)

type clusterClient interface {
	GetCluster(ctx context.Context, req *containerpb.GetClusterRequest, opts ...gax.CallOption) (*containerpb.Cluster, error)
}

type serviceUsageClient interface {
	GetService(ctx context.Context, req *serviceusagepb.GetServiceRequest, opts ...gax.CallOption) (*serviceusagepb.Service, error)
}

type castaiClient interface {
	SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error
}

func NewScanner(log logrus.FieldLogger, cfg config.CloudScan, imgScanEnabled bool, client castaiClient) (*Scanner, error) {
	project, location := parseInfoFromClusterName(cfg.GKE.ClusterName)
	if project == "" || location == "" {
		return nil, fmt.Errorf("could not parse project and location from cluster name, expected format is `projects/*/locations/*/clusters/*`, actual %q", cfg.GKE.ClusterName)
	}

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

	serviceUsageClient, err := serviceusagev1.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		log:                log,
		cfg:                cfg,
		project:            project,
		location:           location,
		imgScanEnabled:     imgScanEnabled,
		castaiClient:       client,
		clusterClient:      clusterClient,
		serviceUsageClient: serviceUsageClient,
	}, nil
}

type check struct {
	id          string
	description string
	manual      bool
	context     any
	failed      bool
	validate    func(c *check)
}

type Scanner struct {
	log                logrus.FieldLogger
	cfg                config.CloudScan
	project            string
	location           string
	imgScanEnabled     bool
	castaiClient       castaiClient
	clusterClient      clusterClient
	serviceUsageClient serviceUsageClient
}

func (s *Scanner) Start(ctx context.Context) {
	for {
		s.log.Info("scanning cloud")
		if err := s.scan(ctx); err != nil {
			s.log.Errorf("gcp cloud scan failed: %v", err)
		} else {
			s.log.Info("gcp cloud scan finished")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.ScanInterval):
		}
	}
}

func (s *Scanner) scan(ctx context.Context) (rerr error) {
	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeCloud, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeCloud, start)
	}()

	cl, err := s.clusterClient.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: s.cfg.GKE.ClusterName,
	})
	if err != nil {
		return fmt.Errorf("getting cluster: %w", err)
	}

	containerUsageService, err := s.serviceUsageClient.GetService(ctx, &serviceusagepb.GetServiceRequest{
		Name: fmt.Sprintf("projects/%s/services/containerscanning.googleapis.com", s.project),
	})
	if err != nil {
		return fmt.Errorf("getting service usage: %w", err)
	}

	checks := []check{
		check431EnsureCNISupportsNetworkPolicies(cl),
		check511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider(containerUsageService, s.imgScanEnabled),
		check512MinimizeuseraccesstoGCR(),
		check513MinimizeclusteraccesstoreadonlyforGCR(),
		check514MinimizeContainerRegistriestoonlythoseapproved(),
		check521EnsureGKEclustersarenotrunningusingtheComputeEnginedefaultserviceaccount(cl),
		check522PreferusingdedicatedGCPServiceAccountsandWorkloadIdentity(cl),
		check531EnsureKubernetesSecretsareencryptedusingkeysmanagedinCloudKMS(cl),
		check541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled(cl),
		check542EnsuretheGKEMetadataServerisEnabled(cl),
		check551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages(cl),
		check552EnsureNodeAutoRepairisenabledforGKEnodes(cl),
		check553EnsureNodeAutoUpgradeisenabledforGKEnodes(cl),
		check554WhencreatingNewClustersAutomateGKEversionmanagementusingReleaseChannels(cl),
		check555EnsureShieldedGKENodesareEnabled(cl),
		check556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled(cl),
		check557EnsureSecureBootforShieldedGKENodesisEnabled(cl),
		check561EnableVPCFlowLogsandIntranodeVisibility(cl),
		check562EnsureuseofVPCnativeclusters(cl),
		check563EnsureMasterAuthorizedNetworksisEnabled(cl),
		check564EnsureclustersarecreatedwithPrivateEndpointEnabledandPublicAccessDisabled(cl),
		check565EnsureclustersarecreatedwithPrivateNodes(cl),
		check566ConsiderfirewallingGKEworkernodes(),
		check567EnsureNetworkPolicyisEnabledandsetasappropriate(cl),
		check568EnsureuseofGooglemanagedSSLCertificates(),
		check571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled(cl),
		check572EnableLinuxauditdlogging(),
		check581EnsureBasicAuthenticationusingstaticpasswordsisDisabled(cl),
		check582EnsureauthenticationusingClientCertificatesisDisabled(cl),
		check583ManageKubernetesRBACuserswithGoogleGroupsforGKE(cl),
		check584EnsureLegacyAuthorizationABACisDisabled(cl),
		check591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD(),
		check5101EnsureKubernetesWebUIisDisabled(cl),
		check5102EnsurethatAlphaclustersarenotusedforproductionworkloads(cl),
		check5103EnsurePodSecurityPolicyisEnabledandsetasappropriate(),
		check5104ConsiderGKESandboxforrunninguntrustedworkloads(cl),
		check5105EnsureuseofBinaryAuthorization(cl),
		check5106EnableCloudSecurityCommandCenterCloudSCC(),
	}

	report := &castai.CloudScanReport{
		Checks: make([]castai.CloudScanCheck, 0, len(checks)),
	}
	for _, c := range checks {
		if c.validate != nil {
			c.validate(&c)
		}
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

func parseInfoFromClusterName(clusterName string) (project, location string) {
	parts := strings.Split(clusterName, "/")
	if len(parts) != 6 {
		return "", ""
	}
	return parts[1], parts[3]
}
