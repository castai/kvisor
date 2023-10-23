// nolint:protogetter
package gke

import (
	"strings"

	"cloud.google.com/go/binaryauthorization/apiv1/binaryauthorizationpb"
	"cloud.google.com/go/serviceusage/apiv1/serviceusagepb"

	"cloud.google.com/go/container/apiv1/containerpb"
)

func check431EnsureCNISupportsNetworkPolicies(cl *containerpb.Cluster) check {
	return check{
		id:          "4.3.1",
		description: "4.3.1 - Ensure that the CNI in use supports Network Policies",
		validate: func(c *check) {
			c.passed = !(cl.NetworkPolicy == nil || !cl.NetworkPolicy.Enabled)
		},
	}
}
func check511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider(gcrContainerScanService *serviceusagepb.Service, castaiImageScanEnabled bool) check {
	return check{
		id:          "5.1.1",
		description: "5.1.1 - Ensure Image Vulnerability Scanning using GCR Container Analysis or a third party provider",
		validate: func(c *check) {
			c.passed = !(gcrContainerScanService.State == serviceusagepb.State_DISABLED && !castaiImageScanEnabled)
		},
	}
}
func check512MinimizeuseraccesstoGCR() check {
	return check{
		id:          "5.1.2",
		description: "5.1.2 - Minimize user access to GCR",
	}
}
func check513MinimizeclusteraccesstoreadonlyforGCR() check {
	return check{
		id:          "5.1.3",
		description: "5.1.3 - Minimize cluster access to read-only for GCR",
	}
}
func check514MinimizeContainerRegistriestoonlythoseapproved() check {
	return check{
		id:          "5.1.4",
		description: "5.1.4 - Minimize Container Registries to only those approved",
	}
}
func check521EnsureGKEclustersarenotrunningusingtheComputeEnginedefaultserviceaccount(cl *containerpb.Cluster) check {
	return check{
		id:          "5.2.1",
		description: "5.2.1 - Ensure GKE clusters are not running using the Compute Engine default service account",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ServiceAccount == "default" {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check522PreferusingdedicatedGCPServiceAccountsandWorkloadIdentity(cl *containerpb.Cluster) check {
	return check{
		id:          "5.2.2",
		description: "5.2.2 - Prefer using dedicated GCP Service Accounts and Workload Identity",
		validate: func(c *check) {
			c.passed = !(cl.WorkloadIdentityConfig == nil || cl.WorkloadIdentityConfig.WorkloadPool == "" || !strings.HasSuffix(cl.WorkloadIdentityConfig.WorkloadPool, "svc.id.goog"))
		},
	}
}
func check531EnsureKubernetesSecretsareencryptedusingkeysmanagedinCloudKMS(cl *containerpb.Cluster) check {
	return check{
		id:          "5.3.1",
		description: "5.3.1 - Ensure Kubernetes Secrets are encrypted using keys managed in Cloud KMS",
		validate: func(c *check) {
			c.passed = !(cl.DatabaseEncryption == nil || cl.DatabaseEncryption.State != containerpb.DatabaseEncryption_ENCRYPTED)
		},
	}
}
func check541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.4.1",
		description: "5.4.1 - Ensure legacy Compute Engine instance metadata APIs are Disabled",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if val, found := pool.Config.Metadata["disable-legacy-endpoints"]; !found || val != "true" {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}

func check542EnsuretheGKEMetadataServerisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.4.2",
		description: "5.4.2 - Ensure the GKE Metadata Server is Enabled",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				md := pool.Config.WorkloadMetadataConfig
				if md == nil || md.Mode != containerpb.WorkloadMetadataConfig_GKE_METADATA {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.1",
		description: "5.5.1 - Ensure Container-Optimized OS (COS) is used for GKE node images",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ImageType != "COS" && pool.Config.ImageType != "COS_CONTAINERD" {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check552EnsureNodeAutoRepairisenabledforGKEnodes(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.2",
		description: "5.5.2 - Ensure Node Auto-Repair is enabled for GKE nodes",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Management == nil || !pool.Management.AutoRepair {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check553EnsureNodeAutoUpgradeisenabledforGKEnodes(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.3",
		description: "5.5.3 - Ensure Node Auto-Upgrade is enabled for GKE nodes",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Management == nil || !pool.Management.AutoUpgrade {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check554WhencreatingNewClustersAutomateGKEversionmanagementusingReleaseChannels(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.4",
		description: "5.5.4 - When creating New Clusters - Automate GKE version management using Release Channels",
		validate: func(c *check) {
			if cl.ReleaseChannel != nil && cl.ReleaseChannel.Channel != containerpb.ReleaseChannel_REGULAR && cl.ReleaseChannel.Channel != containerpb.ReleaseChannel_STABLE {
				c.context = checkContext{ReleaseChannel: cl.ReleaseChannel.Channel.String()}
				return
			}
			c.passed = true
		},
	}
}
func check555EnsureShieldedGKENodesareEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.5",
		description: "5.5.5 - Ensure Shielded GKE Nodes are Enabled",
		validate: func(c *check) {
			c.passed = !(cl.ShieldedNodes == nil || !cl.ShieldedNodes.Enabled)
		},
	}
}
func check556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.6",
		description: "5.5.6 - Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ShieldedInstanceConfig != nil && !pool.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check557EnsureSecureBootforShieldedGKENodesisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.5.7",
		description: "5.5.7 - Ensure Secure Boot for Shielded GKE Nodes is Enabled",
		automated:   true,
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ShieldedInstanceConfig != nil && !pool.Config.ShieldedInstanceConfig.EnableSecureBoot {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check561EnableVPCFlowLogsandIntranodeVisibility(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.1",
		description: "5.6.1 - Enable VPC Flow Logs and Intranode Visibility",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.NetworkConfig == nil || !cl.NetworkConfig.EnableIntraNodeVisibility)
		},
	}
}
func check562EnsureuseofVPCnativeclusters(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.2",
		description: "5.6.2 - Ensure use of VPC-native clusters",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.IpAllocationPolicy == nil || !cl.IpAllocationPolicy.UseIpAliases)
		},
	}
}
func check563EnsureMasterAuthorizedNetworksisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.3",
		description: "5.6.3 - Ensure Master Authorized Networks is Enabled",
		validate: func(c *check) {
			c.passed = !(cl.MasterAuthorizedNetworksConfig == nil || !cl.MasterAuthorizedNetworksConfig.Enabled)
		},
	}
}
func check564EnsureclustersarecreatedwithPrivateEndpointEnabledandPublicAccessDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.4",
		description: "5.6.4 - Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
		validate: func(c *check) {
			c.passed = !(cl.PrivateClusterConfig == nil || !cl.PrivateClusterConfig.EnablePrivateEndpoint)
		},
	}
}
func check565EnsureclustersarecreatedwithPrivateNodes(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.5",
		description: "5.6.5 - Ensure clusters are created with Private Nodes",
		validate: func(c *check) {
			c.passed = !(cl.PrivateClusterConfig == nil || !cl.PrivateClusterConfig.EnablePrivateNodes)
		},
	}
}
func check566ConsiderfirewallingGKEworkernodes() check {
	return check{
		id:          "5.6.6",
		description: "5.6.6 - Consider firewalling GKE worker nodes",
	}
}
func check567EnsureNetworkPolicyisEnabledandsetasappropriate(cl *containerpb.Cluster) check {
	return check{
		id:          "5.6.7",
		description: "5.6.7 - Ensure Network Policy is Enabled and set as appropriate",
		validate: func(c *check) {
			c.passed = !(cl.NetworkPolicy == nil || !cl.NetworkPolicy.Enabled)
		},
	}
}
func check568EnsureuseofGooglemanagedSSLCertificates() check {
	return check{
		id:          "5.6.8",
		description: "5.6.8 - Ensure use of Google-managed SSL Certificates",
	}
}
func check571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.7.1",
		description: "5.7.1 - Ensure Stackdriver Kubernetes Logging and Monitoring is Enabled",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.LoggingService == "none" || cl.MonitoringService == "none")
		},
	}
}
func check572EnableLinuxauditdlogging() check {
	return check{
		id:          "5.7.2",
		description: "5.7.2 - Enable Linux auditd logging",
	}
}
func check581EnsureBasicAuthenticationusingstaticpasswordsisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.8.1",
		description: "5.8.1 - Ensure Basic Authentication using static passwords is Disabled",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.MasterAuth != nil && (cl.MasterAuth.Username != "" || cl.MasterAuth.Password != "")) //nolint:staticcheck
		},
	}
}
func check582EnsureauthenticationusingClientCertificatesisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.8.2",
		description: "5.8.2 - Ensure authentication using Client Certificates is Disabled",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.MasterAuth != nil && cl.MasterAuth.ClientKey != "")
		},
	}
}
func check583ManageKubernetesRBACuserswithGoogleGroupsforGKE(cl *containerpb.Cluster) check {
	return check{
		id:          "5.8.3",
		description: "5.8.3 - Manage Kubernetes RBAC users with Google Groups for GKE",
		validate: func(c *check) {
			c.passed = !(cl.AuthenticatorGroupsConfig == nil || !cl.AuthenticatorGroupsConfig.Enabled || !strings.HasPrefix(cl.AuthenticatorGroupsConfig.SecurityGroup, "gke-security-groups"))
		},
	}
}
func check584EnsureLegacyAuthorizationABACisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.8.4",
		description: "5.8.4 - Ensure Legacy Authorization (ABAC) is Disabled",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.LegacyAbac != nil && cl.LegacyAbac.Enabled)
		},
	}
}
func check591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD() check {
	return check{
		id:          "5.9.1",
		description: "5.9.1 - Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks (PD)",
	}
}
func check5101EnsureKubernetesWebUIisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5.10.1",
		description: "5.10.1 - Ensure Kubernetes Web UI is Disabled",
		automated:   true,
		validate: func(c *check) {
			c.passed = !(cl.AddonsConfig != nil && cl.AddonsConfig.KubernetesDashboard != nil && !cl.AddonsConfig.KubernetesDashboard.Disabled) //nolint:staticcheck
		},
	}
}
func check5102EnsurethatAlphaclustersarenotusedforproductionworkloads(cl *containerpb.Cluster) check {
	return check{
		id:          "5.10.2",
		description: "5.10.2 - Ensure that Alpha clusters are not used for production workloads",
		automated:   true,
		validate: func(c *check) {
			c.passed = !cl.EnableKubernetesAlpha
		},
	}
}
func check5103EnsurePodSecurityPolicyisEnabledandsetasappropriate() check {
	// Pod security policies are now deprecated. CIS is outdated.
	return check{
		id:          "5.10.3",
		description: "5.10.3 - Ensure Pod Security Policy is Enabled and set as appropriate",
	}
}
func check5104ConsiderGKESandboxforrunninguntrustedworkloads(cl *containerpb.Cluster) check {
	return check{
		id:          "5.10.4",
		description: "5.10.4 - Consider GKE Sandbox for running untrusted workloads",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.SandboxConfig == nil {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = checkContext{NodePools: failedPools}
				return
			}
			c.passed = true
		},
	}
}
func check5105EnsureuseofBinaryAuthorization(cl *containerpb.Cluster, binaryAuthService *serviceusagepb.Service, policy *binaryauthorizationpb.Policy) check {
	return check{
		id:          "5.10.5",
		description: "5.10.5 - Ensure use of Binary Authorization",
		automated:   true,
		validate: func(c *check) {
			if binaryAuthService.State == serviceusagepb.State_DISABLED {
				c.context = checkContext{Reason: "binary_auth_service_disabled"}
				return
			}
			if cl.BinaryAuthorization == nil || cl.BinaryAuthorization.EvaluationMode != containerpb.BinaryAuthorization_PROJECT_SINGLETON_POLICY_ENFORCE {
				c.context = checkContext{Reason: "cluster_binary_auth_evaluation_mode_not_set"}
				return
			}
			if policy == nil || (policy.DefaultAdmissionRule != nil && policy.DefaultAdmissionRule.EvaluationMode == binaryauthorizationpb.AdmissionRule_ALWAYS_ALLOW) {
				c.context = checkContext{Reason: "default_policy_allows_all_images"}
				return
			}
			c.passed = true
		},
	}
}
func check5106EnableCloudSecurityCommandCenterCloudSCC() check {
	return check{
		id:          "5.10.6",
		description: "5.10.6 - Enable Cloud Security Command Center (Cloud SCC)",
	}
}

type checkContext struct {
	ReleaseChannel string   `json:"releaseChannel,omitempty"`
	NodePools      []string `json:"nodePools,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}
