package gke

import containerpb "google.golang.org/genproto/googleapis/container/v1"

/*
// Checks are generated using js script.
var txt = `Copy menu items from workbench`

var items = txt.split('\n').map(x => x.trim()).filter(x => {
    if (!x) return false;
    console.log(x.split('.'))
    return x.split('.').length > 2
}).map(x => {
    return {
        id: x.replace(/\s/g, '').replaceAll('(','').replaceAll(')','').replaceAll('.',''). replaceAll('-', ''),
        desc: x,
    }
})
var funcs = items.map(x => {
    return `func check${x.id}() check {
	return check{
		id:          "${x.id}",
		description: "${x.desc}",
		manual:      true,
	}
}`
}).join('\n')
var checksSlice = 'checks := []check{'+items.map(x => {
    return `check${x.id}(),`
}).join('\n')+'}'

console.log(funcs+'\n'+checksSlice)
*/

func check511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider() check {
	return check{
		id:          "511EnsureImageVulnerabilityScanningusingGCRContainerAnalysisorathirdpartyprovider",
		description: "5.1.1 - Ensure Image Vulnerability Scanning using GCR Container Analysis or a third party provider",
		manual:      true,
	}
}
func check512MinimizeuseraccesstoGCR() check {
	return check{
		id:          "512MinimizeuseraccesstoGCR",
		description: "5.1.2 - Minimize user access to GCR",
		manual:      true,
	}
}
func check513MinimizeclusteraccesstoreadonlyforGCR() check {
	return check{
		id:          "513MinimizeclusteraccesstoreadonlyforGCR",
		description: "5.1.3 - Minimize cluster access to read-only for GCR",
		manual:      true,
	}
}
func check514MinimizeContainerRegistriestoonlythoseapproved() check {
	return check{
		id:          "514MinimizeContainerRegistriestoonlythoseapproved",
		description: "5.1.4 - Minimize Container Registries to only those approved",
		manual:      true,
	}
}
func check521EnsureGKEclustersarenotrunningusingtheComputeEnginedefaultserviceaccount() check {
	return check{
		id:          "521EnsureGKEclustersarenotrunningusingtheComputeEnginedefaultserviceaccount",
		description: "5.2.1 - Ensure GKE clusters are not running using the Compute Engine default service account",
		manual:      true,
	}
}
func check522PreferusingdedicatedGCPServiceAccountsandWorkloadIdentity() check {
	return check{
		id:          "522PreferusingdedicatedGCPServiceAccountsandWorkloadIdentity",
		description: "5.2.2 - Prefer using dedicated GCP Service Accounts and Workload Identity",
		manual:      true,
	}
}
func check531EnsureKubernetesSecretsareencryptedusingkeysmanagedinCloudKMS() check {
	return check{
		id:          "531EnsureKubernetesSecretsareencryptedusingkeysmanagedinCloudKMS",
		description: "5.3.1 - Ensure Kubernetes Secrets are encrypted using keys managed in Cloud KMS",
		manual:      true,
	}
}
func check541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled",
		description: "5.4.1 - Ensure legacy Compute Engine instance metadata APIs are Disabled",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if val, found := pool.Config.Metadata["disable-legacy-endpoints"]; !found || val != "true" {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}

func check542EnsuretheGKEMetadataServerisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "542EnsuretheGKEMetadataServerisEnabled",
		description: "5.4.2 - Ensure the GKE Metadata Server is Enabled",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				md := pool.Config.WorkloadMetadataConfig
				if md == nil || md.Mode != containerpb.WorkloadMetadataConfig_GKE_METADATA {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages(cl *containerpb.Cluster) check {
	return check{
		id:          "551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages",
		description: "5.5.1 - Ensure Container-Optimized OS (COS) is used for GKE node images",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ImageType != "COS" {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check552EnsureNodeAutoRepairisenabledforGKEnodes(cl *containerpb.Cluster) check {
	return check{
		id:          "552EnsureNodeAutoRepairisenabledforGKEnodes",
		description: "5.5.2 - Ensure Node Auto-Repair is enabled for GKE nodes",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Management == nil || !pool.Management.AutoRepair {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check553EnsureNodeAutoUpgradeisenabledforGKEnodes(cl *containerpb.Cluster) check {
	return check{
		id:          "553EnsureNodeAutoUpgradeisenabledforGKEnodes",
		description: "5.5.3 - Ensure Node Auto-Upgrade is enabled for GKE nodes",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Management == nil || !pool.Management.AutoUpgrade {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check554WhencreatingNewClustersAutomateGKEversionmanagementusingReleaseChannels() check {
	return check{
		id:          "554WhencreatingNewClustersAutomateGKEversionmanagementusingReleaseChannels",
		description: "5.5.4 - When creating New Clusters - Automate GKE version management using Release Channels",
		manual:      true,
	}
}
func check555EnsureShieldedGKENodesareEnabled() check {
	return check{
		id:          "555EnsureShieldedGKENodesareEnabled",
		description: "5.5.5 - Ensure Shielded GKE Nodes are Enabled",
		manual:      true,
	}
}
func check556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled",
		description: "5.5.6 - Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ShieldedInstanceConfig != nil && !pool.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check557EnsureSecureBootforShieldedGKENodesisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "557EnsureSecureBootforShieldedGKENodesisEnabled",
		description: "5.5.7 - Ensure Secure Boot for Shielded GKE Nodes is Enabled",
		validate: func(c *check) {
			var failedPools []string
			for _, pool := range cl.NodePools {
				if pool.Config.ShieldedInstanceConfig != nil && !pool.Config.ShieldedInstanceConfig.EnableSecureBoot {
					failedPools = append(failedPools, pool.Name)
				}
			}
			if len(failedPools) > 0 {
				c.context = failedPools
				c.failed = true
			}
		},
	}
}
func check561EnableVPCFlowLogsandIntranodeVisibility(cl *containerpb.Cluster) check {
	return check{
		id:          "561EnableVPCFlowLogsandIntranodeVisibility",
		description: "5.6.1 - Enable VPC Flow Logs and Intranode Visibility",
		validate: func(c *check) {
			if cl.NetworkConfig == nil || !cl.NetworkConfig.EnableIntraNodeVisibility {
				c.failed = true
			}
		},
	}
}
func check562EnsureuseofVPCnativeclusters(cl *containerpb.Cluster) check {
	return check{
		id:          "562EnsureuseofVPCnativeclusters",
		description: "5.6.2 - Ensure use of VPC-native clusters",
		validate: func(c *check) {
			if cl.IpAllocationPolicy == nil || !cl.IpAllocationPolicy.UseIpAliases {
				c.failed = true
			}
		},
	}
}
func check563EnsureMasterAuthorizedNetworksisEnabled() check {
	return check{
		id:          "563EnsureMasterAuthorizedNetworksisEnabled",
		description: "5.6.3 - Ensure Master Authorized Networks is Enabled",
		manual:      true,
	}
}
func check564EnsureclustersarecreatedwithPrivateEndpointEnabledandPublicAccessDisabled() check {
	return check{
		id:          "564EnsureclustersarecreatedwithPrivateEndpointEnabledandPublicAccessDisabled",
		description: "5.6.4 - Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
		manual:      true,
	}
}
func check565EnsureclustersarecreatedwithPrivateNodes() check {
	return check{
		id:          "565EnsureclustersarecreatedwithPrivateNodes",
		description: "5.6.5 - Ensure clusters are created with Private Nodes",
		manual:      true,
	}
}
func check566ConsiderfirewallingGKEworkernodes() check {
	return check{
		id:          "566ConsiderfirewallingGKEworkernodes",
		description: "5.6.6 - Consider firewalling GKE worker nodes",
		manual:      true,
	}
}
func check567EnsureNetworkPolicyisEnabledandsetasappropriate() check {
	return check{
		id:          "567EnsureNetworkPolicyisEnabledandsetasappropriate",
		description: "5.6.7 - Ensure Network Policy is Enabled and set as appropriate",
		manual:      true,
	}
}
func check568EnsureuseofGooglemanagedSSLCertificates() check {
	return check{
		id:          "568EnsureuseofGooglemanagedSSLCertificates",
		description: "5.6.8 - Ensure use of Google-managed SSL Certificates",
		manual:      true,
	}
}
func check571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled(cl *containerpb.Cluster) check {
	return check{
		id:          "571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled",
		description: "5.7.1 - Ensure Stackdriver Kubernetes Logging and Monitoring is Enabled",
		validate: func(c *check) {
			if cl.LoggingService == "none" || cl.MonitoringService == "none" {
				c.failed = true
			}
		},
	}
}
func check572EnableLinuxauditdlogging() check {
	return check{
		id:          "572EnableLinuxauditdlogging",
		description: "5.7.2 - Enable Linux auditd logging",
		manual:      true,
	}
}
func check581EnsureBasicAuthenticationusingstaticpasswordsisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "581EnsureBasicAuthenticationusingstaticpasswordsisDisabled",
		description: "5.8.1 - Ensure Basic Authentication using static passwords is Disabled",
		validate: func(c *check) {
			if cl.MasterAuth != nil && (cl.MasterAuth.Username != "" || cl.MasterAuth.Password != "") { //nolint:staticcheck
				c.failed = true
			}
		},
	}
}
func check582EnsureauthenticationusingClientCertificatesisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "582EnsureauthenticationusingClientCertificatesisDisabled",
		description: "5.8.2 - Ensure authentication using Client Certificates is Disabled",
		validate: func(c *check) {
			if cl.MasterAuth.ClientKey != "" {
				c.failed = true
			}
		},
	}
}
func check583ManageKubernetesRBACuserswithGoogleGroupsforGKE() check {
	return check{
		id:          "583ManageKubernetesRBACuserswithGoogleGroupsforGKE",
		description: "5.8.3 - Manage Kubernetes RBAC users with Google Groups for GKE",
		manual:      true,
	}
}
func check584EnsureLegacyAuthorizationABACisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "584EnsureLegacyAuthorizationABACisDisabled",
		description: "5.8.4 - Ensure Legacy Authorization (ABAC) is Disabled",
		validate: func(c *check) {
			if cl.LegacyAbac != nil && cl.LegacyAbac.Enabled {
				c.failed = true
			}
		},
	}
}
func check591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD() check {
	return check{
		id:          "591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD",
		description: "5.9.1 - Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks (PD)",
		manual:      true,
	}
}
func check5101EnsureKubernetesWebUIisDisabled(cl *containerpb.Cluster) check {
	return check{
		id:          "5101EnsureKubernetesWebUIisDisabled",
		description: "5.10.1 - Ensure Kubernetes Web UI is Disabled",
		validate: func(c *check) {
			if cl.AddonsConfig != nil && cl.AddonsConfig.KubernetesDashboard != nil && !cl.AddonsConfig.KubernetesDashboard.Disabled { //nolint:staticcheck
				c.failed = true
			}
		},
	}
}
func check5102EnsurethatAlphaclustersarenotusedforproductionworkloads(cl *containerpb.Cluster) check {
	return check{
		id:          "5102EnsurethatAlphaclustersarenotusedforproductionworkloads",
		description: "5.10.2 - Ensure that Alpha clusters are not used for production workloads",
		validate: func(c *check) {
			if cl.EnableKubernetesAlpha {
				c.failed = true
			}
		},
	}
}
func check5103EnsurePodSecurityPolicyisEnabledandsetasappropriate() check {
	return check{
		id:          "5103EnsurePodSecurityPolicyisEnabledandsetasappropriate",
		description: "5.10.3 - Ensure Pod Security Policy is Enabled and set as appropriate",
		manual:      true,
	}
}
func check5104ConsiderGKESandboxforrunninguntrustedworkloads() check {
	return check{
		id:          "5104ConsiderGKESandboxforrunninguntrustedworkloads",
		description: "5.10.4 - Consider GKE Sandbox for running untrusted workloads",
		manual:      true,
	}
}
func check5105EnsureuseofBinaryAuthorization(cl *containerpb.Cluster) check {
	return check{
		id:          "5105EnsureuseofBinaryAuthorization",
		description: "5.10.5 - Ensure use of Binary Authorization",
		validate: func(c *check) {
			if cl.BinaryAuthorization == nil || !cl.BinaryAuthorization.Enabled { //nolint:staticcheck
				c.failed = true
			}
		},
	}
}
func check5106EnableCloudSecurityCommandCenterCloudSCC() check {
	return check{
		id:          "5106EnableCloudSecurityCommandCenterCloudSCC",
		description: "5.10.6 - Enable Cloud Security Command Center (Cloud SCC)",
		manual:      true,
	}
}
