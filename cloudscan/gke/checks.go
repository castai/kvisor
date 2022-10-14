package gke

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
func check541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled() check {
	return check{
		id:          "541EnsurelegacyComputeEngineinstancemetadataAPIsareDisabled",
		description: "5.4.1 - Ensure legacy Compute Engine instance metadata APIs are Disabled",
		manual:      true,
	}
}
func check542EnsuretheGKEMetadataServerisEnabled() check {
	return check{
		id:          "542EnsuretheGKEMetadataServerisEnabled",
		description: "5.4.2 - Ensure the GKE Metadata Server is Enabled",
		manual:      true,
	}
}
func check1551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages() check {
	return check{
		id:          "1551EnsureContainerOptimizedOSCOSisusedforGKEnodeimages",
		description: "1 5.5.1 - Ensure Container-Optimized OS (COS) is used for GKE node images",
		manual:      true,
	}
}
func check552EnsureNodeAutoRepairisenabledforGKEnodes() check {
	return check{
		id:          "552EnsureNodeAutoRepairisenabledforGKEnodes",
		description: "5.5.2 - Ensure Node Auto-Repair is enabled for GKE nodes",
		manual:      true,
	}
}
func check553EnsureNodeAutoUpgradeisenabledforGKEnodes() check {
	return check{
		id:          "553EnsureNodeAutoUpgradeisenabledforGKEnodes",
		description: "5.5.3 - Ensure Node Auto-Upgrade is enabled for GKE nodes",
		manual:      true,
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
func check556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled() check {
	return check{
		id:          "556EnsureIntegrityMonitoringforShieldedGKENodesisEnabled",
		description: "5.5.6 - Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled",
		manual:      true,
	}
}
func check557EnsureSecureBootforShieldedGKENodesisEnabled() check {
	return check{
		id:          "557EnsureSecureBootforShieldedGKENodesisEnabled",
		description: "5.5.7 - Ensure Secure Boot for Shielded GKE Nodes is Enabled",
		manual:      true,
	}
}
func check561EnableVPCFlowLogsandIntranodeVisibility() check {
	return check{
		id:          "561EnableVPCFlowLogsandIntranodeVisibility",
		description: "5.6.1 - Enable VPC Flow Logs and Intranode Visibility",
		manual:      true,
	}
}
func check562EnsureuseofVPCnativeclusters() check {
	return check{
		id:          "562EnsureuseofVPCnativeclusters",
		description: "5.6.2 - Ensure use of VPC-native clusters",
		manual:      true,
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
func check571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled() check {
	return check{
		id:          "571EnsureStackdriverKubernetesLoggingandMonitoringisEnabled",
		description: "5.7.1 - Ensure Stackdriver Kubernetes Logging and Monitoring is Enabled",
		manual:      true,
	}
}
func check572EnableLinuxauditdlogging() check {
	return check{
		id:          "572EnableLinuxauditdlogging",
		description: "5.7.2 - Enable Linux auditd logging",
		manual:      true,
	}
}
func check581EnsureBasicAuthenticationusingstaticpasswordsisDisabled() check {
	return check{
		id:          "581EnsureBasicAuthenticationusingstaticpasswordsisDisabled",
		description: "5.8.1 - Ensure Basic Authentication using static passwords is Disabled",
		manual:      true,
	}
}
func check582EnsureauthenticationusingClientCertificatesisDisabled() check {
	return check{
		id:          "582EnsureauthenticationusingClientCertificatesisDisabled",
		description: "5.8.2 - Ensure authentication using Client Certificates is Disabled",
		manual:      true,
	}
}
func check583ManageKubernetesRBACuserswithGoogleGroupsforGKE() check {
	return check{
		id:          "583ManageKubernetesRBACuserswithGoogleGroupsforGKE",
		description: "5.8.3 - Manage Kubernetes RBAC users with Google Groups for GKE",
		manual:      true,
	}
}
func check584EnsureLegacyAuthorizationABACisDisabled() check {
	return check{
		id:          "584EnsureLegacyAuthorizationABACisDisabled",
		description: "5.8.4 - Ensure Legacy Authorization (ABAC) is Disabled",
		manual:      true,
	}
}
func check591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD() check {
	return check{
		id:          "591EnableCustomerManagedEncryptionKeysCMEKforGKEPersistentDisksPD",
		description: "5.9.1 - Enable Customer-Managed Encryption Keys (CMEK) for GKE Persistent Disks (PD)",
		manual:      true,
	}
}
func check5101EnsureKubernetesWebUIisDisabled() check {
	return check{
		id:          "5101EnsureKubernetesWebUIisDisabled",
		description: "5.10.1 - Ensure Kubernetes Web UI is Disabled",
		manual:      true,
	}
}
func check5102EnsurethatAlphaclustersarenotusedforproductionworkloads() check {
	return check{
		id:          "5102EnsurethatAlphaclustersarenotusedforproductionworkloads",
		description: "5.10.2 - Ensure that Alpha clusters are not used for production workloads",
		manual:      true,
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
func check5105EnsureuseofBinaryAuthorization() check {
	return check{
		id:          "5105EnsureuseofBinaryAuthorization",
		description: "5.10.5 - Ensure use of Binary Authorization",
		manual:      true,
	}
}
func check5106EnableCloudSecurityCommandCenterCloudSCC() check {
	return check{
		id:          "5106EnableCloudSecurityCommandCenterCloudSCC",
		description: "5.10.6 - Enable Cloud Security Command Center (Cloud SCC)",
		manual:      true,
	}
}
