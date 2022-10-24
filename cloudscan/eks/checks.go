package eks

import (
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/samber/lo"
)

type check struct {
	id          string
	description string
	manual      bool
	context     any
	failed      bool
	validate    func(c *check)
}

func check431EnsureCNISupportsNetworkPolicies() check {
	return check{
		id:          "4.3.1",
		description: "4.3.1 - Ensure that the CNI in use supports Network Policies",
		manual:      true,
	}
}

func check511EnsureImageVulnerabilityScanningUsingAmazonECRImageScanningOrThirdPartyProvider() check {
	return check{
		id:          "5.1.1",
		description: "5.1.1 - Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider",
		manual:      true,
	}
}

func check512MinimizeUserAccessToAmazonECR() check {
	return check{
		id:          "5.1.2",
		description: "5.1.2 - Minimize user access to Amazon ECR",
		manual:      true,
	}
}

func check513MinimizeClusterAccessToReadOnlyForAmazonECR() check {
	return check{
		id:          "5.1.3",
		description: "5.1.3 - Minimize cluster access to read-only for Amazon ECR",
		manual:      true,
	}
}

func check514MinimizeContainerRegistriesToOnlyThoseApproved() check {
	return check{
		id:          "5.1.4",
		description: "5.1.4 - Minimize Container Registries to only those approved",
		manual:      true,
	}
}

func check521PreferUsingManagedIdentitiesForWorkloads() check {
	return check{
		id:          "5.2.1",
		description: "5.2.1 - Prefer using managed identities for workloads",
		manual:      true,
	}
}

func check531EnsureKubernetesSecretsAreEncryptedUsingCustomerMasterKeysCMKsManagedInAWSKMS(cluster *eks.DescribeClusterOutput) check {
	return check{
		id:          "5.3.1",
		description: "5.3.1 - Ensure Kubernetes Secrets are encrypted using Customer Master Keys (CMKs) managed in AWS KMS",
		validate: func(c *check) {
			c.failed = true
			for _, config := range cluster.Cluster.EncryptionConfig {
				if lo.Contains(config.Resources, "secrets") {
					c.failed = false
					return
				}
			}
		},
	}
}

func check541RestrictAccessToTheControlPlaneEndpoint() check {
	return check{
		id:          "5.4.1",
		description: "5.4.1 - Restrict Access to the Control Plane Endpoint",
		manual:      true,
	}
}

func check542EnsureClustersAreCreatedWithPrivateEndpointEnabledAndPublicAccessDisabled(cluster *eks.DescribeClusterOutput) check {
	return check{
		id:          "5.4.2",
		description: "5.4.2 - Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
		validate: func(c *check) {
			if cluster.Cluster.ResourcesVpcConfig == nil {
				// resources VPC config is not provided.
				c.manual = true
				return
			}

			c.failed = true
			if cluster.Cluster.ResourcesVpcConfig.EndpointPrivateAccess && !cluster.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
				c.failed = false
			}
		},
	}
}

func check543EnsureClustersAreCreatedWithPrivateNodes() check {
	return check{
		id:          "5.4.3",
		description: "5.4.3 - Ensure clusters are created with Private Nodes",
		manual:      true,
	}
}
func check544EnsureNetworkPolicyIsEnabledAndSetAsAppropriate() check {
	return check{
		id:          "5.4.4",
		description: "5.4.4 - Ensure Network Policy is Enabled and set as appropriate",
		manual:      true,
	}
}

func check545EncryptTrafficToHTTPSLoadBalancersWithTLSCertificates() check {
	return check{
		id:          "5.4.5",
		description: "5.4.5 - Encrypt traffic to HTTPS load balancers with TLS certificates",
		manual:      true,
	}
}

func check551ManageKubernetesRBACUsersWithAWSIAMAuthenticatorForKubernetes() check {
	return check{
		id:          "5.5.1",
		description: "5.5.1 - Manage Kubernetes RBAC users with AWS IAM Authenticator for Kubernetes",
		manual:      true,
	}
}

func check561ConsiderFargateForRunningUntrustedWorkloads() check {
	return check{
		id:          "5.6.1",
		description: "5.6.1 - Consider Fargate for running untrusted workloads",
		manual:      true,
	}
}
