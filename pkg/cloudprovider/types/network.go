package types

import "net/netip"

type NetworkState struct {
	Provider Type
	Domain   string // Cloud domain (e.g., googleapis.com, amazonaws.com)
	VPCs     []VPC
}

// ServiceRanges contains cloud provider service IP ranges.
type ServiceRanges struct {
	Region string
	CIRDs  []netip.Prefix
}

// VPC represents a virtual private cloud/network.
type VPC struct {
	ID         string
	Name       string
	CIDRs      []netip.Prefix // GCP does not have CIDR on vpc level
	Subnets    []Subnet
	PeeredVPCs         []PeeredVPC
	TransitGatewayVPCs []TransitGatewayVPC
}

// Subnet represents a subnet within a VPC.
type Subnet struct {
	ID              string
	Name            string
	CIDR            netip.Prefix
	Zone            string // AWS zone name (e.g., "us-east-1a") - account-specific, GCP does not have zonal subnets
	ZoneId          string // AWS zone ID (e.g., "use1-az1") - consistent across accounts
	Region          string
	SecondaryRanges []SecondaryRange // GCP specific
}

// SecondaryRange represents secondary IP ranges (GKE pods/services).
type SecondaryRange struct {
	Name string
	CIDR netip.Prefix
	Type string // "pods" or "services"
}

// PeeredVPCRange represents a VPC peering IP ranges.
type PeeredVPCRange struct {
	Zone   string // AWS zone name (e.g., "us-east-1a") - account-specific
	ZoneId string // AWS zone ID (e.g., "use1-az1") - consistent across accounts
	Region string
	CIDR   netip.Prefix
}

// PeeredVPC represents a VPC peering connection.
type PeeredVPC struct {
	Name   string
	Ranges []PeeredVPCRange
}

// TransitGatewayVPC represents a VPC discovered via AWS Transit Gateway.
// Either Subnets (preferred, via cross-account access) or CIDRs (fallback
// from TGW route tables) will be populated, but not both.
type TransitGatewayVPC struct {
	VPCID     string
	AccountID string
	Region    string
	CIDRs     []netip.Prefix // VPC-level CIDRs from TGW route tables (fallback when cross-account access unavailable)
	Subnets   []Subnet       // Subnet-level detail with zone info (via cross-account role assumption)
}
