package types

import "net/netip"

type NetworkState struct {
	Provider      Type
	Domain        string // Cloud domain (e.g., googleapis.com, amazonaws.com)
	VPCs          []VPC
	ServiceRanges []ServiceRanges // Cloud provider service IP ranges (e.g., GCP APIs)
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
	PeeredVPCs []PeeredVPC
}

// Subnet represents a subnet within a VPC.
type Subnet struct {
	ID              string
	Name            string
	CIDR            netip.Prefix
	Zone            string // AWS specific, GCP does not have zonal subnets
	Region          string
	SecondaryRanges []SecondaryRange // GCP specific
}

// SecondaryRange represents secondary IP ranges (GKE pods/services).
type SecondaryRange struct {
	Name string
	CIDR netip.Prefix
	Type string // "pods" or "services"
}

// PeeredVPC represents a VPC peering connection.
type PeeredVPC struct {
	Name   string
	Ranges []PeeredVPCRange
}

// PeeredVPCRange represents a VPC peering IP ranges.
type PeeredVPCRange struct {
	Zone   string
	Region string
	CIDR   netip.Prefix
}
