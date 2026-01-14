package types

import (
	"context"
	"net/netip"
)

// Provider defines cloud-agnostic operations for fetching VPC/network metadata.
type Provider interface {
	// GetMetadata returns the cached network metadata for the cluster's cloud environment.
	GetMetadata(ctx context.Context) (*Metadata, error)

	// RefreshMetadata updates cached metadata.
	RefreshMetadata(ctx context.Context) error

	// Type returns the cloud provider type.
	Type() Type

	// Close cleans up resources.
	Close() error
}

type Type string

const (
	TypeGCP   Type = "gcp"
	TypeAWS   Type = "aws"
	TypeAzure Type = "azure"
	TypeNone  Type = "none"
)

type Metadata struct {
	Provider      Type
	Domain        string // Cloud domain (e.g., googleapis.com, amazonaws.com)
	VPCs          []VPC
	ServiceRanges []ServiceRanges // Cloud provider service IP ranges (e.g., GCP APIs)
}

func (m *Metadata) ListKnownCIDRs() []string {
	netsToStrings := func(nets []netip.Prefix) []string {
		var s []string
		for _, n := range nets {
			s = append(s, n.String())
		}
		return s
	}
	var knownCIDRs []string
	for _, vpc := range m.VPCs {
		knownCIDRs = append(knownCIDRs, netsToStrings(vpc.CIDRs)...)
		for _, subnet := range vpc.Subnets {
			knownCIDRs = append(knownCIDRs, subnet.CIDR.String())
			for _, secondaryRange := range subnet.SecondaryRanges {
				knownCIDRs = append(knownCIDRs, secondaryRange.CIDR.String())
			}
		}
	}
	for _, svcRange := range m.ServiceRanges {
		knownCIDRs = append(knownCIDRs, netsToStrings(svcRange.CIRDs)...)
	}
	return knownCIDRs
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

// Config contains cloud provider configuration.
type Config struct {
	Type Type

	// NetworkName required to filter only requested network
	NetworkName string

	// Authentication
	CredentialsFile string // Path to service account key (fallback)

	// GCP specific
	GCPProjectID string

	// AWS specific (for future)
	AWSAccountID string

	// Azure specific (for future)
	AzureSubscriptionID string
}
