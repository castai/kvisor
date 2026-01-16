package kube

import (
	"net/netip"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cidrindex"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

// IPVPCInfo contains network metadata for a specific IP address.
type IPVPCInfo struct {
	Zone        string // filled only for AWS
	Region      string
	CloudDomain string // filled when IP is public cloud service
}

// vpcCIDRInfo stores CIDR metadata for VPC lookups.
type vpcCIDRInfo struct {
	Zone        string
	Region      string
	CloudDomain string
}

type VPCIndex struct {
	log *logging.Logger

	mu       sync.RWMutex
	metadata *cloudtypes.Metadata

	// Generic CIDR index for fast IP lookups
	cidrIndex *cidrindex.Index[vpcCIDRInfo]

	// Last successful refresh
	lastRefresh time.Time
}

// NewVPCIndex creates a new VPC index.
func NewVPCIndex(log *logging.Logger, refreshInterval time.Duration) *VPCIndex {
	cidrIdx, err := cidrindex.NewIndex[vpcCIDRInfo](10000, refreshInterval)
	if err != nil {
		log.Warnf("failed to create CIDR index: %v", err)
		// Create without cache
		cidrIdx, _ = cidrindex.NewIndex[vpcCIDRInfo](0, refreshInterval)
	}

	return &VPCIndex{
		log:       log,
		cidrIndex: cidrIdx,
	}
}

// Update updates the VPC metadata and rebuilds the CIDR tree.
func (vi *VPCIndex) Update(metadata *cloudtypes.Metadata) error {
	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.metadata = metadata
	vi.lastRefresh = time.Now()

	entries := vi.buildCIDREntries(metadata)

	if err := vi.cidrIndex.Rebuild(entries); err != nil {
		vi.log.Warnf("failed to rebuild CIDR index: %v", err)
		return err
	}

	vi.log.Info("VPC index updated")
	return nil
}

// buildCIDREntries extracts CIDR entries from VPC metadata.
func (vi *VPCIndex) buildCIDREntries(metadata *cloudtypes.Metadata) []cidrindex.Entry[vpcCIDRInfo] {
	if metadata == nil {
		return nil
	}

	var entries []cidrindex.Entry[vpcCIDRInfo]

	// Index service IP ranges first (lowest priority in lookups)
	for _, svcRange := range metadata.ServiceRanges {
		for _, cidr := range svcRange.CIRDs {
			entries = append(entries, cidrindex.Entry[vpcCIDRInfo]{
				CIDR: cidr,
				Metadata: vpcCIDRInfo{
					CloudDomain: metadata.Domain,
					Region:      svcRange.Region,
				},
			})
		}
	}

	// Index VPC and subnet CIDRs
	for _, vpc := range metadata.VPCs {
		// Index VPC CIDRs
		for _, cidr := range vpc.CIDRs {
			entries = append(entries, cidrindex.Entry[vpcCIDRInfo]{
				CIDR:     cidr,
				Metadata: vpcCIDRInfo{},
			})
		}

		// Index subnet CIDRs
		for _, subnet := range vpc.Subnets {
			entries = append(entries, cidrindex.Entry[vpcCIDRInfo]{
				CIDR: subnet.CIDR,
				Metadata: vpcCIDRInfo{
					Zone:   subnet.Zone,
					Region: subnet.Region,
				},
			})

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				entries = append(entries, cidrindex.Entry[vpcCIDRInfo]{
					CIDR: secondary.CIDR,
					Metadata: vpcCIDRInfo{
						Zone:   subnet.Zone,
						Region: subnet.Region,
					},
				})
			}
		}

		// Index peered VPC CIDRs
		for _, peer := range vpc.PeeredVPCs {
			for _, cidrRange := range peer.Ranges {
				entries = append(entries, cidrindex.Entry[vpcCIDRInfo]{
					CIDR: cidrRange.CIDR,
					Metadata: vpcCIDRInfo{
						Zone:   cidrRange.Zone,
						Region: cidrRange.Region,
					},
				})
			}
		}
	}

	return entries
}

// LookupIP looks up VPC metadata for an IP address.
func (vi *VPCIndex) LookupIP(ip netip.Addr) (*IPVPCInfo, bool) {
	vi.mu.RLock()
	defer vi.mu.RUnlock()

	result, found := vi.cidrIndex.Lookup(ip)
	if !found {
		return nil, false
	}

	return &IPVPCInfo{
		Zone:        result.Metadata.Zone,
		Region:      result.Metadata.Region,
		CloudDomain: result.Metadata.CloudDomain,
	}, true
}
