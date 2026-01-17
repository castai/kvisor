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

type VPCIndex struct {
	log *logging.Logger

	mu       sync.RWMutex
	metadata *cloudtypes.Metadata

	cidrIndex *cidrindex.Index[IPVPCInfo]

	// Last successful refresh
	lastRefresh time.Time
}

// NewVPCIndex creates a new VPC index.
func NewVPCIndex(log *logging.Logger, refreshInterval time.Duration, cacheSize uint32) *VPCIndex {
	cidrIdx, err := cidrindex.NewIndex[IPVPCInfo](cacheSize, refreshInterval)
	if err != nil {
		log.Warnf("failed to create CIDR index: %v", err)
		// Create without cache
		cidrIdx, _ = cidrindex.NewIndex[IPVPCInfo](0, refreshInterval)
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
func (vi *VPCIndex) buildCIDREntries(metadata *cloudtypes.Metadata) []cidrindex.Entry[IPVPCInfo] {
	if metadata == nil {
		return nil
	}

	var entries []cidrindex.Entry[IPVPCInfo]

	// Index service IP ranges first (lowest priority in lookups)
	for _, svcRange := range metadata.ServiceRanges {
		for _, cidr := range svcRange.CIRDs {
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR: cidr,
				Metadata: IPVPCInfo{
					CloudDomain: metadata.Domain,
					Region:      svcRange.Region,
				},
			})
		}
	}

	// Index VPC and subnet CIDRs
	for _, vpc := range metadata.VPCs {
		for _, cidr := range vpc.CIDRs {
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR:     cidr,
				Metadata: IPVPCInfo{},
			})
		}

		// Index subnet CIDRs
		for _, subnet := range vpc.Subnets {
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR: subnet.CIDR,
				Metadata: IPVPCInfo{
					Zone:   subnet.Zone,
					Region: subnet.Region,
				},
			})

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				entries = append(entries, cidrindex.Entry[IPVPCInfo]{
					CIDR: secondary.CIDR,
					Metadata: IPVPCInfo{
						Zone:   subnet.Zone,
						Region: subnet.Region,
					},
				})
			}
		}

		// Index peered VPC CIDRs
		for _, peer := range vpc.PeeredVPCs {
			for _, cidrRange := range peer.Ranges {
				entries = append(entries, cidrindex.Entry[IPVPCInfo]{
					CIDR: cidrRange.CIDR,
					Metadata: IPVPCInfo{
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

func (vi *VPCIndex) VpcCIDRs() []string {
	if vi.metadata == nil {
		return []string{}
	}

	var knownCIDRs []string
	for _, vpc := range vi.metadata.VPCs {
		knownCIDRs = append(knownCIDRs, netsToStrings(vpc.CIDRs)...)
		for _, subnet := range vpc.Subnets {
			knownCIDRs = append(knownCIDRs, subnet.CIDR.String())
			for _, secondaryRange := range subnet.SecondaryRanges {
				knownCIDRs = append(knownCIDRs, secondaryRange.CIDR.String())
			}
		}
	}
	return knownCIDRs
}

func (vi *VPCIndex) CloudServiceCIDRs() []string {
	if vi.metadata == nil {
		return []string{}
	}

	var knownCIDRs []string
	for _, svcRange := range vi.metadata.ServiceRanges {
		knownCIDRs = append(knownCIDRs, netsToStrings(svcRange.CIRDs)...)
	}
	return knownCIDRs
}

func netsToStrings(nets []netip.Prefix) []string {
	var s []string
	for _, n := range nets {
		s = append(s, n.String())
	}
	return s
}
