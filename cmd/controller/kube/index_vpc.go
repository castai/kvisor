package kube

import (
	"net/netip"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cidrindex"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

// IPVPCInfo contains network state for a specific IP address.
type IPVPCInfo struct {
	Zone        string // filled only for AWS
	Region      string
	CloudDomain string // filled when IP is public cloud service
}

type VPCIndex struct {
	log *logging.Logger

	mu    sync.RWMutex
	state *cloudtypes.NetworkState

	vpcCIDRs    []string
	subnetCIDRs []string
	peerCIDRs   []string

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
		log:         log,
		cidrIndex:   cidrIdx,
		vpcCIDRs:    make([]string, 0),
		subnetCIDRs: make([]string, 0),
		peerCIDRs:   make([]string, 0),
	}
}

// Update updates the VPC state and rebuilds the CIDR tree.
func (vi *VPCIndex) Update(state *cloudtypes.NetworkState) error {
	if vi == nil {
		return nil
	}

	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.state = state
	vi.lastRefresh = time.Now()

	entries := vi.buildCIDREntries(state)

	if err := vi.cidrIndex.Rebuild(entries); err != nil {
		vi.log.Warnf("failed to rebuild CIDR index: %v", err)
		return err
	}

	vi.log.Infof(
		"VPC index updated: vpc_cidrs=%v, subnet_cidrs=%v, peer_cidrs=%v",
		vi.vpcCIDRs, vi.subnetCIDRs, vi.peerCIDRs,
	)
	return nil
}

// buildCIDREntries extracts CIDR entries from VPC state.
func (vi *VPCIndex) buildCIDREntries(state *cloudtypes.NetworkState) []cidrindex.Entry[IPVPCInfo] {
	if state == nil {
		return nil
	}

	var entries []cidrindex.Entry[IPVPCInfo]
	var vpcCIDRs []string
	var subnetCIDRs []string
	var peerCIDRs []string

	// Index service IP ranges first (lowest priority in lookups)
	for _, svcRange := range state.ServiceRanges {
		for _, cidr := range svcRange.CIRDs {
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR: cidr,
				Metadata: IPVPCInfo{
					CloudDomain: state.Domain,
					Region:      svcRange.Region,
				},
			})
		}
	}

	// Index VPC and subnet CIDRs
	for _, vpc := range state.VPCs {
		for _, cidr := range vpc.CIDRs {
			vpcCIDRs = append(vpcCIDRs, cidr.String())
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR:     cidr,
				Metadata: IPVPCInfo{},
			})
		}

		// Index subnet CIDRs
		for _, subnet := range vpc.Subnets {
			subnetCIDRs = append(subnetCIDRs, subnet.CIDR.String())
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR: subnet.CIDR,
				Metadata: IPVPCInfo{
					Zone:   subnet.Zone,
					Region: subnet.Region,
				},
			})

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				subnetCIDRs = append(subnetCIDRs, secondary.CIDR.String())
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
				peerCIDRs = append(peerCIDRs, cidrRange.CIDR.String())
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

	vi.vpcCIDRs = vpcCIDRs
	vi.subnetCIDRs = subnetCIDRs
	vi.peerCIDRs = peerCIDRs
	return entries
}

// LookupIP looks up VPC state for an IP address.
func (vi *VPCIndex) LookupIP(ip netip.Addr) (*IPVPCInfo, bool) {
	if vi == nil {
		return nil, false
	}

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
	if vi == nil || vi.state == nil {
		return []string{}
	}

	var knownCIDRs []string
	for _, vpc := range vi.state.VPCs {
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
	if vi == nil || vi.state == nil {
		return []string{}
	}

	var knownCIDRs []string
	for _, svcRange := range vi.state.ServiceRanges {
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
