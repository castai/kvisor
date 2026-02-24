package kube

import (
	"net/netip"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cidrindex"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

// IPVPCInfo contains network state for a specific IP address.
type IPVPCInfo struct {
	Zone   string // AWS zone name (e.g., "us-east-1a"), or zone ID (e.g., "use1-az1") when UseAwsZoneId is enabled
	Region string
	CloudDomain string // filled when IP is public cloud service

	// Service/workload metadata (from static config or cloud discovery)
	WorkloadName       string // Destination VPC name, DB name, service name
	WorkloadKind       string // VPC, CloudSQL, RDS, External, etc.
	ConnectivityMethod string // Transit Gateway, VPC Peering, Direct, etc.
}

// StaticCIDREntry represents a user-provided CIDR to zone/region mapping.
type StaticCIDREntry struct {
	CIDR               string
	Zone               string // AWS zone name or zone ID (depending on controller config)
	Region             string
	WorkloadName       string
	WorkloadKind       string
	ConnectivityMethod string
}

type VPCIndex struct {
	log *logging.Logger

	mu    sync.RWMutex
	state *cloudtypes.NetworkState

	vpcCIDRs    []string
	subnetCIDRs []string
	peerCIDRs   []string
	staticCIDRs []cidrindex.Entry[IPVPCInfo] // User-provided static CIDR mappings

	cidrIndex *cidrindex.Index[IPVPCInfo]

	// Last successful refresh
	lastRefresh time.Time

	cfg VPCConfig
}

type VPCConfig struct {
	RefreshInterval time.Duration
	CacheSize       uint32
	UseAwsZoneId    bool
}

// NewVPCIndex creates a new VPC index.
func NewVPCIndex(log *logging.Logger, cfg VPCConfig) *VPCIndex {
	cidrIdx, err := cidrindex.NewIndex[IPVPCInfo](cfg.CacheSize, cfg.RefreshInterval)
	if err != nil {
		log.Warnf("failed to create CIDR index: %v", err)
		// Create without cache
		cidrIdx, _ = cidrindex.NewIndex[IPVPCInfo](0, cfg.RefreshInterval)
	}

	return &VPCIndex{
		log:         log,
		cfg:         cfg,
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

	staticCIDRCount := len(vi.staticCIDRs)
	staticCIDRStrs := make([]string, staticCIDRCount)
	for i, entry := range vi.staticCIDRs {
		staticCIDRStrs[i] = entry.CIDR.String()
	}

	vi.log.Debugf(
		"VPC index updated: vpc_cidrs=%v, subnet_cidrs=%v, peer_cidrs=%v, static_cidrs=%v",
		vi.vpcCIDRs, vi.subnetCIDRs, vi.peerCIDRs, staticCIDRStrs,
	)
	return nil
}

// AddStaticCIDRs injects user-provided CIDR mappings into the index.
func (vi *VPCIndex) AddStaticCIDRs(mappings []StaticCIDREntry) error {
	if vi == nil {
		return nil
	}

	vi.mu.Lock()
	defer vi.mu.Unlock()

	// Validate and parse CIDRs
	entries := make([]cidrindex.Entry[IPVPCInfo], 0, len(mappings))
	for _, mapping := range mappings {
		cidr, err := netip.ParsePrefix(mapping.CIDR)
		if err != nil {
			vi.log.Warnf("invalid static CIDR %s: %v", mapping.CIDR, err)
			continue
		}

		entry := cidrindex.Entry[IPVPCInfo]{
			CIDR: cidr,
			Metadata: IPVPCInfo{
				Zone:               mapping.Zone,
				Region:             mapping.Region,
				WorkloadName:       mapping.WorkloadName,
				WorkloadKind:       mapping.WorkloadKind,
				ConnectivityMethod: mapping.ConnectivityMethod,
			},
		}
		entries = append(entries, entry)
		if err := vi.cidrIndex.Add(entry.CIDR, entry.Metadata); err != nil {
			vi.log.Warnf("failed to add static CIDR %s: %v", mapping.CIDR, err)
		}
	}

	vi.staticCIDRs = entries
	vi.log.Debugf("loaded %d static CIDR mappings", len(entries))
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
			subnetZone := subnet.Zone
			if vi.cfg.UseAwsZoneId {
				subnetZone = subnet.ZoneId
			}
			subnetCIDRs = append(subnetCIDRs, subnet.CIDR.String())
			entries = append(entries, cidrindex.Entry[IPVPCInfo]{
				CIDR: subnet.CIDR,
				Metadata: IPVPCInfo{
					Zone:   subnetZone,
					Region: subnet.Region,
				},
			})

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				subnetCIDRs = append(subnetCIDRs, secondary.CIDR.String())
				entries = append(entries, cidrindex.Entry[IPVPCInfo]{
					CIDR: secondary.CIDR,
					Metadata: IPVPCInfo{
						Zone:   subnetZone,
						Region: subnet.Region,
					},
				})
			}
		}

		// Index peered VPC CIDRs
		for _, peer := range vpc.PeeredVPCs {
			for _, cidrRange := range peer.Ranges {
				peerZone := cidrRange.Zone
				if vi.cfg.UseAwsZoneId {
					peerZone = cidrRange.ZoneId
				}
				peerCIDRs = append(peerCIDRs, cidrRange.CIDR.String())
				entries = append(entries, cidrindex.Entry[IPVPCInfo]{
					CIDR: cidrRange.CIDR,
					Metadata: IPVPCInfo{
						Zone:   peerZone,
						Region: cidrRange.Region,
					},
				})
			}
		}

	}

	// Add static CIDRs LAST (highest priority - most specific match wins)
	// Static /32 IPs will override broader cloud-discovered CIDRs
	entries = append(entries, vi.staticCIDRs...)

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
		vi.log.Debugf("IP %s not found in CIDR index", ip.String())
		return nil, false
	}

	return &IPVPCInfo{
		Zone:               result.Metadata.Zone,
		Region:             result.Metadata.Region,
		CloudDomain:        result.Metadata.CloudDomain,
		WorkloadName:       result.Metadata.WorkloadName,
		WorkloadKind:       result.Metadata.WorkloadKind,
		ConnectivityMethod: result.Metadata.ConnectivityMethod,
	}, true
}

func (vi *VPCIndex) VpcCIDRs() []string {
	if vi == nil {
		return []string{}
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	if vi.state == nil {
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
	if vi == nil {
		return []string{}
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	if vi.state == nil {
		return []string{}
	}

	var knownCIDRs []string
	for _, svcRange := range vi.state.ServiceRanges {
		knownCIDRs = append(knownCIDRs, netsToStrings(svcRange.CIRDs)...)
	}
	return knownCIDRs
}

func (vi *VPCIndex) StaticServiceCIDRs() []string {
	if vi == nil {
		return []string{}
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	var knownCIDRs []string
	for _, svcRange := range vi.staticCIDRs {
		knownCIDRs = append(knownCIDRs, svcRange.CIDR.String())
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
