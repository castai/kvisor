package kube

import (
	"net/netip"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cidrindex"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

// Well-known ConnectivityMethod values for static CIDR mappings.
// The connectivityMethod field is optional and free-form — it can be empty or set to any
// custom string. These constants are provided as a recommended set of standardized values
// for common AWS networking paths. kvisor does not validate or enforce this field;
// it is passed through as-is in netflow records so that downstream systems
// (e.g. CAST AI cost attribution) can distinguish traffic by connectivity type.
const (
	// ConnectivityVPCPeering — inter-VPC peering (same or cross-region).
	ConnectivityVPCPeering = "VPCPeering"

	// ConnectivityTransitGateway — AWS Transit Gateway.
	ConnectivityTransitGateway = "TransitGateway"

	// ConnectivityPrivateLink — AWS PrivateLink / VPC Endpoints (Interface type).
	ConnectivityPrivateLink = "PrivateLink"

	// ConnectivityDirectConnect — AWS Direct Connect.
	ConnectivityDirectConnect = "DirectConnect"

	// ConnectivitySiteToSiteVPN — AWS Site-to-Site VPN.
	ConnectivitySiteToSiteVPN = "SiteToSiteVPN"

	// ConnectivityNATGateway — traffic routed through a NAT Gateway.
	ConnectivityNATGateway = "NATGateway"

	// ConnectivityIntraVPC — traffic within the same VPC.
	ConnectivityIntraVPC = "IntraVPC"
)

// NetworkIPInfo contains network state for a specific IP address.
type NetworkIPInfo struct {
	Zone        string // AWS zone name (e.g., "us-east-1a"), or zone ID (e.g., "use1-az1") when UseAwsZoneId is enabled
	Region      string
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

type NetworkIndex struct {
	log *logging.Logger

	mu    sync.RWMutex
	state *cloudtypes.NetworkState

	vpcCIDRs    []string
	subnetCIDRs []string
	peerCIDRs   []string
	staticCIDRs []cidrindex.Entry[NetworkIPInfo] // User-provided static CIDR mappings

	cloudCIDRIndex       *cidrindex.Index[NetworkIPInfo] // rebuilt on every cloud update
	staticCIDRIndex      *cidrindex.Index[NetworkIPInfo] // populated once at startup, never rebuilt
	cloudPublicCIDRIndex *cidrindex.Index[NetworkIPInfo] // cloud public service ranges (no auth needed)

	cloudPublicServiceRanges []cloudtypes.ServiceRanges

	// Last successful refresh
	lastRefresh time.Time

	cfg NetworkConfig
}

type NetworkConfig struct {
	NetworkRefreshInterval     time.Duration
	PublicCIDRsRefreshInterval time.Duration `json:"publicCIDRsRefreshInterval"`
	CacheSize                  uint32
	UseAwsZoneId               bool
}

// NewNetworkIndex creates a new network index for IP-to-metadata lookups.
func NewNetworkIndex(log *logging.Logger, cfg NetworkConfig) *NetworkIndex {
	cloudIdx, err := cidrindex.NewIndex[NetworkIPInfo](cfg.CacheSize, cfg.NetworkRefreshInterval)
	if err != nil {
		log.Warnf("failed to create cloud CIDR index: %v", err)
		// Create without cache
		cloudIdx, _ = cidrindex.NewIndex[NetworkIPInfo](0, 0)
	}

	// Static index does not use a cache; it is populated once at startup.
	staticIdx, _ := cidrindex.NewIndex[NetworkIPInfo](0, 0)

	// Cloud public index: rebuilt on each fetch from public cloud endpoints.
	cloudPublicIdx, _ := cidrindex.NewIndex[NetworkIPInfo](cfg.CacheSize, cfg.PublicCIDRsRefreshInterval)

	return &NetworkIndex{
		log:                  log,
		cfg:                  cfg,
		cloudCIDRIndex:       cloudIdx,
		staticCIDRIndex:      staticIdx,
		cloudPublicCIDRIndex: cloudPublicIdx,
		vpcCIDRs:             make([]string, 0),
		subnetCIDRs:          make([]string, 0),
		peerCIDRs:            make([]string, 0),
	}
}

// Update replaces the cloud-discovered network state and rebuilds the CIDR index.
func (vi *NetworkIndex) Update(state *cloudtypes.NetworkState) error {
	if vi == nil {
		return nil
	}

	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.state = state
	vi.lastRefresh = time.Now()

	entries := vi.buildCIDREntries(state)

	if err := vi.cloudCIDRIndex.Rebuild(entries); err != nil {
		vi.log.Warnf("failed to rebuild CIDR index: %v", err)
		return err
	}

	vi.log.Debugf(
		"VPC index updated: vpc_cidrs=%v, subnet_cidrs=%v, peer_cidrs=%v",
		vi.vpcCIDRs, vi.subnetCIDRs, vi.peerCIDRs,
	)
	return nil
}

// AddStaticCIDRs injects user-provided CIDR mappings into the index.
func (vi *NetworkIndex) AddStaticCIDRs(mappings []StaticCIDREntry) error {
	if vi == nil {
		return nil
	}

	vi.mu.Lock()
	defer vi.mu.Unlock()

	// Validate and parse CIDRs
	entries := make([]cidrindex.Entry[NetworkIPInfo], 0, len(mappings))
	for _, mapping := range mappings {
		cidr, err := netip.ParsePrefix(mapping.CIDR)
		if err != nil {
			vi.log.Warnf("invalid static CIDR %s: %v", mapping.CIDR, err)
			continue
		}

		entry := cidrindex.Entry[NetworkIPInfo]{
			CIDR: cidr,
			Metadata: NetworkIPInfo{
				Zone:               mapping.Zone,
				Region:             mapping.Region,
				WorkloadName:       mapping.WorkloadName,
				WorkloadKind:       mapping.WorkloadKind,
				ConnectivityMethod: mapping.ConnectivityMethod,
			},
		}
		entries = append(entries, entry)
		if err := vi.staticCIDRIndex.Add(entry.CIDR, entry.Metadata); err != nil {
			vi.log.Warnf("failed to add static CIDR %s: %v", mapping.CIDR, err)
		}
	}

	vi.staticCIDRs = entries
	vi.log.Debugf("loaded %d static CIDR mappings", len(entries))
	return nil
}

// UpdateCloudPublicCIDRs updates the cloud public CIDR index with service ranges
// fetched from public endpoints (no cloud credentials needed).
func (vi *NetworkIndex) UpdateCloudPublicCIDRs(domain string, serviceRanges []cloudtypes.ServiceRanges) error {
	if vi == nil {
		return nil
	}

	vi.mu.Lock()
	defer vi.mu.Unlock()

	var entries []cidrindex.Entry[NetworkIPInfo]
	for _, svcRange := range serviceRanges {
		for _, cidr := range svcRange.CIRDs {
			entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
				CIDR: cidr,
				Metadata: NetworkIPInfo{
					CloudDomain: domain,
					Region:      svcRange.Region,
				},
			})
		}
	}

	if err := vi.cloudPublicCIDRIndex.Rebuild(entries); err != nil {
		vi.log.Warnf("failed to rebuild cloud public CIDR index: %v", err)
		return err
	}

	vi.cloudPublicServiceRanges = serviceRanges
	vi.log.Debugf("cloud public CIDR index updated: %d entries across %d regions", len(entries), len(serviceRanges))
	return nil
}

// buildCIDREntries extracts CIDR entries from VPC state.
func (vi *NetworkIndex) buildCIDREntries(state *cloudtypes.NetworkState) []cidrindex.Entry[NetworkIPInfo] {
	if state == nil {
		return nil
	}

	var entries []cidrindex.Entry[NetworkIPInfo]
	var vpcCIDRs []string
	var subnetCIDRs []string
	var peerCIDRs []string

	// Index VPC and subnet CIDRs
	for _, vpc := range state.VPCs {
		for _, cidr := range vpc.CIDRs {
			vpcCIDRs = append(vpcCIDRs, cidr.String())
			entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
				CIDR:     cidr,
				Metadata: NetworkIPInfo{},
			})
		}

		// Index subnet CIDRs
		for _, subnet := range vpc.Subnets {
			subnetZone := subnet.Zone
			if vi.cfg.UseAwsZoneId {
				subnetZone = subnet.ZoneId
			}
			subnetCIDRs = append(subnetCIDRs, subnet.CIDR.String())
			entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
				CIDR: subnet.CIDR,
				Metadata: NetworkIPInfo{
					Zone:   subnetZone,
					Region: subnet.Region,
				},
			})

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				subnetCIDRs = append(subnetCIDRs, secondary.CIDR.String())
				entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
					CIDR: secondary.CIDR,
					Metadata: NetworkIPInfo{
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
				entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
					CIDR: cidrRange.CIDR,
					Metadata: NetworkIPInfo{
						Zone:   peerZone,
						Region: cidrRange.Region,
					},
				})
			}
		}

		// Index Transit Gateway VPC CIDRs
		for _, tgwVPC := range vpc.TransitGatewayVPCs {
			if len(tgwVPC.Subnets) > 0 {
				for _, subnet := range tgwVPC.Subnets {
					subnetZone := subnet.Zone
					if vi.cfg.UseAwsZoneId {
						subnetZone = subnet.ZoneId
					}
					entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
						CIDR: subnet.CIDR,
						Metadata: NetworkIPInfo{
							Zone:               subnetZone,
							Region:             subnet.Region,
							ConnectivityMethod: ConnectivityTransitGateway,
						},
					})
				}
			} else {
				for _, cidr := range tgwVPC.CIDRs {
					entries = append(entries, cidrindex.Entry[NetworkIPInfo]{
						CIDR: cidr,
						Metadata: NetworkIPInfo{
							Region:             tgwVPC.Region,
							ConnectivityMethod: ConnectivityTransitGateway,
						},
					})
				}
			}
		}

	}

	vi.vpcCIDRs = vpcCIDRs
	vi.subnetCIDRs = subnetCIDRs
	vi.peerCIDRs = peerCIDRs
	return entries
}

// LookupIP looks up network metadata for an IP address, checking static mappings first,
// then cloud-discovered CIDRs, then public cloud service ranges.
func (vi *NetworkIndex) LookupIP(ip netip.Addr) (*NetworkIPInfo, bool) {
	if vi == nil {
		return nil, false
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	if result, found := vi.staticCIDRIndex.Lookup(ip); found {
		return &NetworkIPInfo{
			Zone:               result.Metadata.Zone,
			Region:             result.Metadata.Region,
			CloudDomain:        result.Metadata.CloudDomain,
			WorkloadName:       result.Metadata.WorkloadName,
			WorkloadKind:       result.Metadata.WorkloadKind,
			ConnectivityMethod: result.Metadata.ConnectivityMethod,
		}, true
	}

	if result, found := vi.cloudCIDRIndex.Lookup(ip); found {
		return &NetworkIPInfo{
			Zone:               result.Metadata.Zone,
			Region:             result.Metadata.Region,
			CloudDomain:        result.Metadata.CloudDomain,
			WorkloadName:       result.Metadata.WorkloadName,
			WorkloadKind:       result.Metadata.WorkloadKind,
			ConnectivityMethod: result.Metadata.ConnectivityMethod,
		}, true
	}

	if result, found := vi.cloudPublicCIDRIndex.Lookup(ip); found {
		return &NetworkIPInfo{
			Zone:               result.Metadata.Zone,
			Region:             result.Metadata.Region,
			CloudDomain:        result.Metadata.CloudDomain,
			WorkloadName:       result.Metadata.WorkloadName,
			WorkloadKind:       result.Metadata.WorkloadKind,
			ConnectivityMethod: result.Metadata.ConnectivityMethod,
		}, true
	}

	return nil, false
}

func (vi *NetworkIndex) VpcCIDRs() []string {
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

func (vi *NetworkIndex) CloudServiceCIDRs() []string {
	if vi == nil {
		return []string{}
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	var knownCIDRs []string
	for _, svcRange := range vi.cloudPublicServiceRanges {
		knownCIDRs = append(knownCIDRs, netsToStrings(svcRange.CIRDs)...)
	}
	return knownCIDRs
}

func (vi *NetworkIndex) StaticServiceCIDRs() []string {
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
