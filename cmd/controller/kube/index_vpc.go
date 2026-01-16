package kube

import (
	"net"
	"net/netip"
	"sync"
	"time"

	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/elastic/go-freelru"
	"github.com/yl2chen/cidranger"
)

// IPVPCInfo contains network metadata for a specific IP address.
type IPVPCInfo struct {
	IP          netip.Addr
	Zone        string // filled only for AWS
	Region      string
	CloudDomain string // filled when IP is public cloud service
	ResolvedAt  time.Time
}

// VPCIndex maintains VPC metadata with fast IP-to-VPC lookups using a CIDR tree.
type VPCIndex struct {
	log *logging.Logger

	mu       sync.RWMutex
	metadata *cloudtypes.Metadata

	// CIDR tree for fast IP lookups
	cidrTree cidranger.Ranger

	// IP lookup cache (LRU)
	ipCache *freelru.SyncedLRU[netip.Addr, *IPVPCInfo]

	refreshInterval time.Duration

	// Last successful refresh
	lastRefresh time.Time
}

// cidrEntry implements cidranger.RangerEntry for storing metadata with CIDR ranges.
type cidrEntry struct {
	ipNet    net.IPNet
	metadata any
}

func (c *cidrEntry) Network() net.IPNet {
	return c.ipNet
}

// CIDRInfo stores zone/region CIDR information.
type cidrInfo struct {
	Zone   string
	Region string

	// stores GCP/AWS service IP range information
	CloudDomain string
}

// NewVPCIndex creates a new VPC index.
func NewVPCIndex(log *logging.Logger, refreshInterval time.Duration) *VPCIndex {
	ipCache, err := freelru.NewSynced[netip.Addr, *IPVPCInfo](10000, func(ip netip.Addr) uint32 {
		b := ip.As16()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	})
	if err != nil {
		log.Warnf("failed to create IP cache: %v", err)
		// Continue without cache
	}

	return &VPCIndex{
		log:             log,
		cidrTree:        cidranger.NewPCTrieRanger(),
		ipCache:         ipCache,
		refreshInterval: refreshInterval,
	}
}

// Update updates the VPC metadata and rebuilds the CIDR tree.
func (vi *VPCIndex) Update(metadata *cloudtypes.Metadata) error {
	vi.mu.Lock()
	defer vi.mu.Unlock()

	vi.metadata = metadata
	vi.lastRefresh = time.Now()

	vi.rebuildCIDRTree()

	// Clear IP cache on metadata update
	if vi.ipCache != nil {
		vi.ipCache.Purge()
	}

	vi.log.Info("VPC index updated")
	return nil
}

// rebuildCIDRTree rebuilds the CIDR tree from metadata.
// Must be called with lock held.
func (vi *VPCIndex) rebuildCIDRTree() {
	vi.cidrTree = cidranger.NewPCTrieRanger()

	if vi.metadata == nil {
		return
	}

	// Index service IP ranges first (lowest priority in lookups)
	for _, svcRange := range vi.metadata.ServiceRanges {
		for _, cidr := range svcRange.CIRDs {
			_, ipNet, err := net.ParseCIDR(cidr.String())
			if err != nil {
				vi.log.Warnf("parsing service IP range %s: %v", svcRange, err)
				continue
			}
			entry := &cidrEntry{
				ipNet: *ipNet,
				metadata: &cidrInfo{
					CloudDomain: vi.metadata.Domain,
					Region:      svcRange.Region,
				},
			}
			if err := vi.cidrTree.Insert(entry); err != nil {
				vi.log.Warnf("inserting service IP range: %v", err)
			}
		}
	}

	// Index VPC and subnet CIDRs
	for _, vpc := range vi.metadata.VPCs {
		for _, cidr := range vpc.CIDRs {
			_, ipNet, err := net.ParseCIDR(cidr.String())
			if err != nil {
				vi.log.Warnf("parsing VPC CIDR %s: %v", cidr, err)
				continue
			}
			entry := &cidrEntry{
				ipNet:    *ipNet,
				metadata: &cidrInfo{},
			}
			if err := vi.cidrTree.Insert(entry); err != nil {
				vi.log.Warnf("inserting VPC CIDR: %v", err)
			}
		}

		// Index subnet CIDRs
		for _, subnet := range vpc.Subnets {
			_, ipNet, err := net.ParseCIDR(subnet.CIDR.String())
			if err != nil {
				vi.log.Warnf("parsing subnet CIDR %s: %v", subnet.CIDR, err)
				continue
			}
			entry := &cidrEntry{
				ipNet: *ipNet,
				metadata: &cidrInfo{
					Zone:   subnet.Zone,
					Region: subnet.Region,
				},
			}
			if err := vi.cidrTree.Insert(entry); err != nil {
				vi.log.Warnf("inserting subnet CIDR: %v", err)
			}

			// Index secondary ranges (GKE alias IPs)
			for _, secondary := range subnet.SecondaryRanges {
				_, ipNet, err := net.ParseCIDR(secondary.CIDR.String())
				if err != nil {
					continue
				}
				entry := &cidrEntry{
					ipNet: *ipNet,
					metadata: &cidrInfo{
						Zone:   subnet.Zone,
						Region: subnet.Region,
					},
				}
				if err := vi.cidrTree.Insert(entry); err != nil {
					vi.log.Warnf("inserting secondary range CIDR: %v", err)
				}
			}
		}

		// Index peered VPC CIDRs
		for _, peer := range vpc.PeeredVPCs {
			for _, cidrRange := range peer.Ranges {
				_, ipNet, err := net.ParseCIDR(cidrRange.CIDR.String())
				if err != nil {
					continue
				}
				entry := &cidrEntry{
					ipNet: *ipNet,
					metadata: &cidrInfo{
						Zone:   cidrRange.Zone,
						Region: cidrRange.Region,
					},
				}
				if err := vi.cidrTree.Insert(entry); err != nil {
					vi.log.Warnf("inserting peered VPC CIDR: %v", err)
				}
			}
		}
	}
}

// LookupIP looks up VPC metadata for an IP address.
func (vi *VPCIndex) LookupIP(ip netip.Addr) (*IPVPCInfo, bool) {
	// Check cache first
	if vi.ipCache != nil {
		if cached, ok := vi.ipCache.Get(ip); ok {
			// Check if cached entry is not older than refresh interval
			if time.Since(cached.ResolvedAt) < vi.refreshInterval {
				return cached, true
			}
		}
	}

	vi.mu.RLock()
	defer vi.mu.RUnlock()

	result := vi.lookupInTree(ip)
	if result != nil {
		if vi.ipCache != nil {
			vi.ipCache.Add(ip, result)
		}
		return result, true
	}

	// Not found - cache negative result too
	emptyResult := &IPVPCInfo{
		IP:         ip,
		ResolvedAt: time.Now(),
	}
	if vi.ipCache != nil {
		vi.ipCache.Add(ip, emptyResult)
	}

	return nil, false
}

// lookupInTree performs the actual CIDR tree lookup.
// Must be called with read lock held.
func (vi *VPCIndex) lookupInTree(ip netip.Addr) *IPVPCInfo {
	if vi.cidrTree == nil {
		return nil
	}

	netIP := net.IP(ip.AsSlice())

	// Find all containing networks
	entries, err := vi.cidrTree.ContainingNetworks(netIP)
	if err != nil || len(entries) == 0 {
		return nil
	}

	// Return most specific match (longest prefix / last in list)
	// cidranger returns entries ordered from least to most specific
	mostSpecific := entries[len(entries)-1].(*cidrEntry)

	result := &IPVPCInfo{
		IP:         ip,
		ResolvedAt: time.Now(),
	}

	switch meta := mostSpecific.metadata.(type) {
	case *cidrInfo:
		result.Zone = meta.Zone
		result.Region = meta.Region
		result.CloudDomain = meta.CloudDomain
	}

	return result
}
