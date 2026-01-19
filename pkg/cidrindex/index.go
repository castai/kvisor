package cidrindex

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/elastic/go-freelru"
	"github.com/yl2chen/cidranger"
)

type Entry[T any] struct {
	CIDR     netip.Prefix
	Metadata T
}

type LookupResult[T any] struct {
	IP         netip.Addr
	Metadata   T
	ResolvedAt time.Time
}

// Index maintains a CIDR tree for fast IP-to-metadata lookups with LRU caching.
type Index[T any] struct {
	mu sync.RWMutex

	// CIDR tree for fast IP lookups
	cidrTree cidranger.Ranger

	// Map of CIDR string to entry for tracking and cleanup
	entries map[string]*cidrEntry[T]

	// IP lookup cache (LRU)
	ipCache *freelru.SyncedLRU[netip.Addr, *LookupResult[T]]

	// Cache TTL
	cacheTTL time.Duration
}

// cidrEntry implements cidranger.RangerEntry for storing metadata with CIDR ranges.
type cidrEntry[T any] struct {
	ipNet    net.IPNet
	metadata T
	deleteAt *time.Time
}

func (c *cidrEntry[T]) Network() net.IPNet {
	return c.ipNet
}

// NewIndex creates a new CIDR index with the specified cache size and TTL.
func NewIndex[T any](cacheSize uint32, cacheTTL time.Duration) (*Index[T], error) {
	idx := &Index[T]{
		cidrTree: cidranger.NewPCTrieRanger(),
		entries:  make(map[string]*cidrEntry[T]),
		cacheTTL: cacheTTL,
	}

	if cacheSize > 0 {
		cache, err := freelru.NewSynced[netip.Addr, *LookupResult[T]](cacheSize, func(ip netip.Addr) uint32 {
			b := ip.As16()
			return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		})
		if err != nil {
			return nil, err
		}
		idx.ipCache = cache
	}

	return idx, nil
}

// Add inserts a CIDR range with associated metadata into the index.
func (idx *Index[T]) Add(cidr netip.Prefix, metadata T) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidr.String())
	if err != nil {
		return err
	}

	cidrStr := cidr.String()
	entry := &cidrEntry[T]{
		ipNet:    *ipNet,
		metadata: metadata,
	}

	// Store in map for cleanup tracking
	idx.entries[cidrStr] = entry

	return idx.cidrTree.Insert(entry)
}

// Lookup finds the most specific CIDR range containing the given IP address.
func (idx *Index[T]) Lookup(ip netip.Addr) (*LookupResult[T], bool) {
	if idx.ipCache != nil {
		if cached, ok := idx.ipCache.Get(ip); ok {
			if idx.cacheTTL == 0 || time.Since(cached.ResolvedAt) < idx.cacheTTL {
				return cached, true
			}
		}
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := idx.lookupInTree(ip)
	if result != nil {
		if idx.ipCache != nil {
			idx.ipCache.Add(ip, result)
		}
		return result, true
	}

	return nil, false
}

// lookupInTree performs the actual CIDR tree lookup.
// Must be called with read lock held.
func (idx *Index[T]) lookupInTree(ip netip.Addr) *LookupResult[T] {
	if idx.cidrTree == nil {
		return nil
	}

	netIP := net.IP(ip.AsSlice())

	entries, err := idx.cidrTree.ContainingNetworks(netIP)
	if err != nil || len(entries) == 0 {
		return nil
	}

	// Find the most specific non-deleted match ((longest prefix / last in list))
	// cidranger returns entries ordered from least to most specific
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i].(*cidrEntry[T])
		if entry.deleteAt == nil {
			return &LookupResult[T]{
				IP:         ip,
				Metadata:   entry.metadata,
				ResolvedAt: time.Now(),
			}
		}
	}

	return nil
}

// Rebuild replaces all entries in the index with the provided entries.
func (idx *Index[T]) Rebuild(entries []Entry[T]) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	newTree := cidranger.NewPCTrieRanger()
	newEntries := make(map[string]*cidrEntry[T])

	for _, entry := range entries {
		_, ipNet, err := net.ParseCIDR(entry.CIDR.String())
		if err != nil {
			return err
		}

		cidrEntry := &cidrEntry[T]{
			ipNet:    *ipNet,
			metadata: entry.Metadata,
		}

		if err := newTree.Insert(cidrEntry); err != nil {
			return err
		}

		newEntries[entry.CIDR.String()] = cidrEntry
	}

	idx.cidrTree = newTree
	idx.entries = newEntries

	if idx.ipCache != nil {
		idx.ipCache.Purge()
	}

	return nil
}

// Contains checks if the given IP address is contained in any CIDR range.
func (idx *Index[T]) Contains(ip netip.Addr) bool {
	_, found := idx.Lookup(ip)
	return found
}

// Remove deletes the given CIDR range from the index.
func (idx *Index[T]) Remove(cidr netip.Prefix) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidr.String())
	if err != nil {
		return err
	}
	_, err = idx.cidrTree.Remove(*ipNet)
	if err != nil {
		return err
	}

	// Remove from tracking map
	delete(idx.entries, cidr.String())

	// Despite just single cidr being removed, let's clear all cache,
	// as part of it is no longer valid
	if idx.ipCache != nil {
		idx.ipCache.Purge()
	}
	return nil
}

// MarkDeleted marks the given CIDR range as deleted without removing it from the index.
func (idx *Index[T]) MarkDeleted(cidr netip.Prefix) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	cidrStr := cidr.String()
	entry, found := idx.entries[cidrStr]
	if !found || entry.deleteAt != nil {
		return
	}

	now := time.Now()
	entry.deleteAt = &now

	// Clear cache as deleted entries should not be returned
	if idx.ipCache != nil {
		idx.ipCache.Purge()
	}
}

// Cleanup removes deleted entries that are older than the specified TTL.
func (idx *Index[T]) Cleanup(ttl time.Duration) int {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if len(idx.entries) == 0 {
		return 0
	}

	cutoff := time.Now().Add(-ttl)
	var removed int

	var toRemove []string

	for cidrStr, entry := range idx.entries {
		if entry.deleteAt != nil && entry.deleteAt.Before(cutoff) {
			toRemove = append(toRemove, cidrStr)
		}
	}

	for _, cidrStr := range toRemove {
		entry := idx.entries[cidrStr]
		if _, err := idx.cidrTree.Remove(entry.ipNet); err == nil {
			delete(idx.entries, cidrStr)
			removed++
		}
	}

	if removed > 0 && idx.ipCache != nil {
		idx.ipCache.Purge()
	}

	return removed
}
