package cidrindex

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testMetadata struct {
	Zone   string
	Region string
	Name   string
}

func TestIndex(t *testing.T) {
	t.Run("create new index", func(t *testing.T) {
		r := require.New(t)

		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)
		r.NotNil(idx)
	})

	t.Run("add and lookup single CIDR", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a", Region: "us-east-1", Name: "subnet-1"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		// Lookup IP in CIDR
		ip := netip.MustParseAddr("10.0.1.50")
		result, found := idx.Lookup(ip)
		r.True(found)
		r.NotNil(result)
		r.Equal("us-east-1a", result.Metadata.Zone)
		r.Equal("us-east-1", result.Metadata.Region)
		r.Equal("subnet-1", result.Metadata.Name)
	})

	t.Run("add multiple CIDRs", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		entries := []Entry[testMetadata]{
			{
				CIDR:     netip.MustParsePrefix("10.0.1.0/24"),
				Metadata: testMetadata{Zone: "us-east-1a", Region: "us-east-1"},
			},
			{
				CIDR:     netip.MustParsePrefix("10.0.2.0/24"),
				Metadata: testMetadata{Zone: "us-east-1b", Region: "us-east-1"},
			},
		}

		err = idx.AddMultiple(entries)
		r.NoError(err)

		// Lookup in first CIDR
		ip1 := netip.MustParseAddr("10.0.1.50")
		result1, found1 := idx.Lookup(ip1)
		r.True(found1)
		r.Equal("us-east-1a", result1.Metadata.Zone)

		// Lookup in second CIDR
		ip2 := netip.MustParseAddr("10.0.2.50")
		result2, found2 := idx.Lookup(ip2)
		r.True(found2)
		r.Equal("us-east-1b", result2.Metadata.Zone)
	})

	t.Run("lookup IP not found", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		// Lookup IP not in any CIDR
		ip := netip.MustParseAddr("192.168.1.1")
		result, found := idx.Lookup(ip)
		r.False(found)
		r.Nil(result)
	})

	t.Run("most specific match wins", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		// Add broader CIDR first
		err = idx.Add(netip.MustParsePrefix("10.0.0.0/16"), testMetadata{Name: "vpc"})
		r.NoError(err)

		// Add more specific CIDR
		err = idx.Add(netip.MustParsePrefix("10.0.1.0/24"), testMetadata{Name: "subnet"})
		r.NoError(err)

		// IP matches both, should return more specific
		ip := netip.MustParseAddr("10.0.1.50")
		result, found := idx.Lookup(ip)
		r.True(found)
		r.Equal("subnet", result.Metadata.Name)
	})

	t.Run("cache returns same result", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// First lookup
		result1, found1 := idx.Lookup(ip)
		r.True(found1)
		timestamp1 := result1.ResolvedAt

		// Second lookup - should use cache
		result2, found2 := idx.Lookup(ip)
		r.True(found2)
		r.Equal(timestamp1, result2.ResolvedAt) // Same timestamp means from cache
	})

	t.Run("cache expiry", func(t *testing.T) {
		r := require.New(t)
		shortTTL := 50 * time.Millisecond
		idx, err := NewIndex[testMetadata](1000, shortTTL)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// First lookup
		result1, found1 := idx.Lookup(ip)
		r.True(found1)
		timestamp1 := result1.ResolvedAt

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Second lookup - should get fresh result
		result2, found2 := idx.Lookup(ip)
		r.True(found2)
		r.True(result2.ResolvedAt.After(timestamp1), "Second lookup should have newer timestamp")
	})

	t.Run("clear removes all entries", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// Verify it's added
		_, found := idx.Lookup(ip)
		r.True(found)

		// Clear
		idx.Clear()

		// Should not be found
		_, found = idx.Lookup(ip)
		r.False(found)
	})

	t.Run("rebuild replaces all entries", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		// Add initial entries
		entries1 := []Entry[testMetadata]{
			{
				CIDR:     netip.MustParsePrefix("10.0.1.0/24"),
				Metadata: testMetadata{Zone: "us-east-1a"},
			},
		}
		err = idx.AddMultiple(entries1)
		r.NoError(err)

		ip1 := netip.MustParseAddr("10.0.1.50")
		result1, found1 := idx.Lookup(ip1)
		r.True(found1)
		r.Equal("us-east-1a", result1.Metadata.Zone)

		// Rebuild with different entries
		entries2 := []Entry[testMetadata]{
			{
				CIDR:     netip.MustParsePrefix("10.0.2.0/24"),
				Metadata: testMetadata{Zone: "us-east-1b"},
			},
		}
		err = idx.Rebuild(entries2)
		r.NoError(err)

		// Old entry should not be found
		_, found := idx.Lookup(ip1)
		r.False(found)

		// New entry should be found
		ip2 := netip.MustParseAddr("10.0.2.50")
		result2, found2 := idx.Lookup(ip2)
		r.True(found2)
		r.Equal("us-east-1b", result2.Metadata.Zone)
	})

	t.Run("contains check", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		r.True(idx.Contains(netip.MustParseAddr("10.0.1.50")))
		r.False(idx.Contains(netip.MustParseAddr("192.168.1.1")))
	})

	t.Run("index without cache", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](0, 0) // No cache
		r.NoError(err)

		cidr := netip.MustParsePrefix("10.0.1.0/24")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// Should still work without cache
		result, found := idx.Lookup(ip)
		r.True(found)
		r.Equal("us-east-1a", result.Metadata.Zone)
	})

	t.Run("IPv6 support", func(t *testing.T) {
		r := require.New(t)
		idx, err := NewIndex[testMetadata](1000, 1*time.Hour)
		r.NoError(err)

		cidr := netip.MustParsePrefix("2001:db8::/32")
		meta := testMetadata{Zone: "us-east-1a"}

		err = idx.Add(cidr, meta)
		r.NoError(err)

		ip := netip.MustParseAddr("2001:db8::1")
		result, found := idx.Lookup(ip)
		r.True(found)
		r.Equal("us-east-1a", result.Metadata.Zone)
	})
}
