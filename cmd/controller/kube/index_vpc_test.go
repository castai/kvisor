package kube

import (
	"net/netip"
	"testing"
	"time"

	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestVPCIndex(t *testing.T) {
	log := logging.NewTestLog()

	t.Run("new VPC index", func(t *testing.T) {
		r := require.New(t)
		refreshInterval := 1 * time.Hour

		index := NewVPCIndex(log, refreshInterval, 1000)

		r.NotNil(index)
		r.NotNil(index.cidrIndex)
	})

	t.Run("update metadata", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			Domain: "example.com",
			VPCs: []cloudtypes.VPC{
				{
					ID:    "vpc-1",
					CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)
		r.NotNil(index.metadata)
		r.Equal(metadata, index.metadata)
		r.False(index.lastRefresh.IsZero())
	})

	t.Run("lookup IP in subnet", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// Lookup IP in subnet
		ip := netip.MustParseAddr("10.0.1.50")
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-east-1a", info.Zone)
		r.Equal("us-east-1", info.Region)
		r.Equal("", info.CloudDomain)
	})

	t.Run("lookup IP in service range", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			Domain: "googleapis.com",
			ServiceRanges: []cloudtypes.ServiceRanges{
				{
					Region: "us-central1",
					CIRDs:  []netip.Prefix{netip.MustParsePrefix("34.126.0.0/18")},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// Lookup IP in service range
		ip := netip.MustParseAddr("34.126.10.1")
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-central1", info.Region)
		r.Equal("googleapis.com", info.CloudDomain)
	})

	t.Run("lookup IP in secondary range", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
							SecondaryRanges: []cloudtypes.SecondaryRange{
								{
									Name: "pods",
									CIDR: netip.MustParsePrefix("10.100.0.0/16"),
								},
							},
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// Lookup IP in secondary range
		ip := netip.MustParseAddr("10.100.5.10")
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-east-1a", info.Zone)
		r.Equal("us-east-1", info.Region)
	})

	t.Run("lookup IP in peered VPC", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					PeeredVPCs: []cloudtypes.PeeredVPC{
						{
							Name: "peered-vpc",
							Ranges: []cloudtypes.PeeredVPCRange{
								{
									CIDR:   netip.MustParsePrefix("192.168.0.0/16"),
									Zone:   "eu-west-1a",
									Region: "eu-west-1",
								},
							},
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// Lookup IP in peered VPC
		ip := netip.MustParseAddr("192.168.10.5")
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("eu-west-1a", info.Zone)
		r.Equal("eu-west-1", info.Region)
	})

	t.Run("lookup IP not found", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// Lookup IP not in any range
		ip := netip.MustParseAddr("172.16.5.10")
		info, found := index.LookupIP(ip)
		r.False(found)
		r.Nil(info)
	})

	t.Run("lookup uses cache", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// First lookup
		info1, found1 := index.LookupIP(ip)
		r.True(found1)
		r.NotNil(info1)

		// Second lookup - should return same result
		info2, found2 := index.LookupIP(ip)
		r.True(found2)
		r.NotNil(info2)
		r.Equal(info1.Zone, info2.Zone)
		r.Equal(info1.Region, info2.Region)
	})

	t.Run("cache invalidated on update", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata1 := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata1)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// First lookup
		info1, found1 := index.LookupIP(ip)
		r.True(found1)
		r.Equal("us-east-1a", info1.Zone)

		// Update metadata with different zone
		metadata2 := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1b",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err = index.Update(metadata2)
		r.NoError(err)

		// Second lookup - should reflect new metadata
		info2, found2 := index.LookupIP(ip)
		r.True(found2)
		r.Equal("us-east-1b", info2.Zone)
	})

	t.Run("most specific match wins", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID:    "vpc-1",
					CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		// IP is in both VPC CIDR (10.0.0.0/16) and subnet CIDR (10.0.1.0/24)
		// Should return subnet info (more specific)
		ip := netip.MustParseAddr("10.0.1.50")
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-east-1a", info.Zone)
		r.Equal("us-east-1", info.Region)
	})

	t.Run("empty metadata", func(t *testing.T) {
		r := require.New(t)
		index := NewVPCIndex(log, 1*time.Hour, 1000)

		metadata := &cloudtypes.Metadata{}
		err := index.Update(metadata)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")
		info, found := index.LookupIP(ip)
		r.False(found)
		r.Nil(info)
	})

	t.Run("cache expiry", func(t *testing.T) {
		r := require.New(t)
		shortRefresh := 50 * time.Millisecond
		index := NewVPCIndex(log, shortRefresh, 1000)

		metadata := &cloudtypes.Metadata{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.1.0/24"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		err := index.Update(metadata)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// Lookup should work correctly even with short TTL
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-east-1a", info.Zone)
	})
}
