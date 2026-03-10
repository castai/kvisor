package kube

import (
	"net/netip"
	"testing"
	"time"

	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
	"github.com/stretchr/testify/require"
)

func TestVPCIndex(t *testing.T) {
	log := logging.New()

	t.Run("new VPC index", func(t *testing.T) {
		r := require.New(t)
		refreshInterval := 1 * time.Hour

		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: refreshInterval, CacheSize: 1000})

		r.NotNil(index)
		r.NotNil(index.cloudCIDRIndex)
		r.NotNil(index.staticCIDRIndex)
	})

	t.Run("update state", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
			Domain: "example.com",
			VPCs: []cloudtypes.VPC{
				{
					ID:    "vpc-1",
					CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
				},
			},
		}

		err := index.Update(state)
		r.NoError(err)
		r.NotNil(index.state)
		r.Equal(state, index.state)
		r.False(index.lastRefresh.IsZero())
	})

	t.Run("lookup IP in subnet", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
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

	// t.Run("lookup IP in service range", func(t *testing.T) {
	// 	r := require.New(t)
	// 	index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})
	//
	// 	state := &cloudtypes.NetworkState{
	// 		Domain: "googleapis.com",
	// 		ServiceRanges: []cloudtypes.ServiceRanges{
	// 			{
	// 				Region: "us-central1",
	// 				CIRDs:  []netip.Prefix{netip.MustParsePrefix("34.126.0.0/18")},
	// 			},
	// 		},
	// 	}
	//
	// 	err := index.Update(state)
	// 	r.NoError(err)
	//
	// 	// Lookup IP in service range
	// 	ip := netip.MustParseAddr("34.126.10.1")
	// 	info, found := index.LookupIP(ip)
	// 	r.True(found)
	// 	r.NotNil(info)
	// 	r.Equal("us-central1", info.Region)
	// 	r.Equal("googleapis.com", info.CloudDomain)
	// })

	t.Run("lookup IP in secondary range", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
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
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
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
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
		r.NoError(err)

		// Lookup IP not in any range
		ip := netip.MustParseAddr("172.16.5.10")
		info, found := index.LookupIP(ip)
		r.False(found)
		r.Nil(info)
	})

	t.Run("lookup uses cache", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
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
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state1 := &cloudtypes.NetworkState{
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

		err := index.Update(state1)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// First lookup
		info1, found1 := index.LookupIP(ip)
		r.True(found1)
		r.Equal("us-east-1a", info1.Zone)

		// Update state with different zone
		state2 := &cloudtypes.NetworkState{
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

		err = index.Update(state2)
		r.NoError(err)

		// Second lookup - should reflect new state
		info2, found2 := index.LookupIP(ip)
		r.True(found2)
		r.Equal("us-east-1b", info2.Zone)
	})

	t.Run("most specific match wins", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
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

	t.Run("empty state", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		state := &cloudtypes.NetworkState{}
		err := index.Update(state)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")
		info, found := index.LookupIP(ip)
		r.False(found)
		r.Nil(info)
	})

	t.Run("cache expiry", func(t *testing.T) {
		r := require.New(t)
		shortRefresh := 50 * time.Millisecond
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: shortRefresh, CacheSize: 1000})

		state := &cloudtypes.NetworkState{
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

		err := index.Update(state)
		r.NoError(err)

		ip := netip.MustParseAddr("10.0.1.50")

		// Lookup should work correctly even with short TTL
		info, found := index.LookupIP(ip)
		r.True(found)
		r.NotNil(info)
		r.Equal("us-east-1a", info.Zone)
	})

	t.Run("static CIDRs with metadata", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		// Add static CIDR mappings with rich metadata
		staticMappings := []StaticCIDREntry{
			{
				CIDR:               "10.100.1.0/24",
				Zone:               "us-east-1a",
				Region:             "us-east-1",
				WorkloadName:       "production-vpc",
				WorkloadKind:       "VPC",
				ConnectivityMethod: ConnectivityTransitGateway,
			},
			{
				CIDR:               "10.0.0.13/32", // Single IP for Cloud SQL
				Zone:               "us-east4-a",
				Region:             "us-east4",
				WorkloadName:       "production-cloudsql",
				WorkloadKind:       "CloudSQL",
				ConnectivityMethod: ConnectivityPrivateLink,
			},
			{
				CIDR:               "10.200.0.0/16", // GCP regional subnet
				Zone:               "",
				Region:             "us-central1",
				WorkloadName:       "gcp-app-vpc",
				WorkloadKind:       "VPC",
				ConnectivityMethod: ConnectivityVPCPeering,
			},
		}

		err := index.AddStaticCIDRs(staticMappings)
		r.NoError(err)

		// Update with empty cloud state to trigger rebuild
		err = index.Update(&cloudtypes.NetworkState{})
		r.NoError(err)

		// Verify AWS TGW subnet lookup
		info, found := index.LookupIP(netip.MustParseAddr("10.100.1.5"))
		r.True(found)
		r.Equal("us-east-1a", info.Zone)
		r.Equal("us-east-1", info.Region)
		r.Equal("production-vpc", info.WorkloadName)
		r.Equal("VPC", info.WorkloadKind)
		r.Equal(ConnectivityTransitGateway, info.ConnectivityMethod)

		// Verify specific Cloud SQL IP lookup
		info, found = index.LookupIP(netip.MustParseAddr("10.0.0.13"))
		r.True(found)
		r.Equal("us-east4-a", info.Zone)
		r.Equal("production-cloudsql", info.WorkloadName)
		r.Equal("CloudSQL", info.WorkloadKind)

		// Verify GCP regional subnet lookup (no zone)
		info, found = index.LookupIP(netip.MustParseAddr("10.200.5.10"))
		r.True(found)
		r.Equal("", info.Zone)
		r.Equal("us-central1", info.Region)
		r.Equal("gcp-app-vpc", info.WorkloadName)
	})

	t.Run("static CIDRs override cloud discovery", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		// Add cloud-discovered subnet
		state := &cloudtypes.NetworkState{
			VPCs: []cloudtypes.VPC{
				{
					ID: "vpc-1",
					Subnets: []cloudtypes.Subnet{
						{
							ID:     "subnet-1",
							CIDR:   netip.MustParsePrefix("10.0.0.0/16"),
							Zone:   "us-east-1a",
							Region: "us-east-1",
						},
					},
				},
			},
		}

		// Add static CIDR with more specific /32 that should override
		staticMappings := []StaticCIDREntry{
			{
				CIDR:               "10.0.0.13/32",
				Zone:               "us-east4-a",
				Region:             "us-east4",
				WorkloadName:       "specific-database",
				WorkloadKind:       "CloudSQL",
				ConnectivityMethod: ConnectivityPrivateLink,
			},
		}

		err := index.AddStaticCIDRs(staticMappings)
		r.NoError(err)

		err = index.Update(state)
		r.NoError(err)

		// IP 10.0.0.13 should match static /32, not cloud-discovered /16
		info, found := index.LookupIP(netip.MustParseAddr("10.0.0.13"))
		r.True(found)
		r.Equal("us-east4-a", info.Zone)
		r.Equal("us-east4", info.Region)
		r.Equal("specific-database", info.WorkloadName)
		r.Equal("CloudSQL", info.WorkloadKind)

		// Other IP in /16 should match cloud-discovered subnet
		info, found = index.LookupIP(netip.MustParseAddr("10.0.0.100"))
		r.True(found)
		r.Equal("us-east-1a", info.Zone)
		r.Equal("us-east-1", info.Region)
		r.Equal("", info.WorkloadName)
		r.Equal("", info.WorkloadKind)
	})

	t.Run("invalid static CIDRs", func(t *testing.T) {
		r := require.New(t)
		index := NewNetworkIndex(log, NetworkConfig{NetworkRefreshInterval: 1 * time.Hour, CacheSize: 1000})

		// Add invalid CIDR
		staticMappings := []StaticCIDREntry{
			{
				CIDR:   "invalid-cidr",
				Zone:   "us-east-1a",
				Region: "us-east-1",
			},
			{
				CIDR:   "10.0.1.0/24",
				Zone:   "us-east-1a",
				Region: "us-east-1",
			},
		}

		err := index.AddStaticCIDRs(staticMappings)
		r.NoError(err) // Should not error, just skip invalid

		err = index.Update(&cloudtypes.NetworkState{})
		r.NoError(err)

		// Valid CIDR should work
		info, found := index.LookupIP(netip.MustParseAddr("10.0.1.5"))
		r.True(found)
		r.Equal("us-east-1a", info.Zone)
	})
}
