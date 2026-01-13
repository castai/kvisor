package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"google.golang.org/api/iterator"
)

func (p *Provider) RefreshMetadata(ctx context.Context) error {
	p.log.Info("refreshing GCP metadata")

	metadata := &types.Metadata{
		Domain:   "googleapis.com",
		Provider: types.TypeGCP,
	}

	vpcs, err := p.fetchVPCs(ctx)
	if err != nil {
		return fmt.Errorf("fetching VPCs: %w", err)
	}
	metadata.VPCs = vpcs

	serviceRanges, err := p.fetchServiceIPRanges(ctx)
	if err != nil {
		p.log.Warnf("fetching service IP ranges: %v", err)
	} else {
		metadata.ServiceRanges = serviceRanges
	}

	p.mu.Lock()
	p.metadata = metadata
	p.mu.Unlock()

	p.log.Info("refreshed vpc metadata")
	return nil
}

// https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/list
func (p *Provider) fetchVPCs(ctx context.Context) ([]types.VPC, error) {
	var vpcs []types.VPC

	filterNetwork := fmt.Sprintf("name=%s", p.cfg.NetworkName)

	// List networks (VPCs) in project
	req := &computepb.ListNetworksRequest{
		Project: p.cfg.GCPProjectID,
		Filter:  &filterNetwork,
	}

	it := p.networksClient.List(ctx, req)
	for {
		network, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterating networks: %w", err)
		}

		vpc := types.VPC{
			ID:   fmt.Sprintf("%d", network.GetId()),
			Name: network.GetName(),
		}

		vpcSubnets, err := p.fetchSubnets(ctx, network)
		if err != nil {
			p.log.With("vpc", vpc.Name).Infof("subnets not found, skip VPC processing")
			continue
		}
		vpc.Subnets = vpcSubnets

		// Fetch peered VPCs
		vpc.PeeredVPCs = p.fetchPeeredVPCs(ctx, network)

		vpcs = append(vpcs, vpc)
	}
	p.log.With("count", len(vpcs)).Info("fetched VPCs")
	return vpcs, nil
}

// https://docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks/aggregatedList
func (p *Provider) fetchSubnets(ctx context.Context, network *computepb.Network) ([]types.Subnet, error) {
	subnets := make([]types.Subnet, 0)

	filterNetwork := fmt.Sprintf("network=%q", network.GetSelfLink())

	req := &computepb.AggregatedListSubnetworksRequest{
		Project: p.cfg.GCPProjectID,
		Filter:  &filterNetwork,
	}

	it := p.subnetworksClient.AggregatedList(ctx, req)
	for {
		pair, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterating subnetworks: %w", err)
		}

		for _, subnetwork := range pair.Value.GetSubnetworks() {
			cidr, err := netip.ParsePrefix(subnetwork.GetIpCidrRange())
			if err != nil {
				p.log.Warnf("parsing subnet CIDR %s: %v", subnetwork.GetIpCidrRange(), err)
				continue
			}

			subnet := types.Subnet{
				ID:     fmt.Sprintf("%d", subnetwork.GetId()),
				Name:   subnetwork.GetName(),
				CIDR:   cidr,
				Region: extractRegionFromURL(subnetwork.GetRegion()),
			}

			// Parse secondary IP ranges (GKE alias IPs)
			for _, secondary := range subnetwork.GetSecondaryIpRanges() {
				secCIDR, err := netip.ParsePrefix(secondary.GetIpCidrRange())
				if err != nil {
					continue
				}
				subnet.SecondaryRanges = append(subnet.SecondaryRanges, types.SecondaryRange{
					Name: secondary.GetRangeName(),
					CIDR: secCIDR,
					Type: detectRangeType(secondary.GetRangeName()),
				})
			}

			subnets = append(subnets, subnet)
		}
	}

	p.log.
		With("count", len(subnets)).
		With("network", network.GetName()).
		Info("fetched subnets")
	return subnets, nil
}

// https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/listPeeringRoutes
func (p *Provider) fetchNetworkPeeringRoutes(ctx context.Context, peering *computepb.NetworkPeering) ([]types.PeeredVPCRange, error) {
	var peeredVPCs []types.PeeredVPCRange

	region := "europe-west1" // region is required but not affect result anyhow, so use any region
	direction := "INCOMING"  // always incoming as we interested only in peering routes

	req := &computepb.ListPeeringRoutesNetworksRequest{
		Project:     p.cfg.GCPProjectID,
		Network:     p.cfg.NetworkName,
		PeeringName: peering.Name,
		Region:      &region,
		Direction:   &direction,
	}

	it := p.networksClient.ListPeeringRoutes(ctx, req)
	for {
		network, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterating network peering routes: %w", err)
		}
		cidr, err := netip.ParsePrefix(network.GetDestRange())
		if err != nil {
			p.log.Warnf("parsing peering routes CIDR %s: %v", network.GetDestRange(), err)
			continue
		}

		peeredVPC := types.PeeredVPCRange{
			Region: network.GetNextHopRegion(),
			CIDR:   cidr,
		}
		peeredVPCs = append(peeredVPCs, peeredVPC)
	}

	return peeredVPCs, nil
}

func (p *Provider) fetchPeeredVPCs(ctx context.Context, network *computepb.Network) []types.PeeredVPC {
	var peered []types.PeeredVPC

	for _, peering := range network.GetPeerings() {
		if peering.GetState() != "ACTIVE" {
			continue
		}

		peerVPC := types.PeeredVPC{
			Name: peering.GetName(),
		}

		if peerNetwork := peering.GetNetwork(); peerNetwork != "" {
			ranges, err := p.fetchNetworkPeeringRoutes(ctx, peering)
			if err != nil {
				p.log.
					With("peering", peering.GetName()).
					With("error", err).
					Warnf("failed to fetch network peering routes")
				continue
			}

			peerVPC.Ranges = ranges
		}

		peered = append(peered, peerVPC)
	}

	p.log.
		With("count", len(peered)).
		With("network", network.GetName()).
		Info("fetched peered VPCs")
	return peered
}

type gcpIPRangesResponse struct {
	SyncToken    string      `json:"syncToken"`
	CreationTime string      `json:"creationTime"`
	Prefixes     []gcpPrefix `json:"prefixes"`
}

type gcpPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

func (p *Provider) fetchServiceIPRanges(ctx context.Context) ([]types.ServiceRanges, error) {
	// GCP publishes service IP ranges within URL below
	const gcpIPRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

	rangesByRegion := make(map[string][]netip.Prefix)

	// Add known global ranges for Private Google Access and Restricted Google Access
	// https://cloud.google.com/vpc/docs/configure-private-google-access
	knownGlobalRanges := []string{
		"35.199.192.0/19",          // GCP APIs
		"199.36.153.4/30",          // restricted.googleapis.com CIDR Ranges
		"199.36.153.8/30",          // private.googleapis.com CIDR Ranges
		"2600:2d00:0002:1000::/64", // private.googleapis.com CIDR Ranges
		"2600:2d00:0002:2000::/64", // restricted.googleapis.com CIDR Ranges
	}

	for _, r := range knownGlobalRanges {
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			p.log.Warnf("parsing known range %s: %v", r, err)
			continue
		}
		rangesByRegion["global"] = append(rangesByRegion["global"], prefix)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcpIPRangesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching IP ranges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var ipRanges gcpIPRangesResponse
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	for _, prefix := range ipRanges.Prefixes {
		var cidrStr string
		if prefix.IPv4Prefix != "" {
			cidrStr = prefix.IPv4Prefix
		} else if prefix.IPv6Prefix != "" {
			cidrStr = prefix.IPv6Prefix
		} else {
			continue // Skip entries without IP prefix
		}

		cidr, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			p.log.Warnf("parsing CIDR %s: %v", cidrStr, err)
			continue
		}

		rangesByRegion[prefix.Scope] = append(rangesByRegion[prefix.Scope], cidr)
	}

	var serviceRanges []types.ServiceRanges
	for region, cidrs := range rangesByRegion {
		serviceRanges = append(serviceRanges, types.ServiceRanges{
			Region: region,
			CIRDs:  cidrs,
		})
	}

	p.log.Infof("fetched %d service IP ranges across %d regions (including %d global ranges)",
		len(ipRanges.Prefixes)+len(knownGlobalRanges), len(serviceRanges), len(knownGlobalRanges))

	return serviceRanges, nil
}

// extractRegionFromURL extracts the zone from a GCP region/zone URL.
// Example: "regions/us-central1" -> "us-central1"
func extractRegionFromURL(url string) string {
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if part == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// detectRangeType attempts to detect if a secondary range is for pods or services.
func detectRangeType(name string) string {
	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "pod") {
		return "pods"
	}
	if strings.Contains(nameLower, "service") || strings.Contains(nameLower, "svc") {
		return "services"
	}
	return ""
}
