package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/samber/lo"
)

func (p *Provider) GetNetworkState(ctx context.Context) (*types.NetworkState, error) {
	p.networkStateMu.RLock()
	defer p.networkStateMu.RUnlock()

	if p.networkState == nil {
		return nil, fmt.Errorf("network state not yet available")
	}

	return p.networkState, nil
}

func (p *Provider) RefreshNetworkState(ctx context.Context, network string) error {
	p.log.Info("refreshing AWS metadata")

	metadata := &types.NetworkState{
		Domain:   types.DomainAWS,
		Provider: types.TypeAWS,
	}

	vpcs, err := p.fetchVPCs(ctx, network)
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

	p.networkStateMu.Lock()
	p.networkState = metadata
	p.networkStateMu.Unlock()

	p.log.Info("refreshed vpc metadata")
	return nil
}

// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html
func (p *Provider) fetchVPCs(ctx context.Context, networkID string) ([]types.VPC, error) {
	var vpcs []types.VPC

	filters := []ec2types.Filter{}

	describeVPCsInput := &ec2.DescribeVpcsInput{
		Filters: filters,
		VpcIds:  []string{networkID},
	}

	result, err := p.ec2Client.DescribeVpcs(ctx, describeVPCsInput)
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	for _, vpc := range result.Vpcs {
		vpcID := lo.FromPtr(vpc.VpcId)

		vpcObj := types.VPC{
			ID:   vpcID,
			Name: getTagValue(vpc.Tags, "Name"),
		}

		if vpc.CidrBlock != nil {
			cidr, err := netip.ParsePrefix(*vpc.CidrBlock)
			if err != nil {
				p.log.Warnf("parsing VPC CIDR %s: %v", *vpc.CidrBlock, err)
			} else {
				vpcObj.CIDRs = append(vpcObj.CIDRs, cidr)
			}
		}

		for _, assoc := range vpc.CidrBlockAssociationSet {
			if assoc.CidrBlock == nil {
				continue
			}
			cidr, err := netip.ParsePrefix(*assoc.CidrBlock)
			if err != nil {
				p.log.Warnf("parsing VPC additional CIDR %s: %v", *assoc.CidrBlock, err)
				continue
			}
			vpcObj.CIDRs = append(vpcObj.CIDRs, cidr)
		}

		subnets, err := p.fetchSubnets(ctx, vpcID)
		if err != nil {
			p.log.With("vpc", vpcID).Warnf("fetching subnets: %v", err)
		} else {
			vpcObj.Subnets = subnets
		}

		peeredVPCs, err := p.fetchPeeredVPCs(ctx, vpcID)
		if err != nil {
			p.log.With("vpc", vpcID).Warnf("fetching peered VPCs: %v", err)
		} else {
			vpcObj.PeeredVPCs = peeredVPCs
		}

		vpcs = append(vpcs, vpcObj)
	}

	p.log.With("count", len(vpcs)).Info("fetched VPCs")
	return vpcs, nil
}

// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSubnets.html
func (p *Provider) fetchSubnets(ctx context.Context, vpcID string) ([]types.Subnet, error) {
	var subnets []types.Subnet

	input := &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{
				Name:   lo.ToPtr("vpc-id"),
				Values: []string{vpcID},
			},
		},
	}

	result, err := p.ec2Client.DescribeSubnets(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describing subnets: %w", err)
	}

	for _, subnet := range result.Subnets {
		cidr, err := netip.ParsePrefix(lo.FromPtr(subnet.CidrBlock))
		if err != nil {
			p.log.Warnf("parsing subnet CIDR %s: %v", lo.FromPtr(subnet.CidrBlock), err)
			continue
		}

		subnetObj := types.Subnet{
			ID:     lo.FromPtr(subnet.SubnetId),
			Name:   getTagValue(subnet.Tags, "Name"),
			CIDR:   cidr,
			Zone:   lo.FromPtr(subnet.AvailabilityZone),
			Region: extractRegion(lo.FromPtr(subnet.AvailabilityZone)),
		}

		subnets = append(subnets, subnetObj)
	}

	p.log.
		With("count", len(subnets)).
		With("vpc", vpcID).
		Info("fetched subnets")

	return subnets, nil
}

// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcPeeringConnections.html
func (p *Provider) fetchPeeredVPCs(ctx context.Context, vpcID string) ([]types.PeeredVPC, error) {
	var peeredVPCs []types.PeeredVPC

	// Fetch peerings where our VPC is the requester (peer info is in AccepterVpcInfo).
	requesterPeerings, err := p.describePeeringConnections(ctx, "requester-vpc-info.vpc-id", vpcID)
	if err != nil {
		return nil, err
	}
	for _, peering := range requesterPeerings {
		if peerVPC, ok := p.peeringToPeeredVPC(peering, peering.AccepterVpcInfo); ok {
			peeredVPCs = append(peeredVPCs, peerVPC)
		}
	}

	// Fetch peerings where our VPC is the accepter (peer info is in RequesterVpcInfo).
	accepterPeerings, err := p.describePeeringConnections(ctx, "accepter-vpc-info.vpc-id", vpcID)
	if err != nil {
		return nil, err
	}
	for _, peering := range accepterPeerings {
		if peerVPC, ok := p.peeringToPeeredVPC(peering, peering.RequesterVpcInfo); ok {
			peeredVPCs = append(peeredVPCs, peerVPC)
		}
	}

	p.log.
		With("count", len(peeredVPCs)).
		With("vpc", vpcID).
		Info("fetched peered VPCs")

	return peeredVPCs, nil
}

func (p *Provider) describePeeringConnections(ctx context.Context, filterName, vpcID string) ([]ec2types.VpcPeeringConnection, error) {
	input := &ec2.DescribeVpcPeeringConnectionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   lo.ToPtr(filterName),
				Values: []string{vpcID},
			},
			{
				Name:   lo.ToPtr("status-code"),
				Values: []string{"active"},
			},
		},
	}

	result, err := p.ec2Client.DescribeVpcPeeringConnections(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describing VPC peering connections (filter %s): %w", filterName, err)
	}

	return result.VpcPeeringConnections, nil
}

// peeringToPeeredVPC extracts CIDRs from the remote side of a peering connection.
// peerInfo is the VpcInfo of the remote VPC (AccepterVpcInfo when we are the requester,
// RequesterVpcInfo when we are the accepter).
func (p *Provider) peeringToPeeredVPC(peering ec2types.VpcPeeringConnection, peerInfo *ec2types.VpcPeeringConnectionVpcInfo) (types.PeeredVPC, bool) {
	if peerInfo == nil {
		return types.PeeredVPC{}, false
	}

	peerVPC := types.PeeredVPC{
		Name: lo.FromPtr(peering.VpcPeeringConnectionId),
	}

	if peerInfo.CidrBlock != nil {
		cidr, err := netip.ParsePrefix(*peerInfo.CidrBlock)
		if err != nil {
			p.log.Warnf("parsing peered VPC CIDR %s: %v", *peerInfo.CidrBlock, err)
		} else {
			peerVPC.Ranges = append(peerVPC.Ranges, types.PeeredVPCRange{
				CIDR:   cidr,
				Region: lo.FromPtr(peerInfo.Region),
			})
		}
	}

	for _, cidrBlock := range peerInfo.CidrBlockSet {
		if cidrBlock.CidrBlock == nil {
			continue
		}
		cidr, err := netip.ParsePrefix(*cidrBlock.CidrBlock)
		if err != nil {
			p.log.Warnf("parsing peered VPC additional CIDR %s: %v", *cidrBlock.CidrBlock, err)
			continue
		}
		peerVPC.Ranges = append(peerVPC.Ranges, types.PeeredVPCRange{
			CIDR:   cidr,
			Region: lo.FromPtr(peerInfo.Region),
		})
	}

	return peerVPC, true
}

type awsIPRangesResponse struct {
	SyncToken  string      `json:"syncToken"`
	CreateDate string      `json:"createDate"`
	Prefixes   []awsPrefix `json:"prefixes"`
	IPv6       []awsIPv6   `json:"ipv6_prefixes"`
}

type awsPrefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

type awsIPv6 struct {
	IPv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func (p *Provider) fetchServiceIPRanges(ctx context.Context) ([]types.ServiceRanges, error) {
	// AWS publishes service IP ranges at this URL
	const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

	rangesByRegion := make(map[string][]netip.Prefix)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, awsIPRangesURL, nil)
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

	var ipRanges awsIPRangesResponse
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	// IPv4 prefixes
	for _, prefix := range ipRanges.Prefixes {
		cidr, err := netip.ParsePrefix(prefix.IPPrefix)
		if err != nil {
			p.log.Warnf("parsing CIDR %s: %v", prefix.IPPrefix, err)
			continue
		}

		region := prefix.Region
		if region == "" {
			region = "global"
		}

		rangesByRegion[region] = append(rangesByRegion[region], cidr)
	}

	// IPv6 prefixes
	for _, prefix := range ipRanges.IPv6 {
		cidr, err := netip.ParsePrefix(prefix.IPv6Prefix)
		if err != nil {
			p.log.Warnf("parsing IPv6 CIDR %s: %v", prefix.IPv6Prefix, err)
			continue
		}

		region := prefix.Region
		if region == "" {
			region = "global"
		}

		rangesByRegion[region] = append(rangesByRegion[region], cidr)
	}

	var serviceRanges []types.ServiceRanges
	for region, cidrs := range rangesByRegion {
		serviceRanges = append(serviceRanges, types.ServiceRanges{
			Region: region,
			CIRDs:  cidrs,
		})
	}

	p.log.Infof("fetched %d service IP ranges across %d regions",
		len(ipRanges.Prefixes)+len(ipRanges.IPv6), len(serviceRanges))

	return serviceRanges, nil
}

func getTagValue(tags []ec2types.Tag, key string) string {
	for _, tag := range tags {
		if lo.FromPtr(tag.Key) == key {
			return lo.FromPtr(tag.Value)
		}
	}
	return ""
}

// extractRegion extracts region from availability zone.
// Example: "us-east-1a" -> "us-east-1"
func extractRegion(az string) string {
	if len(az) == 0 {
		return ""
	}
	// AWS AZs are region + letter (e.g., us-east-1a)
	// Remove the last character to get the region
	if len(az) > 0 {
		return az[:len(az)-1]
	}
	return az
}
