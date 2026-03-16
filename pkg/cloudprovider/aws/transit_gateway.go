package aws

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/samber/lo"
)

// fetchTransitGatewayVPCs discovers VPCs connected via Transit Gateway.
// It fetches route-level CIDRs for all attachments and optionally enriches
// with subnet-level detail via cross-account role assumption.
func (p *Provider) fetchTransitGatewayVPCs(ctx context.Context, vpcID string) ([]types.TransitGatewayVPC, error) {
	// Find all TGW attachments for this VPC.
	attachments, err := p.fetchTGWAttachments(ctx, vpcID)
	if err != nil {
		return nil, fmt.Errorf("fetching TGW attachments for vpc %s: %w", vpcID, err)
	}
	if len(attachments) == 0 {
		return nil, nil
	}

	// Collect unique TGW IDs from attachments.
	tgwIDs := make(map[string]struct{})
	for _, att := range attachments {
		if att.TransitGatewayId != nil {
			tgwIDs[*att.TransitGatewayId] = struct{}{}
		}
	}

	// For each TGW, discover all VPC attachments (including remote accounts).
	var allAttachments []ec2types.TransitGatewayAttachment
	var failedTGWAttachments int
	for tgwID := range tgwIDs {
		tgwAttachments, err := p.fetchAllTGWAttachments(ctx, tgwID)
		if err != nil {
			failedTGWAttachments++
			p.log.With("tgw", tgwID).Warnf("fetching all TGW attachments: %v", err)
			continue
		}
		allAttachments = append(allAttachments, tgwAttachments...)
	}
	if failedTGWAttachments > 0 && failedTGWAttachments == len(tgwIDs) {
		p.log.Errorf("all %d Transit Gateway attachment fetches failed; TGW VPC discovery returned no results", failedTGWAttachments)
	}

	// Also discover routes from TGW route tables to find remote CIDRs.
	tgwRoutes := make(map[string][]netip.Prefix) // attachment ID -> CIDRs
	for tgwID := range tgwIDs {
		routeTables, err := p.fetchTGWRouteTables(ctx, tgwID)
		if err != nil {
			p.log.With("tgw", tgwID).Warnf("fetching TGW route tables: %v", err)
			continue
		}
		for _, rt := range routeTables {
			if rt.TransitGatewayRouteTableId == nil {
				continue
			}
			routes, err := p.searchTGWRoutes(ctx, *rt.TransitGatewayRouteTableId)
			if err != nil {
				p.log.With("tgw_route_table", *rt.TransitGatewayRouteTableId).Warnf("searching TGW routes: %v", err)
				continue
			}
			for _, route := range routes {
				if route.DestinationCidrBlock == nil {
					continue
				}
				cidr, err := netip.ParsePrefix(*route.DestinationCidrBlock)
				if err != nil {
					p.log.Warnf("parsing TGW route CIDR %s: %v", *route.DestinationCidrBlock, err)
					continue
				}
				for _, att := range route.TransitGatewayAttachments {
					if att.TransitGatewayAttachmentId != nil {
						tgwRoutes[*att.TransitGatewayAttachmentId] = append(
							tgwRoutes[*att.TransitGatewayAttachmentId], cidr,
						)
					}
				}
			}
		}
	}

	// Cache cross-account EC2 clients by account ID to avoid repeated STS calls.
	crossAccountClients := make(map[string]*ec2.Client)

	// Build TransitGatewayVPC list from remote attachments.
	seen := make(map[string]struct{})
	var result []types.TransitGatewayVPC

	for _, att := range allAttachments {
		remoteVPCID := lo.FromPtr(att.ResourceId)
		remoteAccountID := lo.FromPtr(att.ResourceOwnerId)

		// Skip our own VPC.
		if remoteVPCID == vpcID {
			continue
		}
		// Skip non-VPC attachments.
		if att.ResourceType != ec2types.TransitGatewayAttachmentResourceTypeVpc {
			continue
		}
		// Deduplicate.
		key := remoteAccountID + "/" + remoteVPCID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		tgwVPC := types.TransitGatewayVPC{
			VPCID:     remoteVPCID,
			AccountID: remoteAccountID,
		}

		// Try cross-account subnet discovery if role ARN is configured.
		if p.cfg.AWSCrossAccountRoleARN != "" {
			subnets, region, err := p.fetchRemoteSubnetsWithCache(ctx, crossAccountClients, remoteAccountID, remoteVPCID)
			if err != nil {
				p.log.With("vpc", remoteVPCID, "account", remoteAccountID).
					Errorf("cross-account subnet fetch failed (falling back to route CIDRs): %v", err)
			} else {
				tgwVPC.Subnets = subnets
				tgwVPC.Region = region
			}
		}

		// Use route CIDRs as fallback if no subnets were discovered.
		if len(tgwVPC.Subnets) == 0 {
			attID := lo.FromPtr(att.TransitGatewayAttachmentId)
			if cidrs, ok := tgwRoutes[attID]; ok {
				tgwVPC.CIDRs = cidrs
			}
		}

		// Infer region from subnets if not set.
		if tgwVPC.Region == "" && len(tgwVPC.Subnets) > 0 {
			tgwVPC.Region = tgwVPC.Subnets[0].Region
		}

		result = append(result, tgwVPC)
	}

	p.log.With("count", len(result), "vpc", vpcID).Debug("fetched Transit Gateway VPCs")
	return result, nil
}

// fetchTGWAttachments returns TGW VPC attachments for a specific VPC.
func (p *Provider) fetchTGWAttachments(ctx context.Context, vpcID string) ([]ec2types.TransitGatewayAttachment, error) {
	input := &ec2.DescribeTransitGatewayAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("resource-type"), Values: []string{"vpc"}},
			{Name: lo.ToPtr("resource-id"), Values: []string{vpcID}},
			{Name: lo.ToPtr("state"), Values: []string{"available"}},
		},
	}

	var attachments []ec2types.TransitGatewayAttachment
	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(p.ec2Client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing TGW attachments: %w", err)
		}
		attachments = append(attachments, page.TransitGatewayAttachments...)
	}

	p.log.Debugf("found %d TGW attachments for vpc %s", len(attachments), vpcID)
	return attachments, nil
}

// fetchAllTGWAttachments returns all VPC attachments for a given Transit Gateway.
func (p *Provider) fetchAllTGWAttachments(ctx context.Context, tgwID string) ([]ec2types.TransitGatewayAttachment, error) {
	input := &ec2.DescribeTransitGatewayAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("transit-gateway-id"), Values: []string{tgwID}},
			// should we also filter peer VPCs? so multi accounts get here?
			{Name: lo.ToPtr("resource-type"), Values: []string{"vpc"}},
			{Name: lo.ToPtr("state"), Values: []string{"available"}},
		},
	}

	var attachments []ec2types.TransitGatewayAttachment
	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(p.ec2Client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing all TGW attachments for %s: %w", tgwID, err)
		}
		attachments = append(attachments, page.TransitGatewayAttachments...)
	}

	p.log.Debugf("found %d attachments for tgw %s", len(attachments), tgwID)
	return attachments, nil
}

// fetchTGWRouteTables returns route tables for a given Transit Gateway.
func (p *Provider) fetchTGWRouteTables(ctx context.Context, tgwID string) ([]ec2types.TransitGatewayRouteTable, error) {
	input := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("transit-gateway-id"), Values: []string{tgwID}},
			{Name: lo.ToPtr("state"), Values: []string{"available"}},
		},
	}

	var routeTables []ec2types.TransitGatewayRouteTable
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(p.ec2Client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing TGW route tables for %s: %w", tgwID, err)
		}
		routeTables = append(routeTables, page.TransitGatewayRouteTables...)
	}

	p.log.Debugf("found %d route tables for tgw %s", len(routeTables), tgwID)
	return routeTables, nil
}

// searchTGWRoutes searches for active routes in a TGW route table.
func (p *Provider) searchTGWRoutes(ctx context.Context, routeTableID string) ([]ec2types.TransitGatewayRoute, error) {
	input := &ec2.SearchTransitGatewayRoutesInput{
		TransitGatewayRouteTableId: lo.ToPtr(routeTableID),
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("state"), Values: []string{"active"}},
		},
	}

	result, err := p.ec2Client.SearchTransitGatewayRoutes(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("searching TGW routes for %s: %w", routeTableID, err)
	}

	if result.AdditionalRoutesAvailable != nil && *result.AdditionalRoutesAvailable {
		p.log.Warnf("TGW route table %s has more than 1000 routes; results are truncated", routeTableID)
	}

	return result.Routes, nil
}

// buildCrossAccountEC2Client creates an EC2 client that assumes a role in a remote account.
func (p *Provider) buildCrossAccountEC2Client(ctx context.Context, accountID string) (*ec2.Client, error) {
	if accountID == "" {
		return nil, fmt.Errorf("empty account ID for cross-account role assumption")
	}

	roleARN := strings.ReplaceAll(p.cfg.AWSCrossAccountRoleARN, "{account-id}", accountID)
	if roleARN == p.cfg.AWSCrossAccountRoleARN {
		return nil, fmt.Errorf("cross-account role ARN template %q does not contain {account-id} placeholder", p.cfg.AWSCrossAccountRoleARN)
	}

	awsCfg, err := buildAWSConfig(ctx, p.cfg)
	if err != nil {
		return nil, fmt.Errorf("building base AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
	awsCfg.Credentials = aws.NewCredentialsCache(creds)

	p.log.Debugf("assuming cross-account role %s for account %s", roleARN, accountID)
	return ec2.NewFromConfig(awsCfg), nil
}

// fetchRemoteSubnetsWithCache fetches remote subnets using a cached cross-account EC2 client.
func (p *Provider) fetchRemoteSubnetsWithCache(ctx context.Context, clientCache map[string]*ec2.Client, accountID, vpcID string) ([]types.Subnet, string, error) {
	client, ok := clientCache[accountID]
	if !ok {
		var err error
		client, err = p.buildCrossAccountEC2Client(ctx, accountID)
		if err != nil {
			return nil, "", fmt.Errorf("building cross-account EC2 client: %w", err)
		}
		clientCache[accountID] = client
	}
	return p.fetchRemoteSubnets(ctx, client, vpcID)
}

// fetchRemoteSubnets fetches subnets from a remote account's VPC using a pre-built EC2 client.
func (p *Provider) fetchRemoteSubnets(ctx context.Context, remoteEC2 *ec2.Client, vpcID string) ([]types.Subnet, string, error) {
	input := &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("vpc-id"), Values: []string{vpcID}},
		},
	}

	var allSubnets []ec2types.Subnet
	paginator := ec2.NewDescribeSubnetsPaginator(remoteEC2, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("describing remote subnets: %w", err)
		}
		allSubnets = append(allSubnets, page.Subnets...)
	}

	var subnets []types.Subnet
	var region string
	for _, subnet := range allSubnets {
		cidr, err := netip.ParsePrefix(lo.FromPtr(subnet.CidrBlock))
		if err != nil {
			p.log.Warnf("parsing remote subnet CIDR %s: %v", lo.FromPtr(subnet.CidrBlock), err)
			continue
		}

		az := lo.FromPtr(subnet.AvailabilityZone)
		subnetRegion := extractRegion(az)
		if region == "" {
			region = subnetRegion
		}

		subnets = append(subnets, types.Subnet{
			ID:     lo.FromPtr(subnet.SubnetId),
			Name:   getTagValue(subnet.Tags, "Name"),
			CIDR:   cidr,
			Zone:   az,
			ZoneId: lo.FromPtr(subnet.AvailabilityZoneId),
			Region: subnetRegion,
		})
	}

	return subnets, region, nil
}
