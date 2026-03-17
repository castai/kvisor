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

// tgwDiscovery holds shared state for a single fetchTransitGatewayVPCs invocation:
// cross-account client cache, route-table CIDRs, and deduplication tracking.
type tgwDiscovery struct {
	provider            *Provider
	crossAccountClients map[string]*ec2.Client    // key: accountID/region
	routeCIDRs          map[string][]netip.Prefix // attachment ID -> CIDRs
	seen                map[string]struct{}
	peerTGWRegions      map[string]string // peer TGW ID -> region
}

// fetchTransitGatewayVPCs discovers VPCs connected via Transit Gateway.
// It fetches route-level CIDRs for all attachments and optionally enriches
// with subnet-level detail via cross-account role assumption.
func (p *Provider) fetchTransitGatewayVPCs(ctx context.Context, vpcID string) ([]types.TransitGatewayVPC, error) {
	tgwIDs, allAttachments, err := p.collectTGWAttachments(ctx, vpcID)
	if err != nil {
		return nil, err
	}
	if len(allAttachments) == 0 {
		return nil, nil
	}

	d := &tgwDiscovery{
		provider:            p,
		crossAccountClients: make(map[string]*ec2.Client),
		routeCIDRs:          p.collectTGWRouteCIDRs(ctx, tgwIDs),
		seen:                make(map[string]struct{}),
		peerTGWRegions:      make(map[string]string),
	}

	var result []types.TransitGatewayVPC
	for _, att := range allAttachments {
		if lo.FromPtr(att.ResourceId) == vpcID {
			continue
		}

		switch att.ResourceType {
		case ec2types.TransitGatewayAttachmentResourceTypeVpc:
			if vpc, ok := d.resolveVPCAttachment(ctx, att); ok {
				result = append(result, vpc)
			}
		case ec2types.TransitGatewayAttachmentResourceTypePeering:
			result = append(result, d.resolvePeeringAttachment(ctx, att)...)
		}
	}

	p.log.With("count", len(result), "vpc", vpcID).Debug("fetched Transit Gateway VPCs")
	return result, nil
}

// collectTGWAttachments finds TGW IDs for our VPC, then fetches all attachments
// (including remote accounts) across those TGWs.
func (p *Provider) collectTGWAttachments(ctx context.Context, vpcID string) (map[string]struct{}, []ec2types.TransitGatewayAttachment, error) {
	attachments, err := p.fetchTGWAttachments(ctx, vpcID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching TGW attachments for vpc %s: %w", vpcID, err)
	}
	if len(attachments) == 0 {
		return nil, nil, nil
	}

	tgwIDs := make(map[string]struct{})
	for _, att := range attachments {
		if att.TransitGatewayId != nil {
			tgwIDs[*att.TransitGatewayId] = struct{}{}
		}
	}

	var allAttachments []ec2types.TransitGatewayAttachment
	var failures int
	for tgwID := range tgwIDs {
		tgwAttachments, err := p.fetchAllTGWAttachments(ctx, tgwID)
		if err != nil {
			failures++
			p.log.With("tgw", tgwID).Warnf("fetching all TGW attachments: %v", err)
			continue
		}
		allAttachments = append(allAttachments, tgwAttachments...)
	}
	if failures > 0 && failures == len(tgwIDs) {
		p.log.Errorf("all %d Transit Gateway attachment fetches failed; TGW VPC discovery returned no results", failures)
	}

	return tgwIDs, allAttachments, nil
}

// collectTGWRouteCIDRs discovers CIDRs from TGW route tables, indexed by attachment ID.
// These serve as a fallback when subnet-level detail isn't available.
func (p *Provider) collectTGWRouteCIDRs(ctx context.Context, tgwIDs map[string]struct{}) map[string][]netip.Prefix {
	routeCIDRs := make(map[string][]netip.Prefix)
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
						routeCIDRs[*att.TransitGatewayAttachmentId] = append(
							routeCIDRs[*att.TransitGatewayAttachmentId], cidr,
						)
					}
				}
			}
		}
	}
	return routeCIDRs
}

func (d *tgwDiscovery) alreadyProcessed(accountID, resourceID string) bool {
	key := accountID + "/" + resourceID
	if _, ok := d.seen[key]; ok {
		return true
	}
	d.seen[key] = struct{}{}
	return false
}

func (d *tgwDiscovery) resolveVPCAttachment(ctx context.Context, att ec2types.TransitGatewayAttachment) (types.TransitGatewayVPC, bool) {
	accountID := lo.FromPtr(att.ResourceOwnerId)
	vpcID := lo.FromPtr(att.ResourceId)
	attID := lo.FromPtr(att.TransitGatewayAttachmentId)

	if d.alreadyProcessed(accountID, vpcID) {
		return types.TransitGatewayVPC{}, false
	}

	tgwVPC := d.buildTGWVPC(ctx, accountID, vpcID, attID, "")
	return tgwVPC, true
}

// resolvePeeringAttachment handles a TGW peering attachment by attempting to discover
// VPCs behind the peer TGW via cross-account role assumption. Falls back to
// route-table CIDRs when cross-account access isn't configured or fails.
func (d *tgwDiscovery) resolvePeeringAttachment(ctx context.Context, att ec2types.TransitGatewayAttachment) []types.TransitGatewayVPC {
	peerTGWID := lo.FromPtr(att.ResourceId) // for peering, ResourceId = peer TGW ID
	peerAccountID := lo.FromPtr(att.ResourceOwnerId)
	attID := lo.FromPtr(att.TransitGatewayAttachmentId)
	p := d.provider

	if p.cfg.AWSCrossAccountRoleARN != "" {
		// Look up the peer TGW's region via the peering attachment.
		peerRegion := d.getPeerTGWRegion(ctx, peerTGWID, attID)

		vpcs := d.discoverVPCsBehindPeerTGW(ctx, peerTGWID, peerAccountID, attID, peerRegion)
		if len(vpcs) > 0 {
			return vpcs
		}
	}

	// Fallback: emit a single entry with route-table CIDRs.
	if d.alreadyProcessed(peerAccountID, peerTGWID) {
		return nil
	}
	tgwVPC := types.TransitGatewayVPC{
		VPCID:     peerTGWID,
		AccountID: peerAccountID,
	}
	if cidrs, ok := d.routeCIDRs[attID]; ok {
		tgwVPC.CIDRs = cidrs
	}
	return []types.TransitGatewayVPC{tgwVPC}
}

// getPeerTGWRegion returns the cached region for a peer TGW, fetching it if needed.
func (d *tgwDiscovery) getPeerTGWRegion(ctx context.Context, peerTGWID, attachmentID string) string {
	if region, ok := d.peerTGWRegions[peerTGWID]; ok {
		return region
	}
	region, err := d.provider.fetchPeeringAttachmentRegion(ctx, attachmentID, peerTGWID)
	if err != nil {
		d.provider.log.With("peer_tgw", peerTGWID, "attachment", attachmentID).
			Warnf("failed to fetch peer TGW region (will use local region): %v", err)
		return ""
	}
	d.peerTGWRegions[peerTGWID] = region
	return region
}

// discoverVPCsBehindPeerTGW assumes a role in the peer TGW's account, enumerates
// VPC attachments on the peer TGW, and fetches subnets for each discovered VPC.
func (d *tgwDiscovery) discoverVPCsBehindPeerTGW(ctx context.Context, peerTGWID, peerAccountID, attID, peerRegion string) []types.TransitGatewayVPC {
	p := d.provider

	remoteEC2, err := p.getCrossAccountClient(ctx, d.crossAccountClients, peerAccountID, peerRegion)
	if err != nil {
		p.log.With("peer_tgw", peerTGWID, "account", peerAccountID, "region", peerRegion).
			Warnf("failed to assume role in peer TGW account (falling back to route CIDRs): %v", err)
		return nil
	}

	peerVPCAtts, err := p.fetchPeerTGWVPCAttachments(ctx, remoteEC2, peerTGWID)
	if err != nil {
		p.log.With("peer_tgw", peerTGWID, "account", peerAccountID, "region", peerRegion).
			Warnf("failed to discover VPCs behind peer TGW (falling back to route CIDRs): %v", err)
		return nil
	}

	var result []types.TransitGatewayVPC
	for _, vpcAtt := range peerVPCAtts {
		vpcID := lo.FromPtr(vpcAtt.ResourceId)
		vpcAccountID := lo.FromPtr(vpcAtt.ResourceOwnerId)

		if d.alreadyProcessed(vpcAccountID, vpcID) {
			continue
		}

		result = append(result, d.buildTGWVPC(ctx, vpcAccountID, vpcID, attID, peerRegion))
	}
	return result
}

// buildTGWVPC creates a TransitGatewayVPC, enriching with subnet detail via
// cross-account role assumption when configured, falling back to route CIDRs otherwise.
// regionOverride, when non-empty, targets the cross-account client at a specific region
// (used for VPCs behind a peer TGW in a different region).
func (d *tgwDiscovery) buildTGWVPC(ctx context.Context, accountID, vpcID, fallbackAttID, regionOverride string) types.TransitGatewayVPC {
	p := d.provider

	tgwVPC := types.TransitGatewayVPC{
		VPCID:     vpcID,
		AccountID: accountID,
	}

	if p.cfg.AWSCrossAccountRoleARN != "" {
		subnets, region, err := p.fetchRemoteSubnetsWithCache(ctx, d.crossAccountClients, accountID, vpcID, regionOverride)
		if err != nil {
			p.log.With("vpc", vpcID, "account", accountID).
				Warnf("cross-account subnet fetch failed (falling back to route CIDRs): %v", err)
		} else {
			tgwVPC.Subnets = subnets
			tgwVPC.Region = region
		}
	}

	if len(tgwVPC.Subnets) == 0 {
		if cidrs, ok := d.routeCIDRs[fallbackAttID]; ok {
			tgwVPC.CIDRs = cidrs
		}
	}

	if tgwVPC.Region == "" && len(tgwVPC.Subnets) > 0 {
		tgwVPC.Region = tgwVPC.Subnets[0].Region
	}

	return tgwVPC
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

// fetchAllTGWAttachments returns all attachments for a given Transit Gateway.
func (p *Provider) fetchAllTGWAttachments(ctx context.Context, tgwID string) ([]ec2types.TransitGatewayAttachment, error) {
	input := &ec2.DescribeTransitGatewayAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("transit-gateway-id"), Values: []string{tgwID}},
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
// If region is non-empty, the client targets that region instead of the default (cluster) region.
func (p *Provider) buildCrossAccountEC2Client(ctx context.Context, accountID, region string) (*ec2.Client, error) {
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

	if region != "" {
		awsCfg.Region = region
	}

	stsClient := sts.NewFromConfig(awsCfg)
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
	awsCfg.Credentials = aws.NewCredentialsCache(creds)

	p.log.Debugf("assuming cross-account role %s for account %s (region %s)", roleARN, accountID, awsCfg.Region)
	return ec2.NewFromConfig(awsCfg), nil
}

// fetchPeerTGWVPCAttachments discovers VPC attachments on a remote (peer) Transit Gateway.
func (p *Provider) fetchPeerTGWVPCAttachments(ctx context.Context, remoteEC2 *ec2.Client, peerTGWID string) ([]ec2types.TransitGatewayAttachment, error) {
	input := &ec2.DescribeTransitGatewayAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: lo.ToPtr("transit-gateway-id"), Values: []string{peerTGWID}},
			{Name: lo.ToPtr("resource-type"), Values: []string{"vpc"}},
			{Name: lo.ToPtr("state"), Values: []string{"available"}},
		},
	}

	var attachments []ec2types.TransitGatewayAttachment
	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(remoteEC2, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing VPC attachments for peer TGW %s: %w", peerTGWID, err)
		}
		attachments = append(attachments, page.TransitGatewayAttachments...)
	}

	p.log.Debugf("found %d VPC attachments on peer TGW %s", len(attachments), peerTGWID)
	return attachments, nil
}

// fetchPeeringAttachmentRegion looks up the region of a peer TGW by inspecting the
// peering attachment details. It calls DescribeTransitGatewayPeeringAttachments on the
// local EC2 client (no cross-account needed) and returns the region of whichever side
// matches peerTGWID.
func (p *Provider) fetchPeeringAttachmentRegion(ctx context.Context, attachmentID, peerTGWID string) (string, error) {
	input := &ec2.DescribeTransitGatewayPeeringAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentID},
	}

	result, err := p.ec2Client.DescribeTransitGatewayPeeringAttachments(ctx, input)
	if err != nil {
		return "", fmt.Errorf("describing peering attachment %s: %w", attachmentID, err)
	}

	if len(result.TransitGatewayPeeringAttachments) == 0 {
		return "", fmt.Errorf("peering attachment %s not found", attachmentID)
	}

	att := result.TransitGatewayPeeringAttachments[0]

	// The peer is whichever side's TGW ID matches peerTGWID.
	if att.AccepterTgwInfo != nil && lo.FromPtr(att.AccepterTgwInfo.TransitGatewayId) == peerTGWID {
		return lo.FromPtr(att.AccepterTgwInfo.Region), nil
	}
	if att.RequesterTgwInfo != nil && lo.FromPtr(att.RequesterTgwInfo.TransitGatewayId) == peerTGWID {
		return lo.FromPtr(att.RequesterTgwInfo.Region), nil
	}

	return "", fmt.Errorf("peer TGW %s not found in peering attachment %s", peerTGWID, attachmentID)
}

// getCrossAccountClient returns a cached cross-account EC2 client, creating one if needed.
// The cache is keyed by accountID/region to support the same account in different regions.
func (p *Provider) getCrossAccountClient(ctx context.Context, clientCache map[string]*ec2.Client, accountID, region string) (*ec2.Client, error) {
	cacheKey := accountID + "/" + region
	client, ok := clientCache[cacheKey]
	if ok {
		return client, nil
	}
	client, err := p.buildCrossAccountEC2Client(ctx, accountID, region)
	if err != nil {
		return nil, err
	}
	clientCache[cacheKey] = client
	return client, nil
}

// fetchRemoteSubnetsWithCache fetches remote subnets using a cached cross-account EC2 client.
// If region is non-empty, the client targets that region instead of the default.
func (p *Provider) fetchRemoteSubnetsWithCache(ctx context.Context, clientCache map[string]*ec2.Client, accountID, vpcID, region string) ([]types.Subnet, string, error) {
	client, err := p.getCrossAccountClient(ctx, clientCache, accountID, region)
	if err != nil {
		return nil, "", fmt.Errorf("building cross-account EC2 client: %w", err)
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
