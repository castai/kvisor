package serviceranges

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

// AWS response structs.
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

// GCP response structs.
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

// FetchAWSServiceIPRanges fetches AWS public service IP ranges (no auth needed).
func FetchAWSServiceIPRanges(ctx context.Context, log *logging.Logger) ([]types.ServiceRanges, error) {
	const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

	rangesByRegion := make(map[string][]netip.Prefix)

	body, err := fetchURL(ctx, awsIPRangesURL)
	if err != nil {
		return nil, err
	}

	var ipRanges awsIPRangesResponse
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	for _, prefix := range ipRanges.Prefixes {
		cidr, err := netip.ParsePrefix(prefix.IPPrefix)
		if err != nil {
			log.Warnf("parsing CIDR %s: %v", prefix.IPPrefix, err)
			continue
		}

		region := prefix.Region
		if region == "" {
			region = "global"
		}

		rangesByRegion[region] = append(rangesByRegion[region], cidr)
	}

	for _, prefix := range ipRanges.IPv6 {
		cidr, err := netip.ParsePrefix(prefix.IPv6Prefix)
		if err != nil {
			log.Warnf("parsing IPv6 CIDR %s: %v", prefix.IPv6Prefix, err)
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

	log.Infof("fetched %d service IP ranges across %d regions",
		len(ipRanges.Prefixes)+len(ipRanges.IPv6), len(serviceRanges))

	return serviceRanges, nil
}

// FetchGCPServiceIPRanges fetches GCP public service IP ranges (no auth needed).
func FetchGCPServiceIPRanges(ctx context.Context, log *logging.Logger) ([]types.ServiceRanges, error) {
	const gcpIPRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

	rangesByRegion := make(map[string][]netip.Prefix)

	// Add known global ranges for Private Google Access and Restricted Google Access.
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
			log.Warnf("parsing known range %s: %v", r, err)
			continue
		}
		rangesByRegion["global"] = append(rangesByRegion["global"], prefix)
	}

	body, err := fetchURL(ctx, gcpIPRangesURL)
	if err != nil {
		return nil, err
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
			continue
		}

		cidr, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			log.Warnf("parsing CIDR %s: %v", cidrStr, err)
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

	log.Infof("fetched %d service IP ranges across %d regions (including %d global ranges)",
		len(ipRanges.Prefixes)+len(knownGlobalRanges), len(serviceRanges), len(knownGlobalRanges))

	return serviceRanges, nil
}

// FetchServiceIPRanges dispatches to the provider-specific function based on type.
func FetchServiceIPRanges(ctx context.Context, log *logging.Logger, providerType types.Type) ([]types.ServiceRanges, string, error) {
	switch providerType {
	case types.TypeAWS:
		ranges, err := FetchAWSServiceIPRanges(ctx, log)
		return ranges, types.DomainAWS, err
	case types.TypeGCP:
		ranges, err := FetchGCPServiceIPRanges(ctx, log)
		return ranges, types.DomainGCP, err
	default:
		return nil, "", fmt.Errorf("unsupported cloud provider type for service IP ranges: %s", providerType)
	}
}

const maxResponseSize = 20 * 1024 * 1024 // 20MB

func fetchURL(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status code %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}

	return body, nil
}
