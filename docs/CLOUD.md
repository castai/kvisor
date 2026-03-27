# Cloud Network State

The cloud state controller enriches netflow data with cloud provider network information (VPC/subnet CIDRs, regions, zones, peering, Transit Gateway) so that network flows can be attributed to specific regions and availability zones.

> **Note:** Zone information is not available for GCP due to the nature of GCP networking (subnets are regional, not zonal).

## How It Works

1. On startup, kvisor fetches VPC network state from your cloud provider API
2. Network state is cached and refreshed periodically (default: every hour)
3. Cloud service IP ranges (e.g. `ip-ranges.amazonaws.com`) are fetched separately (no auth needed, refreshed daily)
4. Network flow events are enriched with VPC context (region, zone, subnet info)

IP lookup uses a three-tier priority: **static mappings > cloud-discovered > public cloud service ranges**.

## Setup Guides

| Guide | Description |
|---|---|
| [GCP Configuration](cloud-gcp.md) | Workload Identity or Service Account key setup |
| [AWS EKS Configuration](cloud-aws.md) | IRSA or IAM User setup for VPC/subnet discovery |
| [AWS Transit Gateway](cloud-aws-transit-gateway.md) | Multi-account VPC discovery via TGW (cross-account role assumption) |
| [Static CIDR Mappings](cloud-static-cidrs.md) | Manual IP range annotation for on-prem, VPN, managed services |

## Supported Cloud Providers

- **GCP** — Workload Identity and Service Account authentication
- **AWS** — IRSA (IAM Roles for Service Accounts) and IAM User authentication
- **Azure** — coming soon

## Common Helm Flags

| Flag | Description | Default |
|---|---|---|
| `cloud-provider` | `aws` or `gcp` | — |
| `cloud-provider-vpc-sync-enabled` | Enable VPC state discovery | `false` |
| `cloud-provider-vpc-name` | VPC ID (AWS) or network name (GCP) | — |
| `cloud-provider-vpc-sync-interval` | Refresh interval | `1h` |
| `cloud-provider-vpc-cache-size` | LRU cache size for IP lookups | `10000` |
| `cloud-provider-aws-region` | AWS region (required for TGW region attribution) | — |
| `cloud-provider-aws-use-zone-id` | Use zone IDs (`use1-az1`) instead of zone names (`us-east-1a`) | `false` |
| `cloud-provider-aws-cross-account-role` | Cross-account role ARN template (see [TGW docs](cloud-aws-transit-gateway.md)) | — |
| `cloud-provider-static-cidrs-file` | Path to static CIDR YAML (see [static CIDRs](cloud-static-cidrs.md)) | — |
