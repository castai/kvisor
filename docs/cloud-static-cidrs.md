# Static CIDR Mappings

Static CIDR mappings let you manually annotate IP ranges that are not automatically discovered, such as on-premises networks, VPN endpoints, or cross-account VPCs without Transit Gateway connectivity.

> **Note:** kvisor does not perform any cost calculations. The `connectivityMethod` field is purely a label attached to netflow records so that downstream systems (e.g. CAST AI cost attribution) can distinguish traffic by connectivity type.

## When to Use

- The destination is in another AWS account or cloud and not reachable via the cloud API
- You use Direct Connect, Site-to-Site VPN, or other connectivity not automatically discovered
- You have managed services (RDS, Cloud SQL, etc.) with known private IPs
- Cloud provider API discovery is not enabled (`cloud-provider-vpc-sync-enabled: false`)

Static entries take **highest priority** in IP lookups — a static `/32` will override a broader cloud-discovered subnet.

## Configuration via Helm

Add `staticCIDRs` under `controller.netflow` in your `values.yaml`. Helm creates a ConfigMap and mounts it automatically when the list is non-empty:

```yaml
controller:
  netflow:
    staticCIDRs:
      mappings:
        - cidr: "10.1.0.0/24"
          zone: "us-east-1a"
          region: "us-east-1"
          name: "production-vpc"
          kind: "VPC"
          connectivityMethod: "TransitGateway"

        - cidr: "10.0.0.13/32"
          zone: "us-east-1a"
          region: "us-east-1"
          name: "production-rds"
          kind: "RDS"
          connectivityMethod: "PrivateLink"

        - cidr: "10.2.0.0/16"
          region: "us-east-1"
          name: "peered-vpc"
          kind: "VPC"
          connectivityMethod: "VPCPeering"
```

## Mapping Fields

| Field | Required | Description |
|---|---|---|
| `cidr` | yes | IP range in CIDR notation (e.g. `10.1.0.0/24`) or single IP (`10.0.0.1/32`) |
| `region` | yes | Cloud region (e.g. `us-east-1`) |
| `zone` | no | Availability zone. Leave empty for regional ranges |
| `name` | no | Human-readable name (e.g. `production-rds`) |
| `kind` | no | Resource type (e.g. `VPC`, `RDS`, `CloudSQL`, `OnPrem`) |
| `connectivityMethod` | no | See values below |

### Zone Names vs Zone IDs

By default, kvisor uses **zone names** (e.g. `us-east-1a`). AWS also exposes **zone IDs** (e.g. `use1-az1`) which are consistent across accounts — useful for cross-account cost attribution.

Enable zone IDs with:

```yaml
controller:
  extraArgs:
    cloud-provider-aws-use-zone-id: true
```

When enabled, the `zone` field in static mappings must also use zone IDs.

### `connectivityMethod` Values

This field is **optional and free-form**. The following are recommended values for common AWS networking paths:

| Value | Description |
|---|---|
| `VPCPeering` | VPC Peering |
| `TransitGateway` | AWS Transit Gateway |
| `PrivateLink` | AWS PrivateLink / VPC Endpoints |
| `DirectConnect` | AWS Direct Connect |
| `SiteToSiteVPN` | AWS Site-to-Site VPN |
| `NATGateway` | NAT Gateway |
| `IntraVPC` | Same VPC |

Custom values (e.g. `"on-prem-mpls"`, `"ExpressRoute"`) are passed through as-is in netflow records.

## Using a Pre-existing ConfigMap

If you manage your own ConfigMap (e.g. via GitOps):

```yaml
controller:
  extraArgs:
    cloud-provider-static-cidrs-file: /etc/kvisor/my-cidrs/static-cidrs.yaml

  extraVolumes:
    - name: my-static-cidrs
      configMap:
        name: my-existing-configmap

  extraVolumeMounts:
    - name: my-static-cidrs
      mountPath: /etc/kvisor/my-cidrs
      readOnly: true
```

The file must be valid YAML:

```yaml
staticCIDRMappings:
  - cidr: "10.1.0.0/24"
    zone: "us-east-1a"
    region: "us-east-1"
    name: "production-vpc"
    kind: "VPC"
    connectivityMethod: "TransitGateway"
```

## Combining with Cloud Discovery

Static mappings and cloud provider discovery work together. Static entries always win for the same IP:

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"

  netflow:
    staticCIDRs:
      mappings:
        # This /32 overrides whatever the cloud API says about 10.0.0.13
        - cidr: "10.0.0.13/32"
          region: "us-east-1"
          name: "cross-account-rds"
          connectivityMethod: "TransitGateway"
```
