# Cloud State controller Configuration

## Overview

The Cloud state controller enriches netflow data with cloud provider network information, including:

- VPC and subnet details: CIDR ranges, regions, zones.
- VPC peering connections and their IP ranges
- Transit Gateway cross-account VPC discovery (AWS)
- Cloud provider service IP ranges

This network state enables better network flow analysis and region/zone attribution for network traffic.
**NOTE**: Zones information is not available via GCP VPC state due to the nature of networking in GCP.

## How It Works

1. On startup, kvisor fetches VPC network state from your cloud provider API
2. Network state is cached and refreshed periodically (default: every hour)
3. Network flow events are enriched with VPC context (region, zone, subnet info)
4. The controller runs as a background controller in the kvisor controller pod

## Supported Cloud Providers

Currently supported:
- **GCP** - Workload Identity and Service Account authentication
- **AWS** - IRSA (IAM Roles for Service Accounts) and IAM User authentication

Coming soon:
- Azure

---

## GCP Configuration

### Prerequisites

1. **GCP Project** with the VPC you want to monitor
2. **GCP Service Account** with the following IAM permissions:
   - `compute.networks.list`
   - `compute.networks.listPeeringRoutes`
   - `compute.subnetworks.list`

   **Recommended IAM Role:** `roles/compute.networkViewer`

3. **VPC Network Name** - The name of the VPC network to monitor

### Authentication Methods

Choose one of the following authentication methods:

#### Option 1: Workload Identity (Recommended)

**Step 1: Create GCP Service Account**

```bash
export PROJECT_ID="your-gcp-project-id"
export SERVICE_ACCOUNT_NAME="kvisor-vpc-reader"

# Create service account
gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} \
  --project=${PROJECT_ID} \
  --display-name="Kvisor VPC State Reader"

# Grant necessary permissions
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --project=${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.networkViewer"
```

**Step 2: Enable Workload Identity Binding**

```bash
export NAMESPACE="kvisor"
export KSA_NAME="kvisor"  # Kubernetes service account name

# Bind Kubernetes service account to GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
  --project=${PROJECT_ID} \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[${NAMESPACE}/${KSA_NAME}]"
```

**Step 3: Configure Helm Values**

Create or update your `values.yaml`:

```yaml
agent:
  extraArgs:
    # Right now agent is getting all cluster network ranges upon pod start
    # so in this case we could miss some flows if network ranges change
    # as temporary solution we can disable this check
    netflow-check-cluster-network-ranges: false

controller:
  extraArgs:
    # Cloud provider configuration
    cloud-provider: gcp
    cloud-provider-gcp-project-id: "your-gcp-project-id"

    # VPC controller configuration
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "your-vpc-name"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval
    cloud-provider-vpc-cache-size: 10000 # Optional: cache size

  nodeSelector:
    iam.gke.io/gke-metadata-server-enabled: "true"

  # Service account with Workload Identity annotation
  serviceAccount:
    create: true
    name: kvisor
    annotations:
      iam.gke.io/gcp-service-account: "kvisor-vpc-reader@your-gcp-project-id.iam.gserviceaccount.com"
```

**Step 4: Install/Upgrade kvisor**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor \
  --create-namespace \
  --values values.yaml
```

---

#### Option 2: Service Account Key File

**Step 1: Create GCP Service Account and Key**

```bash
export PROJECT_ID="your-gcp-project-id"
export SERVICE_ACCOUNT_NAME="kvisor-vpc-reader"

# Create service account
gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} \
  --project=${PROJECT_ID} \
  --display-name="Kvisor VPC State Reader"

# Grant necessary permissions
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --project=${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.networkViewer"

# Create and download key
gcloud iam service-accounts keys create kvisor-sa-key.json \
  --project=${PROJECT_ID} \
  --iam-account=${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
```

**Step 2: Create Kubernetes Secret**

```bash
kubectl create namespace kvisor

kubectl create secret generic gcp-credentials \
  --from-file=credentials.json=kvisor-sa-key.json \
  --namespace kvisor

# Delete the local key file
rm kvisor-sa-key.json
```

**Step 3: Configure Helm Values**

Create or update your `values.yaml`:

```yaml
controller:
  # VPC controller configuration
  extraArgs:
    cloud-provider: gcp
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-gcp-project-id: "your-gcp-project-id"
    cloud-provider-vpc-name: "your-vpc-name"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval

  # Mount credentials as environment variable
  env:
    - name: GCP_CREDENTIALS_FILE
      value: /var/secrets/gcp/credentials.json

  # Mount secret as volume
  volumeMounts:
    - name: gcp-credentials
      mountPath: /var/secrets/gcp
      readOnly: true

  volumes:
    - name: gcp-credentials
      secret:
        secretName: gcp-credentials
```

**Step 4: Install/Upgrade kvisor**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor \
  --create-namespace \
  --values values.yaml
```

---

## AWS EKS Configuration

### Prerequisites

1. **AWS Account** with the VPC you want to monitor
2. **IAM Role or User** with the following permissions:
   - `ec2:DescribeVpcs`
   - `ec2:DescribeSubnets`
   - `ec2:DescribeVpcPeeringConnections`
   - `ec2:DescribeTransitGatewayAttachments` (for Transit Gateway discovery)
   - `ec2:DescribeTransitGatewayRouteTables` (for Transit Gateway discovery)
   - `ec2:SearchTransitGatewayRoutes` (for Transit Gateway discovery)
   - `sts:AssumeRole` (for cross-account subnet discovery, optional)

   **Recommended IAM Policy:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:DescribeVpcs",
           "ec2:DescribeSubnets",
           "ec2:DescribeVpcPeeringConnections",
           "ec2:DescribeTransitGatewayAttachments",
           "ec2:DescribeTransitGatewayRouteTables",
           "ec2:SearchTransitGatewayRoutes"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **VPC ID** - The ID of the VPC to monitor (e.g., `vpc-0123456789abcdef0`)

### Authentication Methods

Choose one of the following authentication methods:

#### Option 1: IRSA - IAM Roles for Service Accounts (Recommended)

**Step 1: Create IAM Policy**

```bash
export AWS_REGION="us-east-1"
export POLICY_NAME="KvisorVPCReaderPolicy"

cat > kvisor-vpc-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name ${POLICY_NAME} \
  --policy-document file://kvisor-vpc-policy.json \
  --region ${AWS_REGION}
```

**Step 2: Create IAM Role for Service Account**

You have two options:

**Option A: Use existing kvisor service account (Recommended)**

```bash
export CLUSTER_NAME="your-eks-cluster"
export NAMESPACE="kvisor"
export SERVICE_ACCOUNT_NAME="kvisor"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Associate OIDC provider with cluster (if not already done)
eksctl utils associate-iam-oidc-provider \
  --cluster ${CLUSTER_NAME} \
  --region ${AWS_REGION} \
  --approve

# Get OIDC provider URL
export OIDC_PROVIDER=$(aws eks describe-cluster --name ${CLUSTER_NAME} --region ${AWS_REGION} --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")

# Create IAM role with trust policy for the existing service account
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT_NAME}",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create the IAM role
aws iam create-role \
  --role-name KvisorVPCReaderRole \
  --assume-role-policy-document file://trust-policy.json

# Attach the policy to the role
aws iam attach-role-policy \
  --role-name KvisorVPCReaderRole \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}

# Get the role ARN (you'll need this for helm values)
export ROLE_ARN=$(aws iam get-role --role-name KvisorVPCReaderRole --query 'Role.Arn' --output text)
echo "Role ARN: ${ROLE_ARN}"
```

**Option B: Let eksctl create a new service account**

```bash
export CLUSTER_NAME="your-eks-cluster"
export NAMESPACE="kvisor"
export SERVICE_ACCOUNT_NAME="kvisor"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Associate OIDC provider with cluster (if not already done)
eksctl utils associate-iam-oidc-provider \
  --cluster ${CLUSTER_NAME} \
  --region ${AWS_REGION} \
  --approve

# Create IAM role and service account
eksctl create iamserviceaccount \
  --cluster=${CLUSTER_NAME} \
  --namespace=${NAMESPACE} \
  --name=${SERVICE_ACCOUNT_NAME} \
  --attach-policy-arn=arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME} \
  --region=${AWS_REGION} \
  --approve
```

**Step 3: Configure Helm Values**

Create or update your `values.yaml`:

**For Option A (existing service account):**

```yaml
controller:
  extraArgs:
    # Cloud provider configuration
    cloud-provider: aws

    # VPC controller configuration
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval
    cloud-provider-vpc-cache-size: 10000  # Optional: cache size
    # cloud-provider-aws-use-zone-id: true  # Optional: use zone IDs (e.g. "use1-az1") instead of zone names (e.g. "us-east-1a")

  serviceAccount:
    create: true
    name: kvisor
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::YOUR_ACCOUNT_ID:role/KvisorVPCReaderRole"
```

**For Option B (eksctl-created service account):**

```yaml
controller:
  extraArgs:
    # Cloud provider configuration
    cloud-provider: aws

    # VPC controller configuration
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval
    cloud-provider-vpc-cache-size: 10000  # Optional: cache size
    # cloud-provider-aws-use-zone-id: true  # Optional: use zone IDs (e.g. "use1-az1") instead of zone names (e.g. "us-east-1a")

  serviceAccount:
    create: false
```

**Step 4: Install/Upgrade kvisor**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor \
  --create-namespace \
  --values values.yaml
```

---

#### Option 2: IAM User with Access Keys

**Step 1: Create IAM User and Policy**

```bash
export USER_NAME="kvisor-vpc-reader"
export POLICY_NAME="KvisorVPCReaderPolicy"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create policy
cat > kvisor-vpc-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name ${POLICY_NAME} \
  --policy-document file://kvisor-vpc-policy.json

# Create IAM user
aws iam create-user --user-name ${USER_NAME}

# Attach policy to user
aws iam attach-user-policy \
  --user-name ${USER_NAME} \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}

# Create access key
aws iam create-access-key --user-name ${USER_NAME} > access-key.json
```

**Step 2: Create Kubernetes Secret**

```bash
export AWS_ACCESS_KEY_ID=$(cat access-key.json | jq -r '.AccessKey.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(cat access-key.json | jq -r '.AccessKey.SecretAccessKey')

kubectl create namespace kvisor

kubectl create secret generic aws-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  --from-literal=AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  --namespace kvisor

# Delete the local credentials file
rm access-key.json
```

**Step 3: Configure Helm Values**

Create or update your `values.yaml`:

```yaml
controller:
  extraArgs:
    # Cloud provider configuration
    cloud-provider: aws

    # VPC controller configuration
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval
    cloud-provider-vpc-cache-size: 10000  # Optional: cache size
    # cloud-provider-aws-use-zone-id: true  # Optional: use zone IDs (e.g. "use1-az1") instead of zone names (e.g. "us-east-1a")

  # Mount credentials as environment variables
  envFrom:
    - secretRef:
        name: aws-credentials

  serviceAccount:
    create: true
    name: kvisor
```

**Step 4: Install/Upgrade kvisor**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor \
  --create-namespace \
  --values values.yaml
```

---

## AWS Transit Gateway (Multi-Account VPC Discovery)

When your cluster VPC is connected to other VPCs via an [AWS Transit Gateway](https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html), kvisor can automatically discover remote VPCs and their CIDR ranges. This enables zone/region attribution for cross-account traffic without manual static CIDR configuration.

### How It Works

1. kvisor discovers Transit Gateway attachments for the cluster VPC
2. For each TGW, it enumerates all VPC attachments (including remote accounts)
3. It queries TGW route tables to discover destination CIDRs for each attachment
4. If a cross-account role ARN is configured, kvisor assumes that role via STS to fetch subnet-level detail (zone, zone ID) from remote accounts
5. Discovered CIDRs/subnets are indexed alongside VPC peering and local subnet data

### Basic Setup (Route-Level CIDRs Only)

Transit Gateway discovery works out of the box with the standard IAM permissions listed above — no additional configuration needed. kvisor will discover TGW-attached VPCs and index their route-level CIDRs (region only, no zone detail).

### Cross-Account Subnet Discovery (Optional)

For full subnet-level detail (zone names and zone IDs), configure a cross-account IAM role that kvisor can assume in each remote account.

**Step 1: Create IAM Role in Each Remote Account**

In each remote AWS account connected via the Transit Gateway, create an IAM role with:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets"
      ],
      "Resource": "*"
    }
  ]
}
```

The trust policy should allow the kvisor role in the cluster account to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::CLUSTER_ACCOUNT_ID:role/KvisorVPCReaderRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Step 2: Add `sts:AssumeRole` to the Cluster Account Role**

The kvisor IAM role in the cluster account also needs permission to assume the remote roles:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/KvisorCrossAccountReader"
}
```

**Step 3: Configure the Cross-Account Role ARN Template**

Add the `cloud-provider-aws-cross-account-role` flag with the `{account-id}` placeholder:

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    cloud-provider-aws-cross-account-role: "arn:aws:iam::{account-id}:role/KvisorCrossAccountReader"
```

kvisor replaces `{account-id}` with the actual AWS account ID of each remote VPC discovered via the Transit Gateway.

### What Gets Indexed

| Scenario | Zone | Region | Source |
|---|---|---|---|
| Cross-account role configured, subnets found | Yes (zone name or zone ID) | Yes | Remote account `DescribeSubnets` |
| No cross-account role, or `DescribeSubnets` fails | No | Yes | TGW route table CIDRs |

---

## Static CIDR Mappings

Static CIDR mappings let you manually annotate IP ranges such as cross-account VPCs, Transit Gateway destinations etc.

> **Note:** kvisor does not perform any cost calculations. The `connectivityMethod` field is purely a label attached to netflow records so that downstream systems (e.g. CAST AI cost attribution) can distinguish traffic by connectivity type.

### When to Use

Use static mappings when:
- The destination is in another AWS account or cloud provider and not reachable via the cloud API
- You use AWS Transit Gateway, Direct Connect, or Site-to-Site VPN
- You have managed services (RDS, Cloud SQL, etc.) with known private IPs
- Cloud provider API discovery is not enabled (`cloud-provider-vpc-sync-enabled: false`)

Static entries take **highest priority** in IP lookups — a static `/32` will override a broader cloud-discovered subnet.

### Configuration via Helm

Add `staticCIDRs` under `controller.netflow` in your `values.yaml`. The ConfigMap is created and mounted automatically when the list is non-empty:

```yaml
controller:
  netflow:
    staticCIDRs:
      mappings:
        # Cross-account VPC via Transit Gateway
        - cidr: "10.1.0.0/24"
          zone: "us-east-1a"
          region: "us-east-1"
          name: "production-vpc"
          kind: "VPC"
          connectivityMethod: "TransitGateway"

        # Single IP (overrides broader cloud-discovered CIDRs)
        - cidr: "10.0.0.13/32"
          zone: "us-east-1a"
          region: "us-east-1"
          name: "production-rds"
          kind: "RDS"
          connectivityMethod: "PrivateLink"

        # Regional range without a specific zone
        - cidr: "10.2.0.0/16"
          zone: ""
          region: "us-east-1"
          name: "peered-vpc"
          kind: "VPC"
          connectivityMethod: "VPCPeering"
```

When `mappings` is non-empty, Helm creates a ConfigMap and mounts it into the controller pod. The controller reads it at startup via `--cloud-provider-static-cidrs-file`.

### Mapping Fields

| Field | Required | Description |
|---|---|---|
| `cidr` | yes | IP range in CIDR notation (e.g. `10.1.0.0/24`) or single IP (`10.0.0.1/32`) |
| `region` | yes | Cloud region (e.g. `us-east-1`) |
| `zone` | no | Availability zone. Leave empty for regional ranges. See note below about zone names vs zone IDs |
| `name` | no | Human-readable name for the destination (e.g. `production-rds`) |
| `kind` | no | Resource type (e.g. `VPC`, `RDS`, `CloudSQL`, `OnPrem`) |
| `connectivityMethod` | no | See supported values below |

#### Zone Names vs Zone IDs (`cloud-provider-aws-use-zone-id`)

By default, kvisor uses **zone names** (e.g. `us-east-1a`) for zone resolution. AWS also exposes **zone IDs** (e.g. `use1-az1`) which are consistent identifiers across accounts — useful for cross-account cost attribution where zone names may differ.

You can switch to zone IDs with the controller flag:

```yaml
controller:
  extraArgs:
    cloud-provider-aws-use-zone-id: true
```

When this flag is enabled, the `zone` field in your static CIDR mappings must also use zone IDs (e.g. `use1-az1`) instead of zone names (e.g. `us-east-1a`) to match correctly.

### `connectivityMethod` Values

The `connectivityMethod` field is **optional and free-form** — it can be left empty or set to any custom string value. kvisor does not validate or enforce this field; it is passed through as-is in netflow records.

The following values are a recommended set for common AWS networking paths. Using them enables downstream systems (e.g. CAST AI cost attribution) to recognize and categorize traffic consistently.

| Value | Description |
|---|---|
| `VPCPeering` | VPC Peering |
| `TransitGateway` | AWS Transit Gateway |
| `PrivateLink` | AWS PrivateLink / VPC Endpoints ($0.01/GB processing) |
| `DirectConnect` | AWS Direct Connect (port-hour + ~$0.02/GB data-out) |
| `SiteToSiteVPN` | AWS Site-to-Site VPN |
| `NATGateway` | NAT Gateway |
| `IntraVPC` | Same VPC |

You may also use custom values (e.g. `"on-prem-mpls"`, `"ExpressRoute"`) — they will appear as-is in netflow records.

### Using a Pre-existing ConfigMap

If you manage your own ConfigMap (e.g. via GitOps), mount it manually and pass the file path via `extraArgs`:

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

The file must be valid YAML with the following structure:

```yaml
staticCIDRMappings:
  - cidr: "10.1.0.0/24"
    zone: "us-east-1a"
    region: "us-east-1"
    name: "production-vpc"
    kind: "VPC"
    connectivityMethod: "TransitGateway"
```

### Combining with Cloud Provider Discovery

Static mappings and cloud provider VPC discovery can be used together. Static entries always win over cloud-discovered entries for the same IP.

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
