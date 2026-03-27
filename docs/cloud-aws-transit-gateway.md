# AWS Transit Gateway (Multi-Account VPC Discovery)

When your cluster VPC is connected to other VPCs via [AWS Transit Gateway](https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html), kvisor can automatically discover remote VPCs and their CIDR ranges. This removes the need for manual [static CIDR mappings](cloud-static-cidrs.md) for TGW-connected networks.

## How It Works

1. kvisor discovers Transit Gateway attachments for the cluster VPC
2. For each TGW, it enumerates all VPC and peering attachments (including remote accounts)
3. It queries TGW route tables to discover destination CIDRs per attachment
4. If a cross-account role ARN is configured, kvisor assumes that role via STS to fetch subnet-level detail (zone, zone ID) from remote accounts
5. For TGW peering attachments, it resolves the peer TGW's region and discovers VPCs behind it

## Discovery Scenarios

### 1. Direct VPC Attachments (Same Region)

kvisor discovers all VPCs attached to the cluster's Transit Gateway, including VPCs in other accounts:

```
                          ┌──────────────────────────────────────────────────────┐
                          │              Same Region (e.g. us-east-1)           │
                          │                                                      │
  ┌─────────────────┐     │     ┌──────────────────┐     ┌─────────────────┐    │
  │  Cluster VPC    │     │     │  Transit Gateway  │     │  Remote VPC A   │    │
  │  Account 111    │─────┼────▶│                   │◀────│  Account 222    │    │
  │  10.0.0.0/16    │     │     │  TGW route table  │     │  10.1.0.0/16    │    │
  └─────────────────┘     │     │  has CIDR routes  │     └─────────────────┘    │
                          │     │  for all attached  │                            │
                          │     │  VPCs              │     ┌─────────────────┐    │
                          │     │                   │◀────│  Remote VPC B   │    │
                          │     └──────────────────┘     │  Account 333    │    │
                          │                               │  10.2.0.0/16    │    │
                          │                               └─────────────────┘    │
                          └──────────────────────────────────────────────────────┘

  Without cross-account role:
    → CIDRs from TGW route table (10.1.0.0/16, 10.2.0.0/16)
    → Region only, no AZ detail

  With cross-account role:
    → STS AssumeRole into accounts 222, 333
    → DescribeSubnets → per-subnet CIDR, zone name, zone ID
```

### 2. TGW Peering (Cross-Region / Cross-Account)

When a TGW has peering attachments, kvisor follows the peer to discover VPCs behind it:

```
  Region: us-east-1                              Region: eu-west-1
  ┌─────────────────────────────┐                ┌─────────────────────────────┐
  │                             │   TGW Peering  │                             │
  │  ┌───────────┐  ┌───────┐  │   Attachment    │  ┌───────┐  ┌───────────┐  │
  │  │ Cluster   │  │ TGW-1 │──┼────────────────▶│──│ TGW-2 │  │ Remote    │  │
  │  │ VPC       │─▶│       │  │                 │  │       │◀─│ VPC C     │  │
  │  │ Acct 111  │  │       │  │                 │  │       │  │ Acct 444  │  │
  │  └───────────┘  └───────┘  │                 │  └───────┘  └───────────┘  │
  │                             │                 │              ┌───────────┐  │
  │                             │                 │              │ Remote    │  │
  │                             │                 │              │ VPC D     │  │
  │                             │                 │              │ Acct 555  │  │
  │                             │                 │              └───────────┘  │
  └─────────────────────────────┘                └─────────────────────────────┘

  Discovery flow:
    1. kvisor finds TGW-1 peering attachment → resolves peer TGW-2 region (eu-west-1)
    2. If cross-account role configured:
       a. Assumes role in peer account → queries TGW-2 VPC attachments in eu-west-1
       b. Fetches subnet details (CIDRs, zones) from VPC C and VPC D via DescribeSubnets
    3. Without cross-account role: uses CIDRs from TGW-1's local route table (region only, no AZ detail)
```

### 3. Fallback Behavior Summary

```
  ┌────────────────────────────────┬──────────────────────────────────────────┐
  │  Configuration                 │  What You Get                            │
  ├────────────────────────────────┼──────────────────────────────────────────┤
  │  VPC sync only (no role)       │  TGW route CIDRs, region only            │
  │                                │  ✓ Good: auto-discovers connected VPCs   │
  │                                │  ✗ Missing: AZ / zone-level detail       │
  ├────────────────────────────────┼──────────────────────────────────────────┤
  │  VPC sync + cross-account role │  Subnet CIDRs, zone name + zone ID       │
  │                                │   ✓ Full: zone-aware network mapping     │
  │                                │                                          │
  ├────────────────────────────────┼──────────────────────────────────────────┤
  │  Role configured but STS fails │  Falls back to TGW route CIDRs           │
  │                                │  (logged as warning, non-fatal)          │
  └────────────────────────────────┴──────────────────────────────────────────┘
```

## What Gets Indexed

| Scenario | Zone | Region | Source |
|---|---|---|---|
| Cross-account role configured, subnets found | Yes (zone name or zone ID) | Yes | Remote `DescribeSubnets` |
| No cross-account role, or subnet fetch fails | No | Region only | TGW route table CIDRs |

## Basic Setup (Route-Level CIDRs Only)

TGW discovery works automatically when VPC sync is enabled — no extra flags needed. kvisor discovers TGW-attached VPCs and indexes their route-table CIDRs (region attribution, no per-AZ detail).

Requires the IAM permissions from [AWS EKS setup](cloud-aws.md#iam-policy) (the `DescribeTransitGateway*` and `SearchTransitGatewayRoutes` actions).

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-aws-region: "us-east-1"
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
```

> **Important:** Set `cloud-provider-aws-region` to the cluster's AWS region. This is used as the region for discovered TGW VPCs and for targeting cross-account API calls. Without it, discovered VPCs may have no region attribution in netflow records.

## Cross-Account Subnet Discovery (Optional)

For full subnet-level detail (zone names and zone IDs), configure a cross-account IAM role that kvisor can assume in each remote account.

### Step 1: Create IAM Role in Each Remote Account

**Permissions policy** (minimal — only needs to read subnets and TGW attachments):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets",
        "ec2:DescribeTransitGatewayAttachments"
      ],
      "Resource": "*"
    }
  ]
}
```

**Trust policy** (allows the kvisor role in the cluster account to assume this role):

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

<details>
<summary>AWS CLI (run once per remote account)</summary>

```bash
export CLUSTER_ACCOUNT_ID="123456789012"  # your cluster account ID

cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CLUSTER_ACCOUNT_ID}:role/KvisorVPCReaderRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

cat > permissions-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets",
        "ec2:DescribeTransitGatewayAttachments"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-role \
  --role-name KvisorCrossAccountReader \
  --assume-role-policy-document file://trust-policy.json \
  --description "Allows kvisor in cluster account to read subnet info for TGW discovery"

REMOTE_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws iam create-policy \
  --policy-name KvisorCrossAccountReaderPolicy \
  --policy-document file://permissions-policy.json

aws iam attach-role-policy \
  --role-name KvisorCrossAccountReader \
  --policy-arn arn:aws:iam::${REMOTE_ACCOUNT_ID}:policy/KvisorCrossAccountReaderPolicy

rm trust-policy.json permissions-policy.json
```

</details>

### Step 2: Add `sts:AssumeRole` to the Cluster Account Role

The kvisor role in the cluster account needs permission to assume the remote roles:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/KvisorCrossAccountReader"
}
```

<details>
<summary>AWS CLI (run in the cluster account)</summary>

```bash
cat > assume-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/KvisorCrossAccountReader"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name KvisorVPCReaderRole \
  --policy-name KvisorCrossAccountAssumePolicy \
  --policy-document file://assume-policy.json

rm assume-policy.json
```

</details>

**Verify** (optional):

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::REMOTE_ACCOUNT_ID:role/KvisorCrossAccountReader \
  --role-session-name kvisor-test
```

### Step 3: Configure the Cross-Account Role ARN Template

Add the `cloud-provider-aws-cross-account-role` flag. kvisor replaces `{account-id}` with the actual AWS account ID of each remote VPC discovered via the Transit Gateway.

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-aws-region: "us-east-1"
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    cloud-provider-aws-cross-account-role: "arn:aws:iam::{account-id}:role/KvisorCrossAccountReader"
```
