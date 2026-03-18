# AWS EKS Configuration

## Prerequisites

1. **AWS Account** with the VPC you want to monitor
2. **VPC ID** — e.g. `vpc-0123456789abcdef0`
3. **IAM Role or User** with the following permissions:

### IAM Policy

This policy covers VPC, peering, and Transit Gateway discovery. If you don't use Transit Gateway, the `TransitGateway*` and `SearchTransitGatewayRoutes` actions are unused but harmless.

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
        "ec2:DescribeTransitGatewayPeeringAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes"
      ],
      "Resource": "*"
    }
  ]
}
```

For cross-account Transit Gateway subnet discovery, also add `sts:AssumeRole` — see [Transit Gateway docs](cloud-aws-transit-gateway.md).

---

## Option 1: IRSA — IAM Roles for Service Accounts (Recommended)

**Step 1: Create IAM Policy**

```bash
export AWS_REGION="us-east-1"
export POLICY_NAME="KvisorVPCReaderPolicy"

cat > kvisor-vpc-policy.json <<'EOF'
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
        "ec2:DescribeTransitGatewayPeeringAttachments",
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

<details>
<summary>Option A: Use existing kvisor service account (Recommended)</summary>

```bash
export CLUSTER_NAME="your-eks-cluster"
export NAMESPACE="kvisor"
export SERVICE_ACCOUNT_NAME="kvisor"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

eksctl utils associate-iam-oidc-provider \
  --cluster ${CLUSTER_NAME} --region ${AWS_REGION} --approve

export OIDC_PROVIDER=$(aws eks describe-cluster --name ${CLUSTER_NAME} --region ${AWS_REGION} \
  --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")

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

aws iam create-role \
  --role-name KvisorVPCReaderRole \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy \
  --role-name KvisorVPCReaderRole \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}

export ROLE_ARN=$(aws iam get-role --role-name KvisorVPCReaderRole --query 'Role.Arn' --output text)
echo "Role ARN: ${ROLE_ARN}"
```

</details>

<details>
<summary>Option B: Let eksctl create a new service account</summary>

```bash
export CLUSTER_NAME="your-eks-cluster"
export NAMESPACE="kvisor"
export SERVICE_ACCOUNT_NAME="kvisor"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

eksctl utils associate-iam-oidc-provider \
  --cluster ${CLUSTER_NAME} --region ${AWS_REGION} --approve

eksctl create iamserviceaccount \
  --cluster=${CLUSTER_NAME} \
  --namespace=${NAMESPACE} \
  --name=${SERVICE_ACCOUNT_NAME} \
  --attach-policy-arn=arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME} \
  --region=${AWS_REGION} \
  --approve
```

</details>

**Step 3: Configure Helm Values**

For Option A (existing service account):

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    # cloud-provider-vpc-sync-interval: 1h
    # cloud-provider-vpc-cache-size: 10000
    # cloud-provider-aws-use-zone-id: true

  serviceAccount:
    create: true
    name: kvisor
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::YOUR_ACCOUNT_ID:role/KvisorVPCReaderRole"
```

For Option B (eksctl-created service account), set `serviceAccount.create: false`.

**Step 4: Install/Upgrade**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor --create-namespace --values values.yaml
```

---

## Option 2: IAM User with Access Keys

**Step 1: Create IAM User and Policy**

```bash
export USER_NAME="kvisor-vpc-reader"
export POLICY_NAME="KvisorVPCReaderPolicy"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create policy (same JSON as above)
cat > kvisor-vpc-policy.json <<'EOF'
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
        "ec2:DescribeTransitGatewayPeeringAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:SearchTransitGatewayRoutes"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy --policy-name ${POLICY_NAME} --policy-document file://kvisor-vpc-policy.json
aws iam create-user --user-name ${USER_NAME}
aws iam attach-user-policy --user-name ${USER_NAME} \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}
aws iam create-access-key --user-name ${USER_NAME} > access-key.json
```

**Step 2: Create Kubernetes Secret**

```bash
export AWS_ACCESS_KEY_ID=$(jq -r '.AccessKey.AccessKeyId' access-key.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.AccessKey.SecretAccessKey' access-key.json)

kubectl create namespace kvisor
kubectl create secret generic aws-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  --from-literal=AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  --namespace kvisor

rm access-key.json
```

**Step 3: Configure Helm Values**

```yaml
controller:
  extraArgs:
    cloud-provider: aws
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "vpc-0123456789abcdef0"
    # cloud-provider-vpc-sync-interval: 1h
    # cloud-provider-vpc-cache-size: 10000
    # cloud-provider-aws-use-zone-id: true

  envFrom:
    - secretRef:
        name: aws-credentials

  serviceAccount:
    create: true
    name: kvisor
```

**Step 4: Install/Upgrade**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor --create-namespace --values values.yaml
```
