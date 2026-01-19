# Cloud Metadata Syncer Configuration

## Overview

The Cloud metadata syncer enriches netflow data with cloud provider network information, including:

- VPC and subnet details: CIDR ranges, regions, zones.
- VPC peering connections and their IP ranges
- Cloud provider service IP ranges

This metadata enables better network flow analysis and region/zone attribution for network traffic.
**NOTE**: Zones information is not available via GCP VPC metadata due to the nature of networking in GCP.

## How It Works

1. On startup, kvisor fetches VPC metadata from your cloud provider API
2. Metadata is cached and refreshed periodically (default: every hour)
3. Network flow events are enriched with VPC context (region, zone, subnet info)
4. The syncer runs as a background controller in the kvisor controller pod

## Supported Cloud Providers

Currently supported:
- GCP  - Support with Workload Identity and Service Account authentication

Coming soon:
- AWS
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
  --display-name="Kvisor VPC Metadata Reader"

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
    # VPC syncer configuration
    cloud-provider: gcp
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-gcp-project-id: "your-gcp-project-id"
    cloud-provider-vpc-name: "your-vpc-name"
    cloud-provider-vpc-sync-interval: 1h  # Optional: refresh interval
    cloud-provider-vpc-name: "your-vpc-name"

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
  --display-name="Kvisor VPC Metadata Reader"

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
  # VPC syncer configuration
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
