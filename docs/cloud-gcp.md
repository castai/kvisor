# GCP Configuration

## Prerequisites

1. **GCP Project** with the VPC you want to monitor
2. **GCP Service Account** with the following IAM permissions:
   - `compute.networks.list`
   - `compute.networks.listPeeringRoutes`
   - `compute.subnetworks.list`

   **Recommended IAM Role:** `roles/compute.networkViewer`

3. **VPC Network Name** — the name of the VPC network to monitor

## Option 1: Workload Identity (Recommended)

**Step 1: Create GCP Service Account**

```bash
export PROJECT_ID="your-gcp-project-id"
export SERVICE_ACCOUNT_NAME="kvisor-vpc-reader"

gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} \
  --project=${PROJECT_ID} \
  --display-name="Kvisor VPC State Reader"

gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --project=${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.networkViewer"
```

**Step 2: Enable Workload Identity Binding**

```bash
export NAMESPACE="kvisor"
export KSA_NAME="kvisor"

gcloud iam service-accounts add-iam-policy-binding \
  ${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
  --project=${PROJECT_ID} \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[${NAMESPACE}/${KSA_NAME}]"
```

**Step 3: Configure Helm Values**

```yaml
agent:
  extraArgs:
    netflow-check-cluster-network-ranges: false

controller:
  extraArgs:
    cloud-provider: gcp
    cloud-provider-gcp-project-id: "your-gcp-project-id"
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-vpc-name: "your-vpc-name"
    cloud-provider-vpc-sync-interval: 1h  # Optional
    cloud-provider-vpc-cache-size: 10000  # Optional

  nodeSelector:
    iam.gke.io/gke-metadata-server-enabled: "true"

  serviceAccount:
    create: true
    name: kvisor
    annotations:
      iam.gke.io/gcp-service-account: "kvisor-vpc-reader@your-gcp-project-id.iam.gserviceaccount.com"
```

**Step 4: Install/Upgrade**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor --create-namespace --values values.yaml
```

---

## Option 2: Service Account Key File

**Step 1: Create GCP Service Account and Key**

```bash
export PROJECT_ID="your-gcp-project-id"
export SERVICE_ACCOUNT_NAME="kvisor-vpc-reader"

gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} \
  --project=${PROJECT_ID} \
  --display-name="Kvisor VPC State Reader"

gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --project=${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/compute.networkViewer"

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

rm kvisor-sa-key.json
```

**Step 3: Configure Helm Values**

```yaml
controller:
  extraArgs:
    cloud-provider: gcp
    cloud-provider-vpc-sync-enabled: true
    cloud-provider-gcp-project-id: "your-gcp-project-id"
    cloud-provider-vpc-name: "your-vpc-name"
    cloud-provider-vpc-sync-interval: 1h  # Optional

  env:
    - name: GCP_CREDENTIALS_FILE
      value: /var/secrets/gcp/credentials.json

  volumeMounts:
    - name: gcp-credentials
      mountPath: /var/secrets/gcp
      readOnly: true

  volumes:
    - name: gcp-credentials
      secret:
        secretName: gcp-credentials
```

**Step 4: Install/Upgrade**

```bash
helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
  --namespace kvisor --create-namespace --values values.yaml
```
