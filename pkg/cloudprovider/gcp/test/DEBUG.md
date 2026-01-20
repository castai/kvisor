# GCP VPC Integration Tests

These tests make real API calls to GCP and require actual credentials.

## Prerequisites

### 1. GCP Project
You need access to a GCP project with VPC networks configured.
If you have setup gcloud cli credentials you don't need to do anything extra, otherwsie go to step 2 and 3

### 2. Service Account Credentials (Optional)
Create a service account with the following IAM permissions:
- `compute.networks.list`
- `compute.networks.listPeeringRoutes`
- `compute.subnetworks.list`

You can use one of these pre-defined roles:
- **Compute Network Viewer** (`roles/compute.networkViewer`) - Recommended minimal permissions
- **Compute Viewer** (`roles/compute.viewer`) - Broader read access

### 3. Download Service Account Key (Optional)
```bash
# Create service account
gcloud iam service-accounts create kvisor-integration-test \
    --project=YOUR_PROJECT_ID \
    --display-name="Kvisor Integration Test"

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:kvisor-integration-test@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/compute.networkViewer"

# Download key
gcloud iam service-accounts keys create ~/kvisor-test-sa-key.json \
    --iam-account=kvisor-integration-test@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

## Running the Tests

### Basic Test Run
```bash
# Set environment variables
export GCP_PROJECT_ID="your-project-id"
export GCP_CREDENTIALS_FILE="$HOME/kvisor-test-sa-key.json"

# Run the tests
go test -v -run TestRefreshState ./...
```

## Cleanup

After testing, you can delete the service account and key:

```bash
# List keys
gcloud iam service-accounts keys list \
    --iam-account=kvisor-integration-test@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Delete key
gcloud iam service-accounts keys delete KEY_ID \
    --iam-account=kvisor-integration-test@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Delete service account
gcloud iam service-accounts delete \
    kvisor-integration-test@YOUR_PROJECT_ID.iam.gserviceaccount.com
```
