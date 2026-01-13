package gcp

import (
	"fmt"
	"os"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"google.golang.org/api/option"
)

// buildClientOptions constructs GCP client options with authentication.
// Priority: Workload Identity (default) > Service Account Key File > Default Credentials
func buildClientOptions(cfg types.Config) ([]option.ClientOption, error) {
	var opts []option.ClientOption

	// Try Workload Identity first (no credentials needed - uses pod service account)
	if isWorkloadIdentityAvailable() {
		// Workload Identity is automatically used by GCP client libraries
		// when GOOGLE_APPLICATION_CREDENTIALS is not set
		return opts, nil
	}

	// Fallback to service account key file
	if cfg.CredentialsFile != "" {
		if _, err := os.Stat(cfg.CredentialsFile); err != nil {
			return nil, fmt.Errorf("credentials file not found at %s: %w", cfg.CredentialsFile, err)
		}
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
		return opts, nil
	}

	// No explicit authentication configured - rely on default credentials
	// This will use:
	// 1. GOOGLE_APPLICATION_CREDENTIALS env var
	// 2. GCE metadata service (if running on GCE)
	// 3. gcloud CLI credentials
	return opts, nil
}

// isWorkloadIdentityAvailable checks if running in GKE with Workload Identity enabled.
func isWorkloadIdentityAvailable() bool {
	// GKE with Workload Identity mounts credentials at this path
	_, err := os.Stat("/var/run/secrets/google/serviceaccount/token")
	return err == nil
}
