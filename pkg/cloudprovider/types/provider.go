package types

import (
	"context"
)

// ProviderConfig contains cloud provider configuration.
type ProviderConfig struct {
	Type Type

	// Authentication
	CredentialsFile string // Path to service account key (fallback)

	// GCP specific
	GCPProjectID string

	// AWS specific
	AWSRegion string

	// Azure specific (for future)
	AzureSubscriptionID string
}

// Provider defines cloud-agnostic operations for fetching cloud environment state.
type Provider interface {
	// Type returns the cloud provider type.
	Type() Type

	// GetNetworkState returns the cached network state for the cluster's cloud environment.
	GetNetworkState(ctx context.Context) (*NetworkState, error)

	// RefreshNetworkState updates cached network state.
	RefreshNetworkState(ctx context.Context, network string) error

	// GetStorageState returns the cached storage state for the cluster's cloud environment.
	GetStorageState(ctx context.Context) (*StorageState, error)

	// RefreshStorageState updates cached storage state.
	RefreshStorageState(ctx context.Context, instanceIds ...string) error

	// Close cleans up resources.
	Close() error
}
