package test

import (
	"context"
	"os"
	"testing"

	"github.com/joho/godotenv"

	"github.com/castai/kvisor/pkg/cloudprovider/aws"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// Use .env file or run tests with environment variables:
// AWS_PROFILE=default AWS_INSTANCE_ID=i-1234567890abcdef0 go test -v ./pkg/cloudprovider/aws/test/...
func init() {
	_ = godotenv.Load(".env")
}

func getTestConfig(t *testing.T) types.ProviderConfig {
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		t.Skip("AWS_PROFILE not set (use .env file or environment variable)")
	}

	t.Logf("Using AWS profile: %s", profile)

	cfg := types.ProviderConfig{
		Type: types.TypeAWS,
	}

	if credsFile := os.Getenv("AWS_CREDENTIALS_FILE"); credsFile != "" {
		cfg.CredentialsFile = credsFile
		t.Logf("Using credentials file: %s", credsFile)
	} else if sharedCreds := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); sharedCreds != "" {
		cfg.CredentialsFile = sharedCreds
		t.Logf("Using credentials file: %s", sharedCreds)
	} else {
		t.Log("Using default AWS credentials chain (IAM role, environment variables, or ~/.aws/credentials)")
	}

	if region := os.Getenv("AWS_REGION"); region != "" {
		cfg.AWSRegion = region
	}

	return cfg
}

// TestRefreshStorageState calls RefreshStorageState and prints the results.
func TestRefreshStorageState(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := context.Background()

	provider, err := aws.NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	p := provider.(*aws.Provider)

	// Test storage state refresh with instance ID
	instanceID := os.Getenv("AWS_INSTANCE_ID")
	if instanceID == "" {
		t.Fatal("AWS_INSTANCE_ID not set")
	}

	// Refresh storage state first
	err = p.RefreshStorageState(ctx, instanceID)
	if err != nil {
		t.Fatalf("RefreshStorageState failed: %v", err)
	}

	// Get the cached storage state
	state, err := p.GetStorageState(ctx)
	if err != nil {
		t.Fatalf("GetStorageState failed: %v", err)
	}

	volumes, ok := state.InstanceVolumes[instanceID]
	if !ok {
		t.Fatalf("No volumes found for instance %s", instanceID)
	}

	t.Logf("Found %d volumes attached to instance %s:", len(volumes), instanceID)
	for _, vol := range volumes {
		t.Logf("  Volume:")
		t.Logf("    VolumeID: %s", vol.VolumeID)
		t.Logf("    VolumeType: %s", vol.VolumeType)
		t.Logf("    VolumeState: %s", vol.VolumeState)
		t.Logf("    SizeBytes: %d (%.2f GB)", vol.SizeBytes, float64(vol.SizeBytes)/(1024*1024*1024))
		t.Logf("    AvailabilityZone: %s", vol.AvailabilityZone)
		t.Logf("    Encrypted: %v", vol.Encrypted)
		if vol.IOPS != nil {
			t.Logf("    IOPS: %d", *vol.IOPS)
		}
		if vol.ThroughputBytes != nil {
			t.Logf("    ThroughputBytes: %d (%.2f MB/s)", *vol.ThroughputBytes, float64(*vol.ThroughputBytes)/(1024*1024))
		}
	}
}
