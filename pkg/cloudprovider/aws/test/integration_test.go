package test

import (
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

// TestGetStorageState calls GetStorageState and prints the results.
func TestGetStorageState(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := t.Context()

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

	// Get the cached storage state
	state, err := p.GetStorageState(ctx, instanceID)
	if err != nil {
		t.Fatalf("GetStorageState failed: %v", err)
	}

	volumes, ok := state.InstanceVolumes[instanceID]
	if !ok {
		t.Fatalf("No volumes found for instance %s", instanceID)
	}

	t.Logf("Found %d volumes attached to instance %s:", len(volumes), instanceID)
	for _, v := range volumes {
		t.Logf("  Volume:")
		t.Logf("    VolumeID: %s", v.VolumeID)
		t.Logf("    VolumeType: %s", v.VolumeType)
		t.Logf("    VolumeState: %s", v.VolumeState)
		t.Logf("    SizeBytes: %d", v.SizeBytes)
		t.Logf("    AvailabilityZone: %s", v.Zone)
		t.Logf("    Encrypted: %v", v.Encrypted)
		t.Logf("    IOPS: %d", v.IOPS)
		t.Logf("    ThroughputBytes: %d B/s", v.ThroughputBytes)
	}
}
