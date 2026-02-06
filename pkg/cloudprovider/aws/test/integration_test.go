//go:build cloudintegration

package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"

	"github.com/castai/kvisor/pkg/cloudprovider/aws"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

// Use .env file or run tests with environment variables:
// AWS_PROFILE=default AWS_INSTANCE_IDS=i-1234567890abcdef0,i-0987654321fedcba0 go test -v ./pkg/cloudprovider/aws/test/...
func init() {
	_ = godotenv.Load(".env")
}

func getTestConfig(t *testing.T) types.ProviderConfig {
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		t.Fatal("AWS_PROFILE not set (use .env file or environment variable)")
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

	provider, err := aws.NewProvider(ctx, logging.New(), cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	p := provider.(*aws.Provider)

	instanceIDsStr := os.Getenv("AWS_INSTANCE_IDS")
	if instanceIDsStr == "" {
		t.Fatal("AWS_INSTANCE_IDS not set")
	}

	instanceIDs := strings.Split(instanceIDsStr, ",")
	for i := range instanceIDs {
		instanceIDs[i] = strings.TrimSpace(instanceIDs[i])
	}

	state, err := p.GetStorageState(ctx, instanceIDs...)
	if err != nil {
		t.Fatalf("GetStorageState failed: %v", err)
	}

	for instanceID, volumes := range state.InstanceVolumes {
		t.Logf("Found %d volumes attached to instance %s:", len(volumes), instanceID)
		for _, v := range volumes {
			t.Logf("  Volume:")
			t.Logf("    VolumeID: %s", v.VolumeID)
			t.Logf("    VolumeType: %s", v.VolumeType)
			t.Logf("    VolumeState: %s", v.VolumeState)
			t.Logf("    SizeBytes: %d", v.SizeBytes)
			t.Logf("    Zone: %s", v.Zone)
			t.Logf("    Encrypted: %v", v.Encrypted)
			t.Logf("    IOPS: %d", v.IOPS)
			t.Logf("    ThroughputBytes: %d B/s", v.ThroughputBytes)
			if v.AwsDetails != nil {
				t.Log("    AWSDetails:")
				t.Log("      Device: ", v.AwsDetails.Device)
			}
		}
	}
}

func TestRefreshNetworkState(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := context.Background()

	provider, err := aws.NewProvider(ctx, logging.New(), cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Close()

	p := provider.(*aws.Provider)

	err = p.RefreshNetworkState(ctx, "default")
	if err != nil {
		t.Fatalf("RefreshMetadata failed: %v", err)
	}

	metadata, err := p.GetNetworkState(ctx)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	t.Logf("Metadata:")
	t.Logf("  Provider: %s", metadata.Provider)
	t.Logf("  Domain: %s", metadata.Domain)
	for _, vpc := range metadata.VPCs {
		t.Logf("  VPC: %s (ID: %s)", vpc.Name, vpc.ID)
		t.Logf("    VPC CIDRs: %v", vpc.CIDRs)
		for _, subnet := range vpc.Subnets {
			t.Logf("    Subnet: %s; Zone: %s; Region: %s; CIDR: %s", subnet.Name, subnet.Zone, subnet.Region, subnet.CIDR)
		}
		for _, peer := range vpc.PeeredVPCs {
			for _, r := range peer.Ranges {
				t.Logf("    Peered VPC: %s; Region: %s; CIDR: %s", peer.Name, r.Region, r.CIDR)
			}
		}
	}
	t.Logf("  Service Ranges: %d regions", len(metadata.ServiceRanges))
}
