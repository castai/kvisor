//go:build cloudintegration

package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"

	"github.com/castai/kvisor/pkg/cloudprovider/gcp"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// Use .env file or run tests with environment variables:
func init() {
	_ = godotenv.Load(".env")
}

func getTestConfig(t *testing.T) types.ProviderConfig {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		t.Fatal("GCP_PROJECT_ID not set (use .env file or environment variable)")
	}

	cfg := types.ProviderConfig{
		Type:         types.TypeGCP,
		GCPProjectID: projectID,
	}

	if credsFile := os.Getenv("GCP_CREDENTIALS_FILE"); credsFile != "" {
		cfg.CredentialsFile = credsFile
		t.Logf("Using credentials file: %s", credsFile)
	} else if gadc := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gadc != "" {
		cfg.CredentialsFile = gadc
		t.Logf("Using credentials file: %s", gadc)
	} else {
		t.Log("Using default credentials")
	}

	return cfg
}

// TestRefreshNetworkState calls RefreshNetworkState and prints the results.
func TestRefreshNetworkState(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := context.Background()

	provider, err := gcp.NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	p := provider.(*gcp.Provider)

	networkName := os.Getenv("NETWORK_NAME")
	if networkName == "" {
		t.Fatal("NETWORK_NAME not set (use .env file or environment variable)")
	}

	err = p.RefreshNetworkState(ctx, networkName)
	if err != nil {
		t.Fatalf("RefreshState failed: %v", err)
	}

	state, err := p.GetNetworkState(ctx)
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}

	t.Logf("State:")
	t.Logf("  Provider: %s", state.Provider)
	for _, vpc := range state.VPCs {
		t.Logf("  VPC: %s", vpc.Name)
		for _, subnet := range vpc.Subnets {
			t.Logf("    Subnet: %s; Region: %s; CIDR: %s", subnet.Name, subnet.Region, subnet.CIDR)
		}
		for _, peer := range vpc.PeeredVPCs {
			for _, r := range peer.Ranges {
				t.Logf("    Peered VPC: %s; Region: %s; CIDR: %s", peer.Name, r.Region, r.CIDR)
			}
		}
	}
	// t.Logf("  Service Ranges: %+v", state.ServiceRanges)
}

// TestGetStorageState calls GetStorageState and prints the results.
func TestGetStorageState(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := t.Context()

	provider, err := gcp.NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	p := provider.(*gcp.Provider)

	instanceIDsStr := os.Getenv("GCP_INSTANCE_IDS")
	if instanceIDsStr == "" {
		t.Fatal("GCP_INSTANCE_IDS not set")
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
		}
	}
}
