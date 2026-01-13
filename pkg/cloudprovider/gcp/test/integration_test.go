package test

import (
	"context"
	"os"
	"testing"

	"github.com/joho/godotenv"

	"github.com/castai/kvisor/pkg/cloudprovider/gcp"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// Use .env file or run tests with environment variables:
func init() {
	_ = godotenv.Load(".env")
}

func getTestConfig(t *testing.T) types.Config {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		t.Skip("GCP_PROJECT_ID not set (use .env file or environment variable)")
	}

	networkName := os.Getenv("NETWORK_NAME")
	if networkName == "" {
		t.Skip("NETWORK_NAME not set (use .env file or environment variable)")
	}

	cfg := types.Config{
		Type:         types.TypeGCP,
		GCPProjectID: projectID,
		NetworkName:  networkName,
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

// TestRefreshMetadata calls RefreshMetadata and prints the results.
func TestRefreshMetadata(t *testing.T) {
	cfg := getTestConfig(t)
	ctx := context.Background()

	provider, err := gcp.NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Close()

	p := provider.(*gcp.Provider)

	err = p.RefreshMetadata(ctx)
	if err != nil {
		t.Fatalf("RefreshMetadata failed: %v", err)
	}

	metadata, err := p.GetMetadata(ctx)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	t.Logf("Metadata:")
	t.Logf("  Provider: %s", metadata.Provider)
	for _, vpc := range metadata.VPCs {
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
	// t.Logf("  Service Ranges: %+v", metadata.ServiceRanges)
}
