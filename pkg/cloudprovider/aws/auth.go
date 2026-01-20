package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// buildAWSConfig constructs AWS configuration with authentication.
// Priority: IAM Role (IRSA/Instance Profile) > Credentials File > Environment Variables > Shared Config
func buildAWSConfig(ctx context.Context, cfg types.ProviderConfig) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	// If credentials file is specified, use it
	if cfg.CredentialsFile != "" {
		if _, err := os.Stat(cfg.CredentialsFile); err != nil {
			return aws.Config{}, fmt.Errorf("credentials file not found at %s: %w", cfg.CredentialsFile, err)
		}
		opts = append(opts, config.WithSharedCredentialsFiles([]string{cfg.CredentialsFile}))
	}

	if cfg.AWSRegion != "" {
		opts = append(opts, config.WithRegion(cfg.AWSRegion))
	}

	// Load AWS config with default credential chain
	// This automatically handles:
	// 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
	// 2. Web Identity Token (EKS IRSA)
	// 3. EC2 Instance State (IAM roles)
	// 4. Shared credentials file (~/.aws/credentials)
	// 5. Shared config file (~/.aws/config)
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading AWS config: %w", err)
	}

	return awsCfg, nil
}
