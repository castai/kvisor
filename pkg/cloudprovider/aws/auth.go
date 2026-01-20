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
func buildAWSConfig(ctx context.Context, cfg types.ProviderConfig) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if cfg.CredentialsFile != "" {
		if _, err := os.Stat(cfg.CredentialsFile); err != nil {
			return aws.Config{}, fmt.Errorf("credentials file not found at %s: %w", cfg.CredentialsFile, err)
		}
		opts = append(opts, config.WithSharedCredentialsFiles([]string{cfg.CredentialsFile}))
	}

	if cfg.AWSRegion != "" {
		opts = append(opts, config.WithRegion(cfg.AWSRegion))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading AWS config: %w", err)
	}

	return awsCfg, nil
}
