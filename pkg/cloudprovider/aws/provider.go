package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

type Provider struct {
	log *logging.Logger
	cfg types.ProviderConfig

	// AWS clients
	ec2Client *ec2.Client

	// Cached network state
	networkStateMu sync.RWMutex
	networkState   *types.NetworkState
}

// NewProvider creates a new AWS provider instance.
func NewProvider(ctx context.Context, cfg types.ProviderConfig) (types.Provider, error) {
	log := logging.New(&logging.Config{}).WithField("cloudprovider", "aws")

	awsConfig, err := buildAWSConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("building aws config: %w", err)
	}

	ec2Client := ec2.NewFromConfig(awsConfig)

	p := &Provider{
		log:       log,
		cfg:       cfg,
		ec2Client: ec2Client,
	}

	return p, nil
}

func (p *Provider) Type() types.Type {
	return types.TypeAWS
}

func (p *Provider) Close() error {
	// AWS SDK v2 clients don't need explicit cleanup
	p.log.Info("AWS provider closed")
	return nil
}
