package state

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"golang.org/x/sync/errgroup"
)

type CastaiConfig struct {
	RemoteConfigSyncDuration time.Duration `validate:"required"`
}

func NewCastaiController(
	log *logging.Logger,
	cfg CastaiConfig,
	kubeClient *kube.Client,
	castaiClient *castai.Client,
) *CastaiController {
	if cfg.RemoteConfigSyncDuration == 0 {
		cfg.RemoteConfigSyncDuration = 5 * time.Minute
	}
	return &CastaiController{
		id:                             "castai",
		enabled:                        castaiClient != nil,
		log:                            log.WithField("component", "castai_ctrl"),
		kubeClient:                     kubeClient,
		cfg:                            cfg,
		castaiClient:                   castaiClient,
		remoteConfigFetchErrors:        &atomic.Int64{},
		remoteConfigInitialSyncTimeout: 1 * time.Minute,
		remoteConfigRetryWaitDuration:  20 * time.Second,
		removeConfigMaxFailures:        10,
		streamReconnectWaitDuration:    2 * time.Second,
	}
}

type CastaiController struct {
	id           string
	enabled      bool
	log          *logging.Logger
	kubeClient   *kube.Client
	cfg          CastaiConfig
	castaiClient *castai.Client

	remoteConfigFetchErrors        *atomic.Int64
	removeConfigMaxFailures        int64
	streamReconnectWaitDuration    time.Duration
	remoteConfigRetryWaitDuration  time.Duration
	remoteConfigInitialSyncTimeout time.Duration
}

func (c *CastaiController) Enabled() bool {
	return c.enabled
}

func (c *CastaiController) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	ctxCtx, cancel := context.WithTimeout(ctx, c.remoteConfigInitialSyncTimeout)
	defer cancel()
	if err := c.fetchInitialRemoteConfig(ctxCtx); err != nil {
		return fmt.Errorf("fetching initial config: %w", err)
	}

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return c.runRemoteConfigSyncLoop(ctx)
	})

	return errg.Wait()
}

func (c *CastaiController) fetchConfig(ctx context.Context) (*castaipb.Configuration, error) {
	resp, err := c.castaiClient.GRPC.GetConfiguration(ctx, &castaipb.GetConfigurationRequest{})
	if err != nil {
		return nil, err
	}
	if resp.Config == nil {
		resp.Config = &castaipb.Configuration{}
	}
	return resp.Config, nil
}

func (c *CastaiController) fetchInitialRemoteConfig(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cfg, err := c.fetchConfig(ctx)
		if err != nil {
			c.log.Errorf("fetching initial config: %v", err)
			sleep(ctx, c.remoteConfigRetryWaitDuration)
			continue
		}
		c.updateRemoteConfig(cfg)
		c.log.Info("initial config synced")
		return nil
	}
}

func (c *CastaiController) runRemoteConfigSyncLoop(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.RemoteConfigSyncDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			cfg, err := c.fetchConfig(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				c.log.Errorf("fetching config: %v", err)
				fetchErrors := c.remoteConfigFetchErrors.Add(1)
				if fetchErrors >= c.removeConfigMaxFailures {
					return fmt.Errorf("maximum %d remote config fetch errors reached", fetchErrors)
				}
				continue
			}
			c.remoteConfigFetchErrors.Store(0)
			c.updateRemoteConfig(cfg)
		}
	}
}

func (c *CastaiController) updateRemoteConfig(cfg *castaipb.Configuration) {
}
