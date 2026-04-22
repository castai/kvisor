package controllers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/logging"
	"golang.org/x/sync/errgroup"
)

type CastaiConfig struct {
	RemoteConfigSyncDuration time.Duration `validate:"required" json:"remoteConfigSyncDuration"`
}

func NewCastaiController(log *logging.Logger, cfg CastaiConfig, appJSONConfig []byte, kubeClient *kube.Client, castaiClient *castai.Client) *CastaiController {
	if cfg.RemoteConfigSyncDuration == 0 {
		cfg.RemoteConfigSyncDuration = 5 * time.Minute
	}
	return &CastaiController{
		id:                                "castai",
		enabled:                           castaiClient != nil,
		log:                               log.WithField("component", "castai_ctrl"),
		kubeClient:                        kubeClient,
		cfg:                               cfg,
		appJSONConfig:                     appJSONConfig,
		castaiClient:                      castaiClient,
		remoteConfigFetchErrors:     &atomic.Int64{},
		removeConfigMaxFailures:     10,
		streamReconnectWaitDuration: 2 * time.Second,
		remoteConfigBackoff: backoffConfig{
			InitInterval:   5 * time.Second,
			MaxInterval:    60 * time.Second,
			MaxElapsedTime: 5 * time.Minute,
		},
	}
}

type CastaiController struct {
	id            string
	enabled       bool
	log           *logging.Logger
	kubeClient    *kube.Client
	cfg           CastaiConfig
	castaiClient  *castai.Client
	appJSONConfig []byte

	remoteConfigFetchErrors     *atomic.Int64
	removeConfigMaxFailures     int64
	streamReconnectWaitDuration time.Duration
	remoteConfigBackoff         backoffConfig
}

type backoffConfig struct {
	InitInterval   time.Duration
	MaxInterval    time.Duration
	MaxElapsedTime time.Duration
}

func (c *CastaiController) Enabled() bool {
	return c.enabled
}

func (c *CastaiController) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	if err := c.fetchInitialRemoteConfig(ctx); err != nil {
		return fmt.Errorf("fetching initial config: %w", err)
	}

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return c.runRemoteConfigSyncLoop(ctx)
	})

	return errg.Wait()
}

func (c *CastaiController) fetchConfig(ctx context.Context, req *castaipb.GetConfigurationRequest) (*castaipb.Configuration, error) {
	resp, err := c.castaiClient.GRPC.GetConfiguration(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Config == nil {
		resp.Config = &castaipb.Configuration{}
	}
	return resp.Config, nil
}

func (c *CastaiController) fetchInitialRemoteConfig(ctx context.Context) error {
	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = c.remoteConfigBackoff.InitInterval
	eb.MaxInterval = c.remoteConfigBackoff.MaxInterval

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		cfg, err := c.fetchConfig(ctx, &castaipb.GetConfigurationRequest{
			CurrentConfig: &castaipb.GetConfigurationRequest_Controller{
				Controller: c.appJSONConfig,
			},
		})
		if err != nil {
			c.log.Errorf("fetching initial config: %v", err)
			return struct{}{}, err
		}
		c.updateRemoteConfig(cfg)
		c.log.Info("initial config synced")
		return struct{}{}, nil
	}, backoff.WithBackOff(eb), backoff.WithMaxElapsedTime(c.remoteConfigBackoff.MaxElapsedTime))
	return err
}

func (c *CastaiController) runRemoteConfigSyncLoop(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.RemoteConfigSyncDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			cfg, err := c.fetchConfig(ctx, &castaipb.GetConfigurationRequest{})
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
