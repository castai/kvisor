package state

import (
	"context"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"golang.org/x/sync/errgroup"
)

func NewIngestorController(log *logging.Logger, kubeWatcher *kube.Client, ipInventory *kube.IPInventory, castaiCtrl *CastaiController) *IngestorController {
	ctrl := &IngestorController{
		log:         log.WithField("component", "ctrl"),
		kubeWatcher: kubeWatcher,
		ipInventory: ipInventory,
		castaiCtrl:  castaiCtrl,
	}
	return ctrl
}

type IngestorController struct {
	log         *logging.Logger
	kubeWatcher *kube.Client
	ipInventory *kube.IPInventory
	castaiCtrl  *CastaiController
}

func (c *IngestorController) Run(ctx context.Context, kubeEvents <-chan kube.Issue) error {
	c.log.Infof("running")
	defer c.log.Infof("stopping")

	var errg errgroup.Group

	errg.Go(func() error {
		for {
			select {
			case e := <-kubeEvents:
				c.handleKubeEvent(e)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})

	return errg.Wait()
}

func (c *IngestorController) handleKubeEvent(e kube.Issue) {
	// TODO: Set to castai.
}
