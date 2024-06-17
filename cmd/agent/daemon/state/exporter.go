package state

import (
	"context"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	"golang.org/x/sync/errgroup"
)

func NewExporters(log *logging.Logger) *Exporters {
	return &Exporters{
		log: log.WithField("component", "exporters"),
	}
}

type Exporters struct {
	log *logging.Logger

	Events         []EventsExporter
	ContainerStats []ContainerStatsExporter
	Netflow        []NetflowExporter
	ProcessTree    []ProcessTreeExporter
}

func (e *Exporters) Empty() bool {
	return len(e.Events) == 0 && len(e.ContainerStats) == 0 && len(e.Netflow) == 0 && len(e.ProcessTree) == 0
}

func (e *Exporters) Run(ctx context.Context) error {
	e.log.Infof("running")
	defer e.log.Infof("stopping")

	errg, ctx := errgroup.WithContext(ctx)
	for _, exp := range e.Events {
		exp := exp
		errg.Go(func() error {
			return exp.Run(ctx)
		})
	}
	for _, exp := range e.ContainerStats {
		exp := exp
		errg.Go(func() error {
			return exp.Run(ctx)
		})
	}
	for _, exp := range e.Netflow {
		exp := exp
		errg.Go(func() error {
			return exp.Run(ctx)
		})
	}
	for _, exp := range e.ProcessTree {
		exp := exp
		errg.Go(func() error {
			return exp.Run(ctx)
		})
	}
	return errg.Wait()
}

type DataExporter interface {
	Run(ctx context.Context) error
}

type EventsExporter interface {
	DataExporter
	Enqueue(e *castpb.Event)
}

type ContainerStatsExporter interface {
	DataExporter
	Enqueue(e *castpb.ContainerStatsBatch)
}

type NetflowExporter interface {
	DataExporter
	Enqueue(e *castpb.Netflow)
}

type ProcessTreeExporter interface {
	DataExporter
	Enqueue(e processtree.ProcessTreeEvent)
}
