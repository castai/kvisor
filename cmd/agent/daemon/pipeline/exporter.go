package pipeline

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

	ContainerEvents []ContainerEventsSender
	Stats           []StatsExporter
	Netflow         []NetflowExporter
	ProcessTree     []ProcessTreeExporter
}

func (e *Exporters) Empty() bool {
	return len(e.ContainerEvents) == 0 && len(e.Stats) == 0 && len(e.Netflow) == 0 && len(e.ProcessTree) == 0
}

func (e *Exporters) Run(ctx context.Context) error {
	e.log.Infof("running")
	defer e.log.Infof("stopping")

	errg, ctx := errgroup.WithContext(ctx)
	for _, exp := range e.Stats {
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

type ContainerEventsExporter interface {
	DataExporter
	Enqueue(e *castpb.ContainerEventsBatch)
}

type StatsExporter interface {
	DataExporter
	Enqueue(e *castpb.StatsBatch)
}

type NetflowExporter interface {
	DataExporter
	Enqueue(e *castpb.Netflow)
}

type ProcessTreeExporter interface {
	DataExporter
	Enqueue(e processtree.ProcessTreeEvent)
}
