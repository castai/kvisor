package state

import (
	"context"
	"fmt"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/types"
)

// runEventsExportLoop sends events to server.
func (c *Controller) runEventsExportLoop(ctx context.Context) error {
	c.log.Info("running events sink loop")
	defer c.log.Info("events sink loop done")

	ws := castai.NewWriteStream[*castpb.Event, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.castClient.GRPC.EventsWriteStream(ctx)
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.eventsExportQueue:
			c.enrichEvent(e)
			if err := ws.Send(e); err != nil {
				continue
			}
			metrics.AgentExportedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: e.GetEventType().String()}).Inc()
		}
	}
}

func (c *Controller) enrichEvent(e *castpb.Event) {
	workload, err := c.kubeClient.GetWorkloadFor(types.UID(e.PodUid))
	if err != nil {
		return
	}

	e.WorkloadName = workload.Name
	e.WorkloadUid = string(workload.UID)
}

func (c *Controller) handleEvent(e *castpb.Event) {
	if c.debugEvent {
		printEvent(e)
	}
	c.eventsExportQueue <- e
}

func printEvent(e *castpb.Event) {
	fmt.Printf("%s pid=%d, proc=%s, cgroup=%d, cont=%s ", e.GetEventType(), e.GetHostPid(), e.GetProcessName(), e.GetCgroupId(), e.GetContainerId())
	switch e.GetEventType() {
	case castpb.EventType_EVENT_TCP_LISTEN, castpb.EventType_EVENT_TCP_CONNECT, castpb.EventType_EVENT_TCP_CONNECT_ERROR:
		tuple := e.GetTuple()
		fmt.Print(tuple.GetDstIp())
	case castpb.EventType_EVENT_FILE_CHANGE:
		fmt.Print(e.GetFile().GetPath())
	case castpb.EventType_EVENT_DNS:
		fmt.Print(e.GetDns())
	case castpb.EventType_EVENT_EXEC:
		fmt.Print(e.GetExec())
	}
	fmt.Print("\n")
}
