package state

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/types"
)

// runEventsExportLoop sends events to server.
func (c *Controller) runEventsExportLoop(ctx context.Context) error {
	c.log.Info("running events sink loop")
	defer c.log.Info("events sink loop done")

	var writeStream castpb.RuntimeSecurityAgentAPI_EventsWriteStreamClient
	var err error

	defer func() {
		if writeStream != nil {
			_ = writeStream.CloseSend()
		}
	}()

	for {
		// Create stream.
		if writeStream == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				writeStream, err = c.castClient.GRPC.EventsWriteStream(ctx)
				if err != nil {
					if !isGRPCError(err, codes.Unavailable, codes.Canceled) {
						c.log.Warnf("create write stream: %v", err)
					}
					time.Sleep(c.writeStreamCreateRetryDelay)
					continue
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.eventsExportQueue:
			c.enrichEvent(e)
			if err := writeStream.Send(e); err != nil {
				if errors.Is(err, io.EOF) {
					writeStream = nil
				}
				c.log.Errorf("sending event: %v", err)
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

	e.WorkloadName = workload
}

func (c *Controller) handleEvent(e *castpb.Event) {
	if c.debugEvent {
		printEvent(e)
	}

	if e.EventType == castpb.EventType_EVENT_EXEC {
		c.analyzersService.Enqueue(e)
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
