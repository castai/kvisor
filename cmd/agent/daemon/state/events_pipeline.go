package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/pkg/castai"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
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

func (c *Controller) handleEbpfEvent(e *ebpftypes.Event) {
	pbEvent := toProtoEvent(e)
	if c.enrichmentService.Enqueue(&enrichment.EnrichRequest{
		Event:     pbEvent,
		EbpfEvent: e,
	}) {
		return
	}

	if c.debugEvent {
		printEvent(pbEvent)
	}
	c.eventsExportQueue <- pbEvent
}

// TODO(anjmao): Handle netwflows events. We may need to add separate endpoint and batch/group multiple flows samples.
// Also we need custom exporters for netflow events.
func toProtoEvent(e *ebpftypes.Event) *castpb.Event {
	event := &castpb.Event{
		EventType:     0,
		Timestamp:     e.Context.Ts,
		ProcessName:   string(bytes.TrimRight(e.Context.Comm[:], "\x00")),
		Namespace:     e.Container.PodNamespace,
		PodUid:        e.Container.PodUID,
		PodName:       e.Container.PodName,
		ContainerName: e.Container.Name,
		ContainerId:   e.Container.ID,
		CgroupId:      e.Container.CgroupID,
		HostPid:       e.Context.HostPid,
	}

	switch args := e.Args.(type) {
	case ebpftypes.NetPacketDNSBaseArgs:
		metrics.AgentDNSPacketsTotal.Inc()
		event.EventType = castpb.EventType_EVENT_DNS

		dnsEvent := args.Payload
		dnsEvent.FlowDirection = convertFlowDirection(e.Context.ParseFlowDirection())
		event.Data = &castpb.Event_Dns{
			Dns: dnsEvent,
		}
	case ebpftypes.SockSetStateArgs:
		tpl := args.Tuple
		event.EventType = findTCPEventType(ebpftypes.TCPSocketState(args.OldState), ebpftypes.TCPSocketState(args.NewState))
		event.Data = &castpb.Event_Tuple{
			Tuple: &castpb.Tuple{
				SrcIp:   tpl.Src.Addr().String(),
				DstIp:   tpl.Dst.Addr().String(),
				SrcPort: uint32(tpl.Src.Port()),
				DstPort: uint32(tpl.Dst.Port()),
			},
		}
	case ebpftypes.SchedProcessExecArgs:
		event.EventType = castpb.EventType_EVENT_EXEC
		event.Data = &castpb.Event_Exec{
			Exec: &castpb.Exec{
				Path: args.Pathname,
				Args: args.Argv,
			},
		}
	case ebpftypes.FileModificationArgs:
		event.EventType = castpb.EventType_EVENT_FILE_CHANGE
		event.Data = &castpb.Event_File{
			File: &castpb.File{
				Path: args.FilePath,
			},
		}
	case ebpftypes.ProcessOomKilledArgs:
		event.EventType = castpb.EventType_EVENT_PROCESS_OOM
		// Nothing to add, sinces we do not have a payload

	case ebpftypes.TestEventArgs:
		// nothing to do here, as this event is solely used by testing

	case ebpftypes.MagicWriteArgs:
		event.EventType = castpb.EventType_EVENT_MAGIC_WRITE
		event.Data = &castpb.Event_File{
			File: &castpb.File{
				Path: args.Pathname,
			},
		}
	default:
		data, _ := json.Marshal(args) //nolint:errchkjson
		event.EventType = castpb.EventType_EVENT_ANY
		event.Data = &castpb.Event_Any{
			Any: &castpb.Any{
				EventId: uint32(e.Context.EventID),
				Syscall: uint32(e.Context.Syscall),
				Data:    data,
			},
		}
	}
	return event
}

func convertFlowDirection(flowDir ebpftypes.FlowDirection) castpb.FlowDirection {
	switch flowDir {
	case ebpftypes.FlowDirectionIngress:
		return castpb.FlowDirection_FLOW_INGRESS
	case ebpftypes.FlowDirectionEgress:
		return castpb.FlowDirection_FLOW_EGRESS
	default:
		return castpb.FlowDirection_FLOW_UNKNOWN
	}
}

func findTCPEventType(oldState, newState ebpftypes.TCPSocketState) castpb.EventType {
	if oldState == ebpftypes.TCP_STATE_CLOSE && newState == ebpftypes.TCP_STATE_LISTEN {
		return castpb.EventType_EVENT_TCP_LISTEN
	}

	if oldState == ebpftypes.TCP_STATE_SYN_SENT {
		if newState == ebpftypes.TCP_STATE_ESTABLISHED {
			return castpb.EventType_EVENT_TCP_CONNECT
		}
		if newState == ebpftypes.TCP_STATE_CLOSE {
			return castpb.EventType_EVENT_TCP_CONNECT_ERROR
		}
	}

	return castpb.EventType_UNKNOWN
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
