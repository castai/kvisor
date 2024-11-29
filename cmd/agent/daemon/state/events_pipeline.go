package state

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
)

func (c *Controller) runEventsPipeline(ctx context.Context) error {
	c.log.Info("running events pipeline")
	defer c.log.Info("events pipeline done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.tracer.Events():
			pbEvent := c.toProtoEvent(e)
			if c.enrichmentService.Enqueue(&enrichment.EnrichRequest{
				Event:     pbEvent,
				EbpfEvent: e,
			}) {
				continue
			}
			for _, exporter := range c.exporters.Events {
				exporter.Enqueue(pbEvent)
			}
		case e := <-c.signatureEngine.Events():
			for _, exporter := range c.exporters.Events {
				if podInfo, found := c.getPodInfo(e.PodUid); found {
					e.WorkloadKind = podInfo.WorkloadKind
					e.WorkloadName = podInfo.WorkloadName
					e.WorkloadUid = podInfo.WorkloadUid
				}
				exporter.Enqueue(e)
			}
		case e := <-c.enrichmentService.Events():
			for _, exporter := range c.exporters.Events {
				exporter.Enqueue(e)
			}
		}
	}
}

func (c *Controller) toProtoEvent(e *ebpftypes.Event) *castpb.Event {
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
		ProcessIdentity: &castpb.ProcessIdentity{
			Pid:       e.Context.Pid,
			StartTime: uint64((time.Duration(e.Context.StartTime) * time.Nanosecond).Truncate(time.Second).Nanoseconds()), // nolint:gosec
		},
	}

	if podInfo, found := c.getPodInfo(event.PodUid); found {
		event.WorkloadKind = podInfo.WorkloadKind
		event.WorkloadName = podInfo.WorkloadName
		event.WorkloadUid = podInfo.WorkloadUid
		event.NodeName = podInfo.NodeName
	}

	switch args := e.Args.(type) {
	case ebpftypes.NetPacketDNSBaseArgs:
		metrics.AgentDNSPacketsTotal.Inc()
		event.EventType = castpb.EventType_EVENT_DNS

		dnsEvent := args.Payload
		dnsEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		event.Data = &castpb.Event_Dns{
			Dns: dnsEvent,
		}

		// Add dns cache.
		c.cacheDNS(event, dnsEvent)

	case ebpftypes.SockSetStateArgs:
		tpl := args.Tuple
		event.EventType = findTCPEventType(ebpftypes.TCPSocketState(args.OldState), ebpftypes.TCPSocketState(args.NewState))
		pbTuple := &castpb.Tuple{
			SrcIp:       tpl.Src.Addr().AsSlice(),
			DstIp:       tpl.Dst.Addr().AsSlice(),
			SrcPort:     uint32(tpl.Src.Port()),
			DstPort:     uint32(tpl.Dst.Port()),
			DnsQuestion: c.getAddrDnsQuestion(e.Context.CgroupID, tpl.Dst.Addr()),
		}
		event.Data = &castpb.Event_Tuple{
			Tuple: pbTuple,
		}
	case ebpftypes.SchedProcessExecArgs:
		event.EventType = castpb.EventType_EVENT_EXEC
		event.Data = &castpb.Event_Exec{
			Exec: &castpb.Exec{
				Path:       args.Filepath,
				Args:       args.Argv,
				HashSha256: nil, // Hash is filled inside enrichment.
				Flags:      args.Flags,
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
	case ebpftypes.StdioViaSocketArgs:
		event.EventType = castpb.EventType_EVENT_STDIO_VIA_SOCKET
		finding := castpb.StdioViaSocketFinding{
			Socketfd: args.Sockfd,
		}
		switch addr := args.Addr.(type) {
		case ebpftypes.Ip4SockAddr:
			finding.Ip = addr.Addr.Addr().AsSlice()
			finding.Port = uint32(addr.Addr.Port())
		case ebpftypes.Ip6SockAddr:
			finding.Ip = addr.Addr.Addr().AsSlice()
			finding.Port = uint32(addr.Addr.Port())
		}
		event.Data = &castpb.Event_StdioViaSocket{
			StdioViaSocket: &finding,
		}
	case ebpftypes.TtyWriteArgs:
		event.EventType = castpb.EventType_EVENT_TTY_WRITE
		event.Data = &castpb.Event_File{
			File: &castpb.File{Path: args.Path},
		}
	case ebpftypes.NetPacketSSHBaseArgs:
		event.EventType = castpb.EventType_EVENT_SSH
		sshEvent := args.Payload
		sshEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		event.Data = &castpb.Event_Ssh{
			Ssh: sshEvent,
		}
	}

	if event.EventType == 0 {
		data, _ := json.Marshal(e.Args) //nolint:errchkjson
		event.EventType = castpb.EventType_EVENT_ANY
		event.Data = &castpb.Event_Any{
			Any: &castpb.Any{
				EventId: uint32(e.Context.EventID),
				Syscall: uint32(e.Context.Syscall), // nolint:gosec
				Data:    data,
			},
		}
	}
	return event
}

func (c *Controller) getAddrDnsQuestion(cgroupID uint64, addr netip.Addr) string {
	if cache, found := c.dnsCache.Get(cgroupID); found {
		if dnsQuestion, found := cache.Get(addr.Unmap()); found {
			return dnsQuestion
		}
	}
	return ""
}

func (c *Controller) cacheDNS(e *castpb.Event, dnsEvent *ebpftypes.ProtoDNS) {
	cacheVal, found := c.dnsCache.Get(e.CgroupId)
	if !found {
		var err error
		cacheVal, err = freelru.NewSynced[netip.Addr, string](1024, func(k netip.Addr) uint32 {
			return uint32(xxhash.Sum64(k.AsSlice())) // nolint:gosec
		})
		if err != nil {
			c.log.Errorf("creating dns cache: %v", err)
			return
		}
		c.dnsCache.Add(e.CgroupId, cacheVal)
	}

	for _, answ := range dnsEvent.Answers {
		if len(answ.Ip) == 0 {
			continue
		}
		addr, ok := netip.AddrFromSlice(answ.Ip)
		if !ok {
			continue
		}

		cacheVal.Add(addr, answ.Name)
	}
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
