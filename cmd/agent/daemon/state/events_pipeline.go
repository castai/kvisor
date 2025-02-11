package state

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
)

func (c *Controller) runEventsPipeline(ctx context.Context) error {
	c.log.Info("running events pipeline")
	defer c.log.Info("events pipeline done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.tracer.Events():
			group := c.getOrCreateContainerEventsGroup(ctx, e)
			group.pushEvent(e)
		case e := <-c.signatureEngine.Events():
			group := c.getOrCreateContainerEventsGroup(ctx, e.EbpfEvent)
			group.pushSignatureEvent(e)
		}
	}
}

func (c *Controller) getOrCreateContainerEventsGroup(ctx context.Context, e *ebpftypes.Event) *containerEventsGroup {
	c.eventsGroupsMu.RLock()
	group, found := c.eventsGroups[e.Context.CgroupID]
	c.eventsGroupsMu.RUnlock()
	if !found {
		batch := &castpb.ContainerEventsBatch{
			NodeName:          c.nodeName,
			Namespace:         e.Container.PodNamespace,
			PodName:           e.Container.PodName,
			ContainerName:     e.Container.Name,
			ContainerId:       e.Container.ID,
			PodUid:            e.Container.PodUID,
			ObjectLabels:      e.Container.Labels,
			ObjectAnnotations: e.Container.Annotations,
			CgroupId:          e.Context.CgroupID,
		}
		if podInfo, found := c.getPodInfo(e.Container.PodUID); found {
			batch.WorkloadKind = castpb.WorkloadKind(podInfo.WorkloadKind)
			batch.WorkloadName = podInfo.WorkloadName
			batch.WorkloadUid = podInfo.WorkloadUid
			batch.NodeName = podInfo.NodeName
		}
		// TODO: Consider adjusting these settings dynamically on each group based on their events rate.
		cfg := containerEventsGroupConfig{
			batchSize:           c.eventsBatchSize,
			flushInterval:       c.eventsFlushInterval,
			eventsQueueSize:     100,
			signaturesQueueSize: 100,
			fingerprintSize:     500,
		}
		group = newContainerEventsGroup(
			c.log,
			c.eventsEnrichmentService,
			c.exporters.ContainerEventsSender,
			batch,
			cfg,
			c.nowFunc,
			c.fillProtoContainerEvent,
			c.tracer,
		)
		c.eventsGroupsMu.Lock()
		c.eventsGroups[e.Context.CgroupID] = group
		c.eventsGroupsMu.Unlock()
		go func() {
			if err := group.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				c.log.Errorf("running events group: %v", err)
				return
			}
		}()
	}
	return group
}

func (c *Controller) getAddrDnsQuestion(addr netip.Addr) string {
	if dnsQuestion, found := c.dnsCache.Get(addr.Unmap()); found {
		return dnsQuestion
	}
	return ""
}

func (c *Controller) cacheDNS(dnsEvent *ebpftypes.ProtoDNS) {
	for _, answ := range dnsEvent.Answers {
		if len(answ.Ip) == 0 {
			continue
		}
		addr, ok := netip.AddrFromSlice(answ.Ip)
		if !ok {
			continue
		}
		c.dnsCache.Add(addr.Unmap(), answ.Name)
	}
}

func (c *Controller) fillProtoContainerEvent(res *castpb.ContainerEvent, e *ebpftypes.Event, signatureEvent *castpb.SignatureEvent) {
	res.Timestamp = e.Context.Ts
	res.ProcessName = decoder.ProcessNameString(e.Context.Comm[:])
	res.HostPid = e.Context.HostPid
	res.Pid = e.Context.Pid
	res.ProcessStartTime = uint64(time.Duration(e.Context.StartTime).Truncate(time.Second).Nanoseconds()) // nolint:gosec,
	res.Data = nil
	res.EventType = 0
	parentStartTime := time.Duration(0)
	if e.Context.Ppid != 0 {
		// We only set the parent start time, if we know the parent PID comes from the same NS.
		parentStartTime = time.Duration(e.Context.ParentStartTime) // nolint:gosec
	}
	res.Ppid = e.Context.Ppid
	res.ProcessParentStartTime = uint64(parentStartTime) // nolint:gosec

	if signatureEvent != nil {
		res.EventType = castpb.EventType_EVENT_SIGNATURE
		res.Data = &castpb.ContainerEvent_Signature{
			Signature: signatureEvent,
		}
		return
	}

	switch args := e.Args.(type) {
	case ebpftypes.NetPacketDNSBaseArgs:
		metrics.AgentDNSPacketsTotal.Inc()
		res.EventType = castpb.EventType_EVENT_DNS

		dnsEvent := args.Payload
		dnsEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		res.Data = &castpb.ContainerEvent_Dns{
			Dns: dnsEvent,
		}

		// Add dns cache.
		c.cacheDNS(dnsEvent)

	case ebpftypes.SockSetStateArgs:
		tpl := args.Tuple
		res.EventType = findTCPEventType(ebpftypes.TCPSocketState(args.OldState), ebpftypes.TCPSocketState(args.NewState))
		pbTuple := &castpb.Tuple{
			SrcIp:       tpl.Src.Addr().AsSlice(),
			DstIp:       tpl.Dst.Addr().AsSlice(),
			SrcPort:     uint32(tpl.Src.Port()),
			DstPort:     uint32(tpl.Dst.Port()),
			DnsQuestion: c.getAddrDnsQuestion(tpl.Dst.Addr()),
		}
		res.Data = &castpb.ContainerEvent_Tuple{
			Tuple: pbTuple,
		}
	case ebpftypes.SchedProcessExecArgs:
		res.EventType = castpb.EventType_EVENT_EXEC
		res.Data = &castpb.ContainerEvent_Exec{
			Exec: &castpb.Exec{
				Path:       args.Filepath,
				Args:       args.Argv,
				HashSha256: nil, // Hash is filled inside enrichment.
				Flags:      args.Flags,
			},
		}
	case ebpftypes.SchedProcessForkArgs:
		res.EventType = castpb.EventType_EVENT_PROCESS_FORK
		res.Data = &castpb.ContainerEvent_ProcessFork{
			ProcessFork: &castpb.ProcessFork{},
		}
	case ebpftypes.SchedProcessExitArgs:
		res.EventType = castpb.EventType_EVENT_PROCESS_EXIT
		res.Data = &castpb.ContainerEvent_ProcessExit{
			ProcessExit: &castpb.ProcessExit{
				ExitCode: args.ExitCode,
			},
		}
	case ebpftypes.FileModificationArgs:
		res.EventType = castpb.EventType_EVENT_FILE_CHANGE
		res.Data = &castpb.ContainerEvent_File{
			File: &castpb.File{
				Path: args.FilePath,
			},
		}
	case ebpftypes.ProcessOomKilledArgs:
		res.EventType = castpb.EventType_EVENT_PROCESS_EXIT
		res.Data = &castpb.ContainerEvent_ProcessExit{
			ProcessExit: &castpb.ProcessExit{
				ExitCode: args.ExitCode,
			},
		}

	case ebpftypes.TestEventArgs:
		// nothing to do here, as this event is solely used by testing

	case ebpftypes.MagicWriteArgs:
		res.EventType = castpb.EventType_EVENT_MAGIC_WRITE
		res.Data = &castpb.ContainerEvent_File{
			File: &castpb.File{
				Path: args.Pathname,
			},
		}
	case ebpftypes.StdioViaSocketArgs:
		res.EventType = castpb.EventType_EVENT_STDIO_VIA_SOCKET
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
		res.Data = &castpb.ContainerEvent_StdioViaSocket{
			StdioViaSocket: &finding,
		}
	case ebpftypes.TtyWriteArgs:
		res.EventType = castpb.EventType_EVENT_TTY_WRITE
		res.Data = &castpb.ContainerEvent_File{
			File: &castpb.File{Path: args.Path},
		}
	case ebpftypes.NetPacketSSHBaseArgs:
		res.EventType = castpb.EventType_EVENT_SSH
		sshEvent := args.Payload
		sshEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		res.Data = &castpb.ContainerEvent_Ssh{
			Ssh: sshEvent,
		}
	}

	if res.EventType == 0 {
		data, _ := json.Marshal(e.Args) //nolint:errchkjson
		res.EventType = castpb.EventType_EVENT_ANY
		res.Data = &castpb.ContainerEvent_Any{
			Any: &castpb.Any{
				EventId: uint32(e.Context.EventID),
				Syscall: uint32(e.Context.Syscall), // nolint:gosec
				Data:    data,
			},
		}
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
