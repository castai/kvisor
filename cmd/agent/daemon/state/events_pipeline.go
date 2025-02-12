package state

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
	"golang.org/x/sync/errgroup"
)

func (c *Controller) runEventsPipeline(ctx context.Context) error {
	c.log.Info("running events pipeline")
	defer c.log.Info("events pipeline done")

	numWorkers := 8
	flushQueueSize := 200

	var errg errgroup.Group
	// Flush queue is used to periodically flush aggregated groups events.
	// This is needed to ensure that events are sent for low rate groups.
	flushQueue := make(chan uint64, flushQueueSize)
	errg.Go(func() error {
		ticker := time.NewTicker(c.cfg.EventsFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				now := c.nowFunc()
				// This func should be fast because it locks the whole groups map.
				func() {
					c.eventsGroupsMu.Lock()
					defer c.eventsGroupsMu.Unlock()
					for id, g := range c.eventsGroups {
						if g.flushedAt.Load().Add(g.cfg.flushInterval).Before(now) {
							select {
							case flushQueue <- id:
							default:
							}
						}
					}
				}()
			}
		}
	})

	// Process ebpf events, signatures and flush requests in workers.
	for range numWorkers {
		errg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case e := <-c.tracer.Events():
					group := c.getOrCreateContainerEventsGroup(e)
					group.handleEvent(ctx, e, nil)
				case e := <-c.signatureEngine.Events():
					group := c.getOrCreateContainerEventsGroup(e.EbpfEvent)
					group.handleEvent(ctx, e.EbpfEvent, e.SignatureEvent)
				case cgroupID := <-flushQueue:
					func() {
						c.eventsGroupsMu.Lock()
						group, found := c.eventsGroups[cgroupID]
						c.eventsGroupsMu.Unlock()
						if found {
							group.sendBatchLocked(ctx)
						}
					}()
				}
			}
		})
	}

	return errg.Wait()
}

func (c *Controller) getOrCreateContainerEventsGroup(e *ebpftypes.Event) *containerEventsGroup {
	c.eventsGroupsMu.Lock()
	defer c.eventsGroupsMu.Unlock()

	group, found := c.eventsGroups[e.Context.CgroupID]
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
		cfg := containerEventsGroupConfig{
			batchSize:     c.cfg.EventsBatchSize,
			flushInterval: c.cfg.EventsFlushInterval,
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
		c.eventsGroups[e.Context.CgroupID] = group
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
	res.ProcessName = strings.ToValidUTF8(decoder.ProcessNameString(e.Context.Comm[:]), "")
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
		dnsEvent.DNSQuestionDomain = strings.ToValidUTF8(dnsEvent.DNSQuestionDomain, "")
		for _, answer := range dnsEvent.Answers {
			answer.Name = strings.ToValidUTF8(answer.Name, "")
		}
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
		for i, arg := range args.Argv {
			args.Argv[i] = strings.ToValidUTF8(arg, "")
		}
		res.EventType = castpb.EventType_EVENT_EXEC
		res.Data = &castpb.ContainerEvent_Exec{
			Exec: &castpb.Exec{
				Path:       strings.ToValidUTF8(args.Filepath, ""),
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
				Path: strings.ToValidUTF8(args.FilePath, ""),
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
			File: &castpb.File{Path: strings.ToValidUTF8(args.Path, "")},
		}
	case ebpftypes.NetPacketSSHBaseArgs:
		res.EventType = castpb.EventType_EVENT_SSH
		sshEvent := args.Payload
		sshEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		sshEvent.Version = strings.ToValidUTF8(sshEvent.Version, "v")
		sshEvent.Comments = strings.ToValidUTF8(sshEvent.Comments, "v")
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
