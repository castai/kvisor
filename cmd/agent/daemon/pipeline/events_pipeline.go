package pipeline

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"google.golang.org/protobuf/proto"
)

type containerEventsGroup struct {
	pb        *castaipb.ContainerEvents
	updatedAt time.Time
}

func (c *Controller) runEventsPipeline(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.DataBatch.FlushInterval)
	defer ticker.Stop()

	groups := c.eventGroups
	stats := newDataBatchStats()

	send := func(reason string) {
		items := make([]*castaipb.DataBatchItem, 0, stats.totalItems)
		for _, group := range groups {
			if len(group.pb.Items) == 0 {
				continue
			}
			items = append(items, &castaipb.DataBatchItem{
				Data: &castaipb.DataBatchItem_ContainerEvents{ContainerEvents: group.pb},
			})
		}
		c.sendDataBatch(reason, metrics.PipelineEBPFEvents, items)

		// Reset stats and group items after send.
		stats.reset()
		now := time.Now()
		for key, group := range groups {
			// Delete the inactive group.
			if group.updatedAt.Add(time.Minute).Before(now) {
				delete(groups, key)
				c.log.Debugf("deleted inactive events group, cgroup_id=%d", key)
				continue
			}
			group.pb.Items = group.pb.Items[:0]
		}
	}

	handleCgroupDelete := func(cgroupID uint64) {
		group, found := groups[cgroupID]
		if !found {
			return
		}
		if len(group.pb.Items) == 0 {
			delete(groups, cgroupID)
			return
		}
		c.sendDataBatch("events cgroup deleted", metrics.PipelineEBPFEvents, []*castaipb.DataBatchItem{
			{
				Data: &castaipb.DataBatchItem_ContainerEvents{
					ContainerEvents: group.pb,
				},
			},
		})
		delete(groups, cgroupID)
	}

	for {
		// Top priority, handle context cancel and flush remaining data.
		select {
		case <-ctx.Done():
			if stats.sizeBytes > 0 {
				send("events shutdown")
			}
			return ctx.Err()
		default:
		}

		// High priority. Flush recently deleted groups.
		select {
		case cgroupID := <-c.deletedContainersEventsQueue:
			handleCgroupDelete(cgroupID)
		default:
		}

		// Normal priority.
		select {
		case <-ctx.Done():
			if stats.sizeBytes > 0 {
				send("events shutdown")
			}
			return ctx.Err()
		case cgroupID := <-c.deletedContainersEventsQueue:
			handleCgroupDelete(cgroupID)
		case e := <-c.tracer.Events():
			c.handleEvent(groups, stats, e)
			if stats.sizeBytes >= c.cfg.DataBatch.MaxBatchSizeBytes {
				send("events batch is full")
			}
		case e := <-c.signatureEngine.Events():
			c.handleSignatureEvent(groups, stats, e.EbpfEvent, e.SignatureEvent)
			if stats.sizeBytes >= c.cfg.DataBatch.MaxBatchSizeBytes {
				send("events batch is full")
			}
		case <-ticker.C:
			if stats.sizeBytes > 0 && stats.lastSentAt.Add(c.cfg.DataBatch.FlushInterval).Before(time.Now()) {
				send("events flush interval")
			}
			continue
		case e := <-c.enrichmentService.Events():
			c.handleEnrichedEvent(groups, stats, e)
			if stats.sizeBytes >= c.cfg.DataBatch.MaxBatchSizeBytes {
				send("events batch is full")
			}
		}
	}
}

func (c *Controller) handleEvent(groups map[uint64]*containerEventsGroup, stats *dataBatchStats, e *ebpftypes.Event) {
	group, found := groups[e.Context.CgroupID]
	if !found {
		group = c.newContainerEventsGroup(e)
		groups[e.Context.CgroupID] = group
		stats.totalItems++
	}
	pbEvent := &castaipb.ContainerEvent{}
	c.fillProtoContainerEvent(pbEvent, e, nil)

	if c.enrichmentService.Enqueue(&enrichment.EnrichedContainerEvent{
		Event:     pbEvent,
		EbpfEvent: e,
	}) {
		return
	}

	group.pb.Items = append(group.pb.Items, pbEvent)
	group.updatedAt = time.Now()
	stats.sizeBytes += proto.Size(pbEvent)
}

func (c *Controller) handleSignatureEvent(groups map[uint64]*containerEventsGroup, stats *dataBatchStats, e *ebpftypes.Event, signatureEvent *castaipb.SignatureEvent) {
	group, found := groups[e.Context.CgroupID]
	if !found {
		group = c.newContainerEventsGroup(e)
		groups[e.Context.CgroupID] = group
		stats.totalItems++
	}
	pbEvent := &castaipb.ContainerEvent{}
	c.fillProtoContainerEvent(pbEvent, e, signatureEvent)

	group.pb.Items = append(group.pb.Items, pbEvent)
	group.updatedAt = time.Now()
	stats.sizeBytes += proto.Size(pbEvent)
}

func (c *Controller) handleEnrichedEvent(groups map[uint64]*containerEventsGroup, stats *dataBatchStats, e *enrichment.EnrichedContainerEvent) {
	group, found := groups[e.EbpfEvent.Context.CgroupID]
	if !found {
		// If enriched event is not found here most likely container was removed.
		c.log.Warnf("group not found for enriched event, cgroup_id=%d, event_type=%s", e.EbpfEvent.Context.CgroupID, e.Event.EventType.String())
		return
	}

	group.pb.Items = append(group.pb.Items, e.Event)
	group.updatedAt = time.Now()
	stats.sizeBytes += proto.Size(e.Event)
}

func (c *Controller) newContainerEventsGroup(e *ebpftypes.Event) *containerEventsGroup {
	group := &castaipb.ContainerEvents{
		NodeName:          c.nodeName,
		Namespace:         e.Container.PodNamespace,
		PodName:           e.Container.PodName,
		ContainerName:     e.Container.Name,
		ContainerId:       e.Container.ID,
		PodUid:            e.Container.PodUID,
		ObjectLabels:      e.Container.Labels,
		ObjectAnnotations: e.Container.Annotations,
		CgroupId:          e.Context.CgroupID,
		Items:             make([]*castaipb.ContainerEvent, 0, 10), // Preallocate to reduce memory allocations.
	}
	if podInfo, found := c.getPodInfo(e.Container.PodUID); found {
		group.WorkloadKind = castaipb.WorkloadKind(podInfo.WorkloadKind)
		group.WorkloadName = podInfo.WorkloadName
		group.WorkloadUid = podInfo.WorkloadUid
		group.NodeName = podInfo.NodeName
	}
	return &containerEventsGroup{
		pb:        group,
		updatedAt: time.Now(),
	}
}

func (c *Controller) fillProtoContainerEvent(res *castaipb.ContainerEvent, e *ebpftypes.Event, signatureEvent *castaipb.SignatureEvent) {
	res.Timestamp = e.Context.Ts
	res.ProcessName = strings.ToValidUTF8(decoder.ProcessNameString(e.Context.Comm[:]), "")
	res.HostPid = e.Context.HostPid
	res.Pid = e.Context.Pid
	res.ProcessStartTime = uint64(time.Duration(e.Context.LeaderStartTime).Truncate(time.Second).Nanoseconds()) // nolint:gosec,
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
		res.EventType = castaipb.EventType_EVENT_SIGNATURE
		res.Data = &castaipb.ContainerEvent_Signature{
			Signature: signatureEvent,
		}
		return
	}

	switch args := e.Args.(type) {
	case ebpftypes.NetPacketDNSBaseArgs:
		metrics.AgentDNSPacketsTotal.Inc()
		res.EventType = castaipb.EventType_EVENT_DNS

		dnsEvent := args.Payload
		dnsEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		dnsEvent.DNSQuestionDomain = strings.ToValidUTF8(dnsEvent.DNSQuestionDomain, "")
		for _, answer := range dnsEvent.Answers {
			answer.Name = strings.ToValidUTF8(answer.Name, "")
		}
		res.Data = &castaipb.ContainerEvent_Dns{
			Dns: dnsEvent,
		}

		// Add dns cache.
		c.cacheDNS(e.Context.CgroupID, dnsEvent)

	case ebpftypes.SockSetStateArgs:
		tpl := args.Tuple
		res.EventType = findTCPEventType(ebpftypes.TCPSocketState(args.OldState), ebpftypes.TCPSocketState(args.NewState))
		pbTuple := &castaipb.Tuple{
			SrcIp:       tpl.Src.Addr().AsSlice(),
			DstIp:       tpl.Dst.Addr().AsSlice(),
			SrcPort:     uint32(tpl.Src.Port()),
			DstPort:     uint32(tpl.Dst.Port()),
			DnsQuestion: c.getAddrDnsQuestion(e.Context.CgroupID, tpl.Dst.Addr()),
		}
		res.Data = &castaipb.ContainerEvent_Tuple{
			Tuple: pbTuple,
		}
	case ebpftypes.SchedProcessExecArgs:
		for i, arg := range args.Argv {
			args.Argv[i] = strings.ToValidUTF8(arg, "")
		}
		res.EventType = castaipb.EventType_EVENT_EXEC
		res.Data = &castaipb.ContainerEvent_Exec{
			Exec: &castaipb.Exec{
				Path:       strings.ToValidUTF8(args.Filepath, ""),
				Args:       args.Argv,
				HashSha256: nil, // Hash is filled inside enrichment.
				Flags:      args.Flags,
			},
		}
	case ebpftypes.SchedProcessForkArgs:
		res.EventType = castaipb.EventType_EVENT_PROCESS_FORK
		res.Data = &castaipb.ContainerEvent_ProcessFork{
			ProcessFork: &castaipb.ProcessFork{},
		}
	case ebpftypes.SchedProcessExitArgs:
		res.EventType = castaipb.EventType_EVENT_PROCESS_EXIT
		res.Data = &castaipb.ContainerEvent_ProcessExit{
			ProcessExit: &castaipb.ProcessExit{
				ExitCode: args.ExitCode,
			},
		}
	case ebpftypes.FileModificationArgs:
		res.EventType = castaipb.EventType_EVENT_FILE_CHANGE
		res.Data = &castaipb.ContainerEvent_File{
			File: &castaipb.File{
				Path: strings.ToValidUTF8(args.FilePath, ""),
			},
		}
	case ebpftypes.ProcessOomKilledArgs:
		res.EventType = castaipb.EventType_EVENT_PROCESS_EXIT
		res.Data = &castaipb.ContainerEvent_ProcessExit{
			ProcessExit: &castaipb.ProcessExit{
				ExitCode: args.ExitCode,
			},
		}

	case ebpftypes.TestEventArgs:
		// nothing to do here, as this event is solely used by testing

	case ebpftypes.MagicWriteArgs:
		res.EventType = castaipb.EventType_EVENT_MAGIC_WRITE
		res.Data = &castaipb.ContainerEvent_File{
			File: &castaipb.File{
				Path: args.Pathname,
			},
		}
	case ebpftypes.StdioViaSocketArgs:
		res.EventType = castaipb.EventType_EVENT_STDIO_VIA_SOCKET
		finding := castaipb.StdioViaSocketFinding{
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
		res.Data = &castaipb.ContainerEvent_StdioViaSocket{
			StdioViaSocket: &finding,
		}
	case ebpftypes.TtyWriteArgs:
		res.EventType = castaipb.EventType_EVENT_TTY_WRITE
		res.Data = &castaipb.ContainerEvent_File{
			File: &castaipb.File{Path: strings.ToValidUTF8(args.Path, "")},
		}
	case ebpftypes.NetPacketSSHBaseArgs:
		res.EventType = castaipb.EventType_EVENT_SSH
		sshEvent := args.Payload
		sshEvent.FlowDirection = convertFlowDirection(e.Context.GetFlowDirection())
		sshEvent.Version = strings.ToValidUTF8(sshEvent.Version, "v")
		sshEvent.Comments = strings.ToValidUTF8(sshEvent.Comments, "v")
		res.Data = &castaipb.ContainerEvent_Ssh{
			Ssh: sshEvent,
		}
	case ebpftypes.SecurityFileOpenArgs:
		res.EventType = castaipb.EventType_EVENT_FILE_OPEN
		res.Data = &castaipb.ContainerEvent_File{
			File: &castaipb.File{
				Path: args.Path,
			},
		}
	}

	if res.EventType == 0 {
		data, _ := json.Marshal(e.Args) //nolint:errchkjson
		res.EventType = castaipb.EventType_EVENT_ANY
		res.Data = &castaipb.ContainerEvent_Any{
			Any: &castaipb.Any{
				EventId: uint32(e.Context.EventID),
				Syscall: uint32(e.Context.Syscall), // nolint:gosec
				Data:    data,
			},
		}
	}
}

func (c *Controller) getAddrDnsQuestion(cgroupID uint64, addr netip.Addr) string {
	if cache, found := c.dnsCache.Get(cgroupID); found {
		if dnsQuestion, found := cache.Get(addr.Unmap()); found {
			return dnsQuestion
		}
	}
	return ""
}

func (c *Controller) cacheDNS(cgroupID uint64, dnsEvent *ebpftypes.ProtoDNS) {
	cacheVal, found := c.dnsCache.Get(cgroupID)
	if !found {
		var err error
		cacheVal, err = freelru.NewSynced[netip.Addr, string](1024, func(k netip.Addr) uint32 {
			return uint32(xxhash.Sum64(k.AsSlice())) // nolint:gosec
		})
		if err != nil {
			c.log.Errorf("creating dns cache: %v", err)
			return
		}
		c.dnsCache.Add(cgroupID, cacheVal)
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

func convertFlowDirection(flowDir ebpftypes.FlowDirection) castaipb.FlowDirection {
	switch flowDir {
	case ebpftypes.FlowDirectionIngress:
		return castaipb.FlowDirection_FLOW_INGRESS
	case ebpftypes.FlowDirectionEgress:
		return castaipb.FlowDirection_FLOW_EGRESS
	default:
		return castaipb.FlowDirection_FLOW_UNKNOWN
	}
}

func findTCPEventType(oldState, newState ebpftypes.TCPSocketState) castaipb.EventType {
	if oldState == ebpftypes.TCP_STATE_CLOSE && newState == ebpftypes.TCP_STATE_LISTEN {
		return castaipb.EventType_EVENT_TCP_LISTEN
	}

	if oldState == ebpftypes.TCP_STATE_SYN_SENT {
		if newState == ebpftypes.TCP_STATE_ESTABLISHED {
			return castaipb.EventType_EVENT_TCP_CONNECT
		}
		if newState == ebpftypes.TCP_STATE_CLOSE {
			return castaipb.EventType_EVENT_TCP_CONNECT_ERROR
		}
	}

	return castaipb.EventType_UNKNOWN
}
