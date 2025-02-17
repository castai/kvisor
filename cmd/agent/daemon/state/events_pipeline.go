package state

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	ebpftypes "github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
)

func (c *Controller) runEventsPipeline(ctx context.Context) error {
	c.log.Info("running events pipeline")
	defer c.log.Info("events pipeline done")

	var currentEventsCount int
	lastFlushedAt := time.Now()
	groups := map[uint64]*castpb.ContainerEvents{}

	ticker := time.NewTicker(c.cfg.EventsFlushInterval)
	defer ticker.Stop()

	batch := &castpb.ContainerEventsBatch{}

	send := func() {
		batch.Items = batch.Items[:0]
		if currentEventsCount == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for _, group := range groups {
			if len(group.Items) > 0 {
				batch.Items = append(batch.Items, group)
			}
		}

		c.log.Debugf("sending events batch, events=%d, groups=%d", currentEventsCount, len(batch.Items))
		if err := c.exporters.ContainerEventsSender.Send(ctx, batch); err != nil {
			c.log.Errorf("sending events batch: %s", err)
		}

		// Reset state after data is sent.
		for _, group := range groups {
			group.Items = group.Items[:0]
		}
		lastFlushedAt = time.Now()
		currentEventsCount = 0
	}

	handleEvent := func(e *ebpftypes.Event) {
		group, found := groups[e.Context.CgroupID]
		if !found {
			group = c.newContainerEventsGroup(e)
			groups[e.Context.CgroupID] = group
		}
		pbEvent := &castpb.ContainerEvent{}
		c.fillProtoContainerEvent(pbEvent, e, nil)

		if c.enrichmentService.Enqueue(&enrichment.EnrichedContainerEvent{
			Event:     pbEvent,
			EbpfEvent: e,
		}) {
			return
		}

		group.Items = append(group.Items, pbEvent)
		currentEventsCount++
	}

	handleSignatureEvent := func(e *ebpftypes.Event, signatureEvent *castpb.SignatureEvent) {
		group, found := groups[e.Context.CgroupID]
		if !found {
			group = c.newContainerEventsGroup(e)
			groups[e.Context.CgroupID] = group
		}
		pbEvent := &castpb.ContainerEvent{}
		c.fillProtoContainerEvent(pbEvent, e, signatureEvent)

		group.Items = append(group.Items, pbEvent)
		currentEventsCount++
	}

	handleEnrichedEvent := func(e *enrichment.EnrichedContainerEvent) {
		group, found := groups[e.EbpfEvent.Context.CgroupID]
		if !found {
			// If enriched event is not found here most likely container was removed.
			c.log.Warnf("group not found for enriched event, cgroup_id=%d, event_type=%s", e.EbpfEvent.Context.CgroupID, e.Event.EventType.String())
			return
		}

		group.Items = append(group.Items, e.Event)
		currentEventsCount++
	}

	// Go select works by randomly selects from any channel. If we have many ebpf events in the queue and container deletion burst
	// it may lag to handle container delete events. In such case ebpf events may pick from group since we have a grouping key by cgroupID.
	//
	// NOTE: It's important to keep the last select blocking
	// otherwise it will consume CPU resources.
	for {
		// Top priority, handle context cancel and flush remaining data.
		select {
		case <-ctx.Done():
			send()
			return ctx.Err()
		default:
		}

		// High priority, handle deleted first containers.
		select {
		case cgroupID := <-c.deletedContainersQueue:
			group, found := groups[cgroupID]
			if !found {
				continue
			}
			if len(group.Items) == 0 {
				delete(groups, cgroupID)
				continue
			}
			// Send data only from this container.
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := c.exporters.ContainerEventsSender.Send(ctx, &castpb.ContainerEventsBatch{Items: []*castpb.ContainerEvents{group}}); err != nil {
					c.log.Errorf("sending events batch for deletet container: %s", err)
				}
			}()
			delete(groups, cgroupID)
		default:
		}

		// Normal priority. Here we are fine to read all channels randomly.
		select {
		case <-ctx.Done():
			send()
			return ctx.Err()
		// Handle eBPF events.
		case e := <-c.tracer.Events():
			handleEvent(e)
			if currentEventsCount >= c.cfg.EventsBatchSize {
				send()
			}
		// Handle signature events.
		case e := <-c.signatureEngine.Events():
			handleSignatureEvent(e.EbpfEvent, e.SignatureEvent)
			if currentEventsCount >= c.cfg.EventsBatchSize {
				send()
			}
		case e := <-c.enrichmentService.Events():
			handleEnrichedEvent(e)
			if currentEventsCount >= c.cfg.EventsBatchSize {
				send()
			}
		// Periodically flush collected data in case batch size is not reached (low events rate).
		case <-ticker.C:
			if lastFlushedAt.Add(c.cfg.EventsFlushInterval).Before(time.Now()) {
				send()
			}
		}
	}
}

func (c *Controller) newContainerEventsGroup(e *ebpftypes.Event) *castpb.ContainerEvents {
	group := &castpb.ContainerEvents{
		NodeName:          c.nodeName,
		Namespace:         e.Container.PodNamespace,
		PodName:           e.Container.PodName,
		ContainerName:     e.Container.Name,
		ContainerId:       e.Container.ID,
		PodUid:            e.Container.PodUID,
		ObjectLabels:      e.Container.Labels,
		ObjectAnnotations: e.Container.Annotations,
		CgroupId:          e.Context.CgroupID,
		Items:             make([]*castpb.ContainerEvent, 0, 100), // Preallocate to reduce memory allocations.
	}
	if podInfo, found := c.getPodInfo(e.Container.PodUID); found {
		group.WorkloadKind = castpb.WorkloadKind(podInfo.WorkloadKind)
		group.WorkloadName = podInfo.WorkloadName
		group.WorkloadUid = podInfo.WorkloadUid
		group.NodeName = podInfo.NodeName
	}
	return group
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
		c.cacheDNS(e.Context.CgroupID, dnsEvent)

	case ebpftypes.SockSetStateArgs:
		tpl := args.Tuple
		res.EventType = findTCPEventType(ebpftypes.TCPSocketState(args.OldState), ebpftypes.TCPSocketState(args.NewState))
		pbTuple := &castpb.Tuple{
			SrcIp:       tpl.Src.Addr().AsSlice(),
			DstIp:       tpl.Dst.Addr().AsSlice(),
			SrcPort:     uint32(tpl.Src.Port()),
			DstPort:     uint32(tpl.Dst.Port()),
			DnsQuestion: c.getAddrDnsQuestion(e.Context.CgroupID, tpl.Dst.Addr()),
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
