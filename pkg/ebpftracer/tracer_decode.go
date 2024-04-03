package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/kernel"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/net/packet"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
)

// Error indicating that the resulting error was caught from a panic
var ErrPanic = errors.New("encountered panic")

func (t *Tracer) decodeAndHandleSignal(_ context.Context, data []byte) (rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, data)
	var signalCtx types.SignalContext
	if err := ebpfMsgDecoder.DecodeSignalContext(&signalCtx); err != nil {
		return err
	}
	parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, signalCtx.EventID)
	if err != nil {
		return fmt.Errorf("cannot parse event type %d: %w", signalCtx.EventID, err)
	}

	switch args := parsedArgs.(type) {
	case types.SignalCgroupMkdirArgs:
		// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
		if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
			return nil
		}

		t.cfg.CgroupClient.LoadCgroup(args.CgroupId, args.CgroupPath)

	case types.SignalCgroupRmdirArgs:
		// We we only care about events from the default cgroup, as cgroup v1 does not have unified cgroups.
		if !t.cfg.CgroupClient.IsDefaultHierarchy(args.HierarchyId) {
			return nil
		}

		t.queueCgroupForRemoval(args.CgroupId)
		err := t.UnmuteEventsFromCgroup(args.CgroupId)
		if err != nil {
			return fmt.Errorf("cannot remove cgroup %d from mute map: %w", args.CgroupId, err)
		}
	default:
		t.log.Warnf("unhandled signal: %d", signalCtx.EventID)
	}

	return nil
}

func (t *Tracer) decodeAndExportEvent(ctx context.Context, data []byte) (rerr error) {
	metrics.AgentPulledEventsBytesTotal.Add(float64(len(data)))

	defer func() {
		if perr := recover(); perr != nil {
			stack := string(debug.Stack())
			rerr = fmt.Errorf("decode %w: %v, stack=%s", ErrPanic, perr, stack)
		}
	}()

	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, data)
	var eventCtx types.EventContext
	if err := ebpfMsgDecoder.DecodeContext(&eventCtx); err != nil {
		return err
	}

	eventId := eventCtx.EventID

	parsedArgs, err := decoder.ParseArgs(ebpfMsgDecoder, eventId)
	if err != nil {
		return fmt.Errorf("cannot parse event type %d: %w", eventId, err)
	}

	container, err := t.cfg.ContainerClient.GetContainerForCgroup(ctx, eventCtx.CgroupID)
	if err != nil {
		// we ignore any event not belonging to a container for now
		if errors.Is(err, containers.ErrContainerNotFound) {
			err := t.MuteEventsFromCgroup(eventCtx.CgroupID)
			if err != nil {
				return fmt.Errorf("cannot mute events for cgroup %d: %w", eventCtx.CgroupID, err)
			}
			return nil
		}

		return fmt.Errorf("cannot get container for cgroup %d: %w", eventCtx.CgroupID, err)
	}

	if _, found := t.signatureEventMap[eventId]; found {
		t.policy.SignatureEngine.QueueEvent(&types.Event{
			Context:   &eventCtx,
			Container: container,
			Args:      parsedArgs,
		})
	}

	// Do not parse event, if it is not registered. If there is no policy set, we treat is as to parse all the events
	if _, found := t.eventPoliciesMap[eventId]; !found && t.policy != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventId))}).Inc()
		return nil
	}

	// TODO: Move rate limit based policy to kernel side.
	if err := t.allowedByPolicyPre(&eventCtx); err != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventId))}).Inc()
		return nil
	}

	event := castpb.Event{
		EventType:     0,
		Timestamp:     t.bootTime + eventCtx.Ts,
		ProcessName:   string(bytes.TrimRight(eventCtx.Comm[:], "\x00")),
		Namespace:     container.PodNamespace,
		PodUid:        container.PodUID,
		PodName:       container.PodName,
		ContainerName: container.Name,
		ContainerId:   container.ID,
		CgroupId:      container.CgroupID,
		HostPid:       eventCtx.HostPid,
	}

	switch args := parsedArgs.(type) {
	case types.NetPacketDNSBaseArgs:
		metrics.AgentDNSPacketsTotal.Inc()
		event.EventType = castpb.EventType_EVENT_DNS

		dnsEvent, err := decodeDNS(args.Payload, t.dnsPacketParser)
		// If we cannot parse an DNS packet, we abord
		if err != nil {
			metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: event.GetEventType().String()}).Inc()
			return nil
		}
		event.Data = &castpb.Event_Dns{
			Dns: dnsEvent,
		}
	case types.SockSetStateArgs:
		tpl := args.Tuple
		socketState := types.SocketState{
			OldState: types.TCPSocketState(args.OldState),
			NewState: types.TCPSocketState(args.NewState),
		}
		event.EventType = findTCPEventType(socketState)
		if t.shouldFindActualDestination(socketState, tpl) {
			if dst, found := t.cfg.ActualDestinationGetter.GetDestination(tpl.Src, tpl.Dst); found {
				tpl.Dst = dst
			}
		}
		event.Data = &castpb.Event_Tuple{
			Tuple: &castpb.Tuple{
				SrcIp:   tpl.Src.Addr().String(),
				DstIp:   tpl.Dst.Addr().String(),
				SrcPort: uint32(tpl.Src.Port()),
				DstPort: uint32(tpl.Dst.Port()),
			},
		}
	case types.SchedProcessExecArgs:
		if eventCtx.Pid == 1 {
			t.cfg.MountNamespacePIDStore.ForceAddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		} else {
			t.cfg.MountNamespacePIDStore.AddToBucket(proc.NamespaceID(eventCtx.MntID), eventCtx.NodeHostPid)
		}

		event.EventType = castpb.EventType_EVENT_EXEC
		event.Data = &castpb.Event_Exec{
			Exec: &castpb.Exec{
				Path: args.Pathname,
				Args: args.Argv,
			},
		}
	case types.FileModificationArgs:
		event.EventType = castpb.EventType_EVENT_FILE_CHANGE
		event.Data = &castpb.Event_File{
			File: &castpb.File{
				Path: args.FilePath,
			},
		}
	case types.ProcessOomKilledArgs:
		event.EventType = castpb.EventType_EVENT_PROCESS_OOM
		// Nothing to add, sinces we do not have a payload

	case types.TestEventArgs:
		// nothing to do here, as this event is solely used by testing

	case types.MagicWriteArgs:
		event.EventType = castpb.EventType_EVENT_MAGIC_WRITE
		event.Data = &castpb.Event_File{
			File: &castpb.File{
				Path: args.Pathname,
			},
		}
	}

	if event.EventType == castpb.EventType_UNKNOWN {
		return fmt.Errorf("unknown event %d, process=%s", eventId, event.GetProcessName())
	}

	if err := t.allowedByPolicy(eventId, eventCtx.CgroupID, &event); err != nil {
		metrics.AgentSkippedEventsTotal.With(prometheus.Labels{metrics.EventIDLabel: strconv.Itoa(int(eventCtx.EventID))}).Inc()
		return nil
	}

	if t.cfg.EnrichEvent(&enrichment.EnrichRequest{
		Event:        &event,
		EventContext: &eventCtx,
		Args:         parsedArgs,
		Container:    container,
	}) {
		// If we can get an event into the enrichment path, we are not allowed to put throw it into
		// the events chan, as otherwise we will report events twice.
		return nil
	}

	select {
	case t.eventsChan <- &event:

	default:
		metrics.AgentDroppedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: event.GetEventType().String()}).Inc()
	}

	return nil
}

func findTCPEventType(state types.SocketState) castpb.EventType {
	if state.OldState == types.TCP_STATE_CLOSE && state.NewState == types.TCP_STATE_LISTEN {
		return castpb.EventType_EVENT_TCP_LISTEN
	}

	if state.OldState == types.TCP_STATE_SYN_SENT {
		if state.NewState == types.TCP_STATE_ESTABLISHED {
			return castpb.EventType_EVENT_TCP_CONNECT
		}
		if state.NewState == types.TCP_STATE_CLOSE {
			return castpb.EventType_EVENT_TCP_CONNECT_ERROR
		}
	}

	return castpb.EventType_UNKNOWN
}

func (t *Tracer) shouldFindActualDestination(socketState types.SocketState, tpl types.AddrTuple) bool {
	if ct := t.cfg.ActualDestinationGetter; ct != nil && isTCPConnect(socketState) && !tpl.Dst.Addr().IsPrivate() {
		return true
	}
	return false
}

func (t *Tracer) MuteEventsFromCgroup(cgroup uint64) error {
	t.log.Infof("muting cgroup %d", cgroup)
	return t.module.objects.IgnoredCgroupsMap.Put(cgroup, cgroup)
}

func (t *Tracer) MuteEventsFromCgroups(cgroups []uint64) error {
	t.log.Infof("muting cgroups %v", cgroups)

	kernelVersion, err := kernel.CurrentKernelVersion()
	if err != nil {
		return err
	}

	// The ebpf batch helpers are available since kernel version 5.6.
	if kernelVersion.Major > 5 || (kernelVersion.Major == 5 && kernelVersion.Minor >= 6) {
		_, err = t.module.objects.IgnoredCgroupsMap.BatchUpdate(cgroups, cgroups, &ebpf.BatchOptions{
			Flags: uint64(ebpf.UpdateAny),
		})

		if err != nil {
			t.log.Warnf("got error while trying to mute cgroups %v: %s", cgroups, err)
		}
	} else {
		for _, cgroup := range cgroups {
			err = t.module.objects.IgnoredCgroupsMap.Update(cgroup, cgroup, ebpf.UpdateAny)

			if err != nil {
				t.log.Warnf("got error while trying to delete cgroup %d from ignore map: %s", cgroup, err)
			}
		}
	}

	return nil
}

func (t *Tracer) UnmuteEventsFromCgroup(cgroup uint64) error {
	t.log.Infof("unmuting cgroup %d", cgroup)

	err := t.module.objects.IgnoredCgroupsMap.Delete(cgroup)

	// We do not care if we try to remove a non existing cgroup.
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}

	return err
}

func (t *Tracer) UnmuteEventsFromCgroups(cgroups []uint64) error {
	t.log.Infof("unmuting cgroup %v", cgroups)

	kernelVersion, err := kernel.CurrentKernelVersion()
	if err != nil {
		return err
	}

	// The ebpf batch helpers are available since kernel version 5.6.
	if kernelVersion.Major > 5 || (kernelVersion.Major == 5 && kernelVersion.Minor >= 6) {
		_, err = t.module.objects.IgnoredCgroupsMap.BatchDelete(cgroups, nil)
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.Warnf("got error while trying to delete cgroups %v from ignore map: %s", cgroups, err)
		}
	} else {
		for _, cgroup := range cgroups {
			err = t.module.objects.IgnoredCgroupsMap.Delete(cgroup)
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.log.Warnf("got error while trying to delete cgroup %d from ignore map: %s", cgroup, err)
			}
		}
	}

	return nil
}

func (t *Tracer) IsCgroupMuted(cgroup uint64) bool {
	var value uint64

	err := t.module.objects.IgnoredCgroupsMap.Lookup(cgroup, &value)

	return !errors.Is(err, ebpf.ErrKeyNotExist) && value > 0
}

var errDNSMessageNotComplete = errors.New("received dns packet not complete")

func decodeDNS(data []byte, dnsPacketParser *layers.DNS) (*castpb.DNS, error) {
	payload, subProtocol, err := packet.ExtractPayload(data)
	if err != nil {
		return nil, err
	}

	if subProtocol == packet.SubProtocolTCP {
		if len(payload) < 2 {
			return nil, errDNSMessageNotComplete
		}

		// DNS over TCP prefixes the DNS message with a two octet length field. If the payload is not as big as this specified length,
		// then we cannot parse the packet, as part of the DNS message will be send in a later one.
		// For more information see https://datatracker.ietf.org/doc/html/rfc1035.html#section-4.2.2
		length := int(binary.BigEndian.Uint16(payload[:2]))
		if len(payload)+2 < length {
			return nil, errDNSMessageNotComplete
		}
		payload = payload[2:]
	}
	if err := dnsPacketParser.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	pbDNS := &castpb.DNS{
		Answers: make([]*castpb.DNSAnswers, len(dnsPacketParser.Answers)),
	}

	for _, v := range dnsPacketParser.Questions {
		pbDNS.DNSQuestionDomain = string(v.Name)
		break
	}

	for i, v := range dnsPacketParser.Answers {
		pbDNS.Answers[i] = &castpb.DNSAnswers{
			Name:  string(v.Name),
			Type:  uint32(v.Type),
			Class: uint32(v.Class),
			Ttl:   v.TTL,
			Ip:    v.IP,
			Cname: string(v.CNAME),
		}
	}

	return pbDNS, nil
}

func isTCPConnect(st types.SocketState) bool {
	return st.OldState == types.TCP_STATE_SYN_SENT && st.NewState == types.TCP_STATE_ESTABLISHED
}
