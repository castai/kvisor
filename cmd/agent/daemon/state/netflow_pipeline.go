package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"net/netip"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"golang.org/x/sync/errgroup"
)

type clusterInfo struct {
	podCidr     netip.Prefix
	serviceCidr netip.Prefix
}

func (c *Controller) getClusterInfo(ctx context.Context) (*clusterInfo, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := c.kubeClient.GetClusterInfo(ctx, &kubepb.GetClusterInfoRequest{})
		if err != nil {
			c.log.Warnf("getting cluster info: %v", err)
			sleep(ctx, 2*time.Second)
			continue
		}
		res := clusterInfo{}
		res.podCidr, err = netip.ParsePrefix(resp.PodsCidr)
		if err != nil {
			return nil, err
		}
		res.serviceCidr, err = netip.ParsePrefix(resp.ServiceCidr)
		if err != nil {
			return nil, err
		}
		return &res, nil
	}
}

func (c *Controller) runNetflowPipeline(ctx context.Context) error {
	c.log.Info("running netflow pipeline")
	defer c.log.Info("netflow pipeline done")

	var err error
	c.clusterInfo, err = c.getClusterInfo(ctx)
	if err != nil {
		return fmt.Errorf("get cluster info: %w", err)
	}

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e := <-c.tracer.NetflowEvents():
				c.upsertNetflow(e)
			}
		}
	})
	errg.Go(func() error {
		t := time.NewTicker(c.cfg.NetflowCleanupInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				c.cleanupNetflow()
			}
		}
	})
	return errg.Wait()
}

type netflowVal struct {
	updatedAt    time.Time
	event        *types.Event
	destinations map[uint64]*netflowDest
}

type netflowDest struct {
	addrPort  netip.AddrPort
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
}

func (c *Controller) upsertNetflow(e *types.Event) {
	c.netflowsMu.Lock()
	defer c.netflowsMu.Unlock()

	args := e.Args.(types.NetFlowBaseArgs)
	key := netflowKey(e, &args)
	netflow, found := c.netflows[key]
	if !found {
		netflow = &netflowVal{
			event:        e,
			destinations: map[uint64]*netflowDest{},
		}
		c.netflows[key] = netflow
	}

	destKey := netflowDestKey(&args)
	dest, found := netflow.destinations[destKey]
	if !found {
		dest = &netflowDest{
			addrPort: args.Tuple.Dst,
		}
		netflow.destinations[key] = dest
	}
	// Update stats
	dest.txBytes += args.TxBytes
	dest.rxBytes += args.RxBytes
	dest.txPackets += args.TxPackets
	dest.rxPackets += args.RxPackets

	now := time.Now()
	start := time.UnixMicro(int64(e.Context.Ts) / 1e3)
	netflow.updatedAt = now
	flowType := e.Context.GetNetflowType()
	if now.Sub(start) >= c.cfg.NetflowExportInterval || flowType == types.NetflowTypeTCPBegin || flowType == types.NetflowTypeTCPEnd {
		pbNetFlow := c.toProtoNetflow(netflow, &args, now)
		for _, exp := range c.exporters.Netflow {
			exp.Enqueue(pbNetFlow)
		}
		// Reset flow stats after export.
		for _, flowDest := range netflow.destinations {
			flowDest.txBytes = 0
			flowDest.rxBytes = 0
			flowDest.txPackets = 0
			flowDest.rxPackets = 0
		}
	}

	// Cleanup flow.
	if flowType == types.NetflowTypeTCPEnd {
		delete(c.netflows, key)
	}
}

func (c *Controller) toProtoNetflow(flow *netflowVal, args *types.NetFlowBaseArgs, now time.Time) *castpb.Netflow {
	ctx := flow.event.Context
	cont := flow.event.Container

	res := &castpb.Netflow{
		StartTs:       ctx.Ts,
		EndTs:         uint64(now.UnixNano()),
		ProcessName:   string(bytes.TrimRight(ctx.Comm[:], "\x00")),
		Namespace:     cont.PodNamespace,
		PodName:       cont.PodName,
		ContainerName: cont.Name,
		Addr:          args.Tuple.Src.Addr().AsSlice(),
		Port:          uint32(args.Tuple.Src.Port()),
		Protocol:      toProtoProtocol(args.Proto),
		Destinations:  make([]*castpb.NetflowDestination, 0, len(flow.destinations)),
	}

	c.enrichFlowKubeInfo(args.Tuple.Src.Addr(), res)

	for _, dest := range flow.destinations {
		dst := dest.addrPort
		dns, _ := c.dnsCache.Get(dst.Addr())

		if c.clusterInfo.serviceCidr.Contains(dst.Addr()) {
			if realDst, found := c.ct.GetDestination(args.Tuple.Src, args.Tuple.Dst); found {
				dst = realDst
			}
		}

		pbDest := &castpb.NetflowDestination{
			DnsQuestion: dns,
			Addr:        dst.Addr().AsSlice(),
			Port:        uint32(dst.Port()),
			TxBytes:     dest.txBytes,
			RxBytes:     dest.rxBytes,
			TxPackets:   dest.txPackets,
			RxPackets:   dest.rxPackets,
		}

		c.enrichFlowDestinationKubeInfo(dst.Addr(), pbDest)

		res.Destinations = append(res.Destinations, pbDest)
	}
	return res
}

func (c *Controller) enrichFlowKubeInfo(addr netip.Addr, res *castpb.Netflow) {
	ipInfo, found := c.getIPInfo(addr)
	if !found {
		return
	}
	res.WorkloadName = ipInfo.WorkloadName
	res.WorkloadKind = ipInfo.WorkloadKind
	res.Zone = ipInfo.Zone
}

func (c *Controller) enrichFlowDestinationKubeInfo(dstAddr netip.Addr, pbDest *castpb.NetflowDestination) {
	if !c.clusterInfo.serviceCidr.Contains(dstAddr) && !c.clusterInfo.podCidr.Contains(dstAddr) {
		return
	}

	ipInfo, found := c.getIPInfo(dstAddr)
	if !found {
		return
	}

	pbDest.PodName = ipInfo.PodName
	pbDest.Namespace = ipInfo.Namespace
	pbDest.WorkloadName = ipInfo.WorkloadName
	pbDest.WorkloadKind = ipInfo.WorkloadKind
	pbDest.Zone = ipInfo.Zone
}

func (c *Controller) getIPInfo(addr netip.Addr) (*kubepb.IPInfo, bool) {
	ipInfo, found := c.ipInfoCache.Get(addr)
	if !found {
		resp, err := c.kubeClient.GetIPInfo(context.Background(), &kubepb.GetIPInfoRequest{Ip: addr.Unmap().String()})
		if err != nil {
			c.log.Warnf("failed to get ip info: %v", err)
			return nil, false
		}
		ipInfo = resp.Info
		c.ipInfoCache.Add(addr, ipInfo)
	}
	return ipInfo, true
}

func (c *Controller) cleanupNetflow() {
	c.netflowsMu.Lock()
	defer c.netflowsMu.Unlock()

	now := time.Now()
	for key, flow := range c.netflows {
		lastFlowUpdate := now.Sub(flow.updatedAt)
		if lastFlowUpdate >= c.cfg.NetflowExportInterval*2 {
			c.log.Debugf("removed expired netflow flow, ns=%s, pod=%s", flow.event.Container.PodNamespace, flow.event.Container.PodName)
			delete(c.netflows, key)
		}
	}
}

var netflowKeyHash maphash.Hash

func netflowKey(e *types.Event, args *types.NetFlowBaseArgs) uint64 {
	netflowKeyHash.Reset()

	// Cgroup id.
	var cgroup [8]byte
	binary.LittleEndian.PutUint64(cgroup[:], e.Context.CgroupID)
	_, _ = netflowKeyHash.Write(cgroup[:])

	// Pid.
	var pid [4]byte
	binary.LittleEndian.PutUint32(cgroup[:], e.Context.HostPid)
	_, _ = netflowKeyHash.Write(pid[:])

	// Source addr+port.
	srcBytes, _ := args.Tuple.Src.MarshalBinary()
	_, _ = netflowKeyHash.Write(srcBytes)

	// Protocol.
	_ = netflowKeyHash.WriteByte(args.Proto)

	// Direction.
	_ = netflowKeyHash.WriteByte(byte(e.Context.GetFlowDirection()))

	return netflowKeyHash.Sum64()
}

func netflowDestKey(args *types.NetFlowBaseArgs) uint64 {
	netflowKeyHash.Reset()

	// Destination addr+port.
	srcBytes, _ := args.Tuple.Dst.MarshalBinary()
	_, _ = netflowKeyHash.Write(srcBytes)

	return netflowKeyHash.Sum64()
}

func toProtoProtocol(proto uint8) castpb.NetflowProtocol {
	switch proto {
	case 6:
		return castpb.NetflowProtocol_NETFLOW_PROTOCOL_TCP
	default:
		return castpb.NetflowProtocol_NETFLOW_PROTOCOL_UNKNOWN
	}
}

func sleep(ctx context.Context, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
