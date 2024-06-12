package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/metrics"
	"golang.org/x/sync/errgroup"
)

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
	c.log.Infof("fetched cluster info, pod_cidr=%s, cluster_cidr=%s", c.clusterInfo.podCidr, c.clusterInfo.serviceCidr)

	lastExportedAt := time.Now().UTC()
	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e := <-c.tracer.NetflowEvents():
				c.upsertNetflow(e)
				eventTs := time.UnixMicro(int64(e.Context.Ts) / 1000)
				if eventTs.Sub(lastExportedAt) >= c.cfg.NetflowExportInterval {
					c.enqueueNetflowExport(eventTs)
					lastExportedAt = eventTs
				}
			}
		}
	})
	return errg.Wait()
}

// upsertNetflow groups flows by user defined grouping flags.
// This allows to reduce cardinality but also increases agent memory usage
// since it need to store temp grouped netflow data.
func (c *Controller) upsertNetflow(e *types.Event) {
	now := time.Now()
	args := e.Args.(types.NetFlowBaseArgs)
	key := c.netflowKey(e, &args)
	netflow, found := c.netflows[key]
	if !found {
		netflow = &netflowVal{
			updatedAt:    now,
			event:        e,
			destinations: map[uint64]*netflowDest{},
		}
		c.netflows[key] = netflow
	}

	destKey := c.netflowDestKey(&args)
	dest, found := netflow.destinations[destKey]
	if !found {
		dest = &netflowDest{
			addrPort: args.Tuple.Dst,
		}
		netflow.destinations[destKey] = dest
	}

	// Update stats
	dest.txBytes += args.TxBytes
	dest.rxBytes += args.RxBytes
	dest.txPackets += args.TxPackets
	dest.rxPackets += args.RxPackets
}

func (c *Controller) enqueueNetflowExport(now time.Time) {
	for key, netflow := range c.netflows {
		// Flow was exported before and doesn't have new changes. Delete it and continue.
		if netflow.exportedAt.After(netflow.updatedAt) {
			delete(c.netflows, key)
			continue
		}

		args := netflow.event.Args.(types.NetFlowBaseArgs)
		pbNetFlow := c.toProtoNetflow(netflow.event, &args)
		var activeNetflowDests []*netflowDest
		for destKey, dest := range netflow.destinations {
			if dest.empty() {
				// No new data of flow dest. It's not active.
				delete(netflow.destinations, destKey)
				continue
			}
			activeNetflowDests = append(activeNetflowDests, dest)
		}
		pbNetFlow.Destinations = make([]*castpb.NetflowDestination, 0, len(activeNetflowDests))
		for _, dest := range activeNetflowDests {
			flowDest := c.toProtoNetflowDest(
				netflow.event.Context.CgroupID,
				args.Tuple.Src,
				dest.addrPort,
				dest.txBytes,
				dest.rxBytes,
				dest.txPackets,
				dest.rxPackets,
			)
			pbNetFlow.Destinations = append(pbNetFlow.Destinations, flowDest)
		}

		// Enqueue to exporters.
		for _, exp := range c.exporters.Netflow {
			exp.Enqueue(pbNetFlow)
		}
		netflow.exportedAt = now

		// Reset flow stats after export.
		for _, flowDest := range netflow.destinations {
			flowDest.txBytes = 0
			flowDest.rxBytes = 0
			flowDest.txPackets = 0
			flowDest.rxPackets = 0
		}
	}
}

func (c *Controller) netflowKey(e *types.Event, args *types.NetFlowBaseArgs) uint64 {
	c.netflowKeyHash.Reset()

	// Cgroup id.
	var cgroup [8]byte
	binary.LittleEndian.PutUint64(cgroup[:], e.Context.CgroupID)
	_, _ = c.netflowKeyHash.Write(cgroup[:])

	// Pid.
	var pid [4]byte
	binary.LittleEndian.PutUint32(cgroup[:], e.Context.HostPid)
	_, _ = c.netflowKeyHash.Write(pid[:])

	// Source addr+port.
	srcBytes, _ := args.Tuple.Src.MarshalBinary()
	_, _ = c.netflowKeyHash.Write(srcBytes)

	// Protocol.
	_ = c.netflowKeyHash.WriteByte(args.Proto)

	return c.netflowKeyHash.Sum64()
}

func (c *Controller) netflowDestKey(args *types.NetFlowBaseArgs) uint64 {
	c.netflowDestKeyHash.Reset()

	// Destination addr+port.
	srcBytes, _ := args.Tuple.Dst.MarshalBinary()
	_, _ = c.netflowKeyHash.Write(srcBytes)

	return c.netflowKeyHash.Sum64()
}

func (c *Controller) toProtoNetflow(e *types.Event, args *types.NetFlowBaseArgs) *castpb.Netflow {
	ctx := e.Context
	cont := e.Container
	res := &castpb.Netflow{
		Timestamp:     ctx.Ts,
		ProcessName:   string(bytes.TrimRight(ctx.Comm[:], "\x00")),
		Namespace:     cont.PodNamespace,
		PodName:       cont.PodName,
		ContainerName: cont.Name,
		Addr:          args.Tuple.Src.Addr().AsSlice(),
		Port:          uint32(args.Tuple.Src.Port()),
		Protocol:      toProtoProtocol(args.Proto),
	}
	ipInfo, found := c.getPodInfo(cont.PodUID)
	if found {
		res.WorkloadName = ipInfo.WorkloadName
		res.WorkloadKind = ipInfo.WorkloadKind
		res.Zone = ipInfo.Zone
	}
	return res
}

func (c *Controller) toProtoNetflowDest(cgroupID uint64, src, dst netip.AddrPort, txBytes, rxBytes, txPackets, rxPackets uint64) *castpb.NetflowDestination {
	dns := c.getAddrDnsQuestion(cgroupID, dst.Addr())

	if c.clusterInfo.serviceCidr.Contains(dst.Addr()) {
		if realDst, found := c.getConntrackDest(src, dst); found {
			dst = realDst
		}
	}

	res := &castpb.NetflowDestination{
		DnsQuestion: dns,
		Addr:        dst.Addr().AsSlice(),
		Port:        uint32(dst.Port()),
		TxBytes:     txBytes,
		RxBytes:     rxBytes,
		TxPackets:   txPackets,
		RxPackets:   rxPackets,
	}

	if c.clusterInfo.serviceCidr.Contains(dst.Addr()) || c.clusterInfo.podCidr.Contains(dst.Addr()) {
		ipInfo, found := c.getIPInfo(dst.Addr())
		if found {
			res.PodName = ipInfo.PodName
			res.Namespace = ipInfo.Namespace
			res.WorkloadName = ipInfo.WorkloadName
			res.WorkloadKind = ipInfo.WorkloadKind
			res.Zone = ipInfo.Zone
		}
	}
	return res
}

func (c *Controller) getIPInfo(addr netip.Addr) (*kubepb.IPInfo, bool) {
	ipInfo, found := c.ipInfoCache.Get(addr)
	if !found {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := c.kubeClient.GetIPInfo(ctx, &kubepb.GetIPInfoRequest{Ip: addr.Unmap().AsSlice()})
		if err != nil {
			metrics.AgentFetchKubeIPInfoErrorsTotal.Inc()
			return nil, false
		}
		ipInfo = resp.Info
		c.ipInfoCache.Add(addr, ipInfo)
	}
	return ipInfo, true
}

func (c *Controller) getPodInfo(podID string) (*kubepb.Pod, bool) {
	pod, found := c.podCache.Get(podID)
	if !found {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := c.kubeClient.GetPod(ctx, &kubepb.GetPodRequest{Uid: podID})
		if err != nil {
			return nil, false
		}
		pod = resp.Pod
		c.podCache.Add(podID, pod)
	}
	return pod, true
}

func (c *Controller) getConntrackDest(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	realDst, found := c.ctCache.Get(src)
	if !found {
		if realDst, found := c.ct.GetDestination(src, dst); found {
			c.ctCache.Add(src, realDst)
			return realDst, true
		}
		return netip.AddrPort{}, false
	}
	return realDst, true
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
