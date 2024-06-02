package state

import (
	"bytes"
	"context"
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

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e := <-c.tracer.NetflowEvents():
				args := e.Args.(types.NetFlowBaseArgs)
				pbFlow := c.toProtoNetflow(e, &args)
				pbFlowDest := c.toProtoNetflowDest(
					e.Context.CgroupID,
					args.Tuple.Src,
					args.Tuple.Dst,
					args.TxBytes,
					args.RxBytes,
					args.TxPackets,
					args.RxPackets,
				)
				pbFlow.Destinations = []*castpb.NetflowDestination{pbFlowDest}
				c.exportNetflow(pbFlow)
			}
		}
	})
	return errg.Wait()
}

func (c *Controller) exportNetflow(pbNetFlow *castpb.Netflow) {
	for _, exp := range c.exporters.Netflow {
		exp.Enqueue(pbNetFlow)
	}
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
		if realDst, found := c.ct.GetDestination(src, dst); found {
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
