package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/net/iputil"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
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
		for _, cidr := range resp.PodsCidr {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("parsing pods cidr: %w", err)
			}
			res.podCidr = append(res.podCidr, subnet)
		}
		for _, cidr := range resp.ServiceCidr {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("parsing service cidr: %w", err)
			}
			res.serviceCidr = append(res.serviceCidr, subnet)
		}
		return &res, nil
	}
}

func (c *Controller) runNetflowPipeline(ctx context.Context) error {
	c.log.Info("running netflow pipeline")
	defer c.log.Info("netflow pipeline done")

	// TODO: Now this call will block until error or result is returned.
	// Instead we should consider having periodic refresh loop to call with timeout and
	// refresh. It may also be the case that cluster info changes.
	clusterInfo, err := c.getClusterInfo(ctx)
	if err != nil {
		c.log.Errorf("getting cluster info: %v", err)
	}
	c.clusterInfo = clusterInfo
	if clusterInfo != nil {
		c.log.Infof("fetched cluster info, pod_cidr=%s, service_cidr=%s", clusterInfo.podCidr, clusterInfo.serviceCidr)
	}

	ticker := time.NewTicker(c.cfg.Netflow.ExportInterval)
	defer func() {
		ticker.Stop()
	}()

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				keys, vals, err := c.tracer.CollectNetworkSummary()
				if err != nil {
					c.log.Errorf("error while collecting network traffic summary: %v", err)
					continue
				}
				c.enqueueNetworkSummaryExport(ctx, keys, vals)
			}
		}
	})
	return errg.Wait()

}

type netflowVal struct {
	pb              *castpb.Netflow
	mergeThreshold  int
	mergedDestIndex int
}

func (c *Controller) enqueueNetworkSummaryExport(ctx context.Context, keys []ebpftracer.TrafficKey, vals []ebpftracer.TrafficSummary) {
	start := time.Now()
	podsByIPCache := map[netip.Addr]*kubepb.IPInfo{}

	type cgroupID = uint64
	netflows := map[cgroupID]*netflowVal{}

	for i, key := range keys {
		summary := vals[i]
		netflow, found := netflows[key.ProcessIdentity.CgroupId]
		if !found {
			d, err := c.toNetflow(ctx, key, start)
			if err != nil {
				c.log.Errorf("error while parsing netflow destination: %v", err)
				continue
			}
			val := &netflowVal{pb: d}
			netflows[key.ProcessIdentity.CgroupId] = val
			netflow = val
		}

		dest, isPublicDest, err := c.toNetflowDestination(key, summary, podsByIPCache)
		if err != nil {
			c.log.Errorf("cannot parse netflow destination: %v", err)
			continue
		}

		c.addNetflowDestination(netflow, dest, isPublicDest)
	}

	for _, n := range netflows {
		// Enqueue to exporters.
		for _, exp := range c.exporters.Netflow {
			exp.Enqueue(n.pb)
		}
	}
}

func (c *Controller) addNetflowDestination(netflow *netflowVal, dest *castpb.NetflowDestination, isPublicDest bool) {
	// To reduce cardinality we merge destinations to 0.0.0.0 range if
	// it's a public ip and doesn't have dns domain.
	maybeMerge := isNetflowDestCandidateForMerge(dest, isPublicDest, c.cfg.Netflow.MaxPublicIPs)
	if maybeMerge && netflow.mergeThreshold >= int(c.cfg.Netflow.MaxPublicIPs) {
		if netflow.mergedDestIndex == 0 {
			netflow.pb.Destinations = append(netflow.pb.Destinations, &castpb.NetflowDestination{
				Addr:      []byte{0, 0, 0, 0},
				TxBytes:   dest.TxBytes,
				TxPackets: dest.TxPackets,
				RxBytes:   dest.RxBytes,
				RxPackets: dest.RxPackets,
			})
			netflow.mergedDestIndex = len(netflow.pb.Destinations) - 1
		} else {
			destForMerge := netflow.pb.Destinations[netflow.mergedDestIndex]
			destForMerge.TxBytes += dest.TxBytes
			destForMerge.TxPackets += dest.TxPackets
			destForMerge.RxBytes += dest.RxBytes
			destForMerge.RxPackets += dest.RxPackets
		}
		return
	}

	// No merge, just append to destinations list.
	netflow.pb.Destinations = append(netflow.pb.Destinations, dest)
	if maybeMerge {
		netflow.mergeThreshold++
	}
}

func isNetflowDestCandidateForMerge(dest *castpb.NetflowDestination, isPublic bool, maxPublicIPs int16) bool {
	// No merge for private destinations.
	if !isPublic {
		return false
	}
	// Not merge if there is destination dns context.
	if dest.DnsQuestion != "" {
		return false
	}
	// Not merge if it's disabled.
	if maxPublicIPs == -1 {
		return false
	}
	return true
}

func (c *Controller) toNetflow(ctx context.Context, key ebpftracer.TrafficKey, t time.Time) (*castpb.Netflow, error) {
	res := &castpb.Netflow{
		Timestamp:   uint64(t.UnixNano()), // nolint:gosec
		ProcessName: string(bytes.SplitN(key.ProcessIdentity.Comm[:], []byte{0}, 2)[0]),
		Protocol:    toProtoProtocol(key.Proto),
		// TODO(patrick.pichler): only set local port if it is the listening port. ephemeral ports
		// are not that interesting and  generate a lot of additional data.
		// The main problem right is to figure out which port is the ephemeral and which the listening
		// one. I tried using `sk->state == 0xa`, but this is not working as expected. One way would be
		// to trace the full lifecycle of a socket, but this is rather expensive and would not fully work
		// for already existing sockets.
		Port:     uint32(key.Tuple.Sport),
		NodeName: c.nodeName,
	}

	if key.Tuple.Family == unix.AF_INET {
		res.Addr = key.Tuple.Saddr.Raw[:4]
	} else {
		res.Addr = key.Tuple.Saddr.Raw[:]
	}

	container, err := c.containersClient.GetOrLoadContainerByCgroupID(ctx, key.ProcessIdentity.CgroupId)
	if err != nil && !errors.Is(err, containers.ErrContainerNotFound) {
		return nil, err
	}

	if container != nil {
		res.Namespace = container.PodNamespace
		res.PodName = container.PodName
		res.ContainerName = container.Name

		ipInfo, found := c.getPodInfo(container.PodUID)
		if found {
			res.WorkloadName = ipInfo.WorkloadName
			res.WorkloadKind = workloadKindString(ipInfo.WorkloadKind)
			res.Zone = ipInfo.Zone
			res.NodeName = ipInfo.NodeName
		}
	}

	return res, nil
}

func (c *Controller) toNetflowDestination(key ebpftracer.TrafficKey, summary ebpftracer.TrafficSummary, podsByIPCache map[netip.Addr]*kubepb.IPInfo) (*castpb.NetflowDestination, bool, error) {
	localIP := parseAddr(key.Tuple.Saddr.Raw, key.Tuple.Family)
	if !localIP.IsValid() {
		return nil, false, fmt.Errorf("got invalid local addr `%v`", key.Tuple.Saddr.Raw)
	}
	local := netip.AddrPortFrom(localIP, key.Tuple.Sport)

	remoteIP := parseAddr(key.Tuple.Daddr.Raw, key.Tuple.Family)
	if !remoteIP.IsValid() {
		return nil, false, fmt.Errorf("got invalid remote addr `%v`", key.Tuple.Daddr.Raw)
	}
	remote := netip.AddrPortFrom(remoteIP, key.Tuple.Dport)

	dns := c.getAddrDnsQuestion(key.ProcessIdentity.CgroupId, remote.Addr())

	if c.clusterInfo != nil && c.clusterInfo.serviceCidrContains(remote.Addr()) {
		if realDst, found := c.getConntrackDest(local, remote); found {
			remote = realDst
		}
	}

	destination := &castpb.NetflowDestination{
		DnsQuestion: dns,
		Addr:        remote.Addr().AsSlice(),
		Port:        uint32(remote.Port()),
		TxBytes:     summary.TxBytes,
		RxBytes:     summary.RxBytes,
		TxPackets:   summary.TxPackets,
		RxPackets:   summary.RxPackets,
	}

	if c.clusterInfo != nil && (c.clusterInfo.serviceCidrContains(remote.Addr()) || c.clusterInfo.podCidrContains(remote.Addr())) {
		ipInfo, found := c.getIPInfo(podsByIPCache, remote.Addr())
		if found {
			destination.PodName = ipInfo.PodName
			destination.Namespace = ipInfo.Namespace
			destination.WorkloadName = ipInfo.WorkloadName
			destination.WorkloadKind = ipInfo.WorkloadKind
			destination.Zone = ipInfo.Zone
			destination.NodeName = ipInfo.NodeName
		}
	}

	isPublicDst := !iputil.IsPrivateNetwork(remote.Addr())

	return destination, isPublicDst, nil
}

func parseAddr(data [16]byte, family uint16) netip.Addr {
	switch family {
	case uint16(types.AF_INET):
		return netip.AddrFrom4([4]byte(data[:]))
	case uint16(types.AF_INET6):
		return netip.AddrFrom16(data)
	}

	return netip.Addr{}
}

func (c *Controller) getIPInfo(podsByIPCache map[netip.Addr]*kubepb.IPInfo, addr netip.Addr) (*kubepb.IPInfo, bool) {
	ipInfo, found := podsByIPCache[addr]
	if !found {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := c.kubeClient.GetIPInfo(ctx, &kubepb.GetIPInfoRequest{Ip: addr.Unmap().AsSlice()})
		if err != nil {
			metrics.AgentFetchKubeIPInfoErrorsTotal.Inc()
			return nil, false
		}
		ipInfo = resp.Info
		podsByIPCache[addr] = ipInfo
	}
	return ipInfo, true
}

func (c *Controller) getConntrackDest(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	tpl := types.AddrTuple{Src: src, Dst: dst}
	realDst, found := c.conntrackCache.Get(tpl)
	if !found {
		if realDst, found := c.ct.GetDestination(src, dst); found {
			c.conntrackCache.AddWithLifetime(tpl, realDst, 30*time.Second)
			return realDst, true
		}
		return netip.AddrPort{}, false
	}
	return realDst, true
}

func toProtoProtocol(proto uint8) castpb.NetflowProtocol {
	switch proto {
	case unix.IPPROTO_TCP:
		return castpb.NetflowProtocol_NETFLOW_PROTOCOL_TCP
	case unix.IPPROTO_UDP:
		return castpb.NetflowProtocol_NETFLOW_PROTOCOL_UDP
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
