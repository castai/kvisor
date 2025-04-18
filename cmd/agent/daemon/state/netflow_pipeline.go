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

	ticker := time.NewTicker(c.cfg.NetflowExportInterval)
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
				networkSummary, err := c.tracer.CollectNetworkSummary()
				if err != nil {
					c.log.Errorf("error while collecting network traffic summary: %v", err)
					continue
				}
				c.enqueueNetworkSummayExport(ctx, networkSummary)
			}
		}
	})
	return errg.Wait()
}

func (c *Controller) enqueueNetworkSummayExport(ctx context.Context, summary map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary) {
	start := time.Now()
	podsByIPCache := map[netip.Addr]*kubepb.IPInfo{}
	type cgroupID = uint64

	netflows := map[cgroupID]*castpb.Netflow{}

	for key, summary := range summary {
		netflow, found := netflows[key.ProcessIdentity.CgroupId]
		if !found {
			d, err := c.toNetflow(ctx, key, start)
			if err != nil {
				c.log.Errorf("error while parsing netflow destination: %v", err)
				continue
			}

			netflows[key.ProcessIdentity.CgroupId] = d
			netflow = d
		}

		dest, err := c.toNetflowDestination(key, summary, podsByIPCache)
		if err != nil {
			c.log.Errorf("cannot parse netflow destination: %v", err)
			continue
		}

		netflow.Destinations = append(netflow.Destinations, dest)
	}

	for _, n := range netflows {
		// Enqueue to exporters.
		for _, exp := range c.exporters.Netflow {
			exp.Enqueue(n)
		}
	}
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

func (c *Controller) toNetflowDestination(key ebpftracer.TrafficKey, summary ebpftracer.TrafficSummary,
	podsByIPCache map[netip.Addr]*kubepb.IPInfo) (*castpb.NetflowDestination, error) {
	localIP := parseAddr(key.Tuple.Saddr.Raw, key.Tuple.Family)
	if !localIP.IsValid() {
		return nil, fmt.Errorf("got invalid local addr `%v`", key.Tuple.Saddr.Raw)
	}
	local := netip.AddrPortFrom(localIP, key.Tuple.Sport)

	remoteIP := parseAddr(key.Tuple.Daddr.Raw, key.Tuple.Family)
	if !remoteIP.IsValid() {
		return nil, fmt.Errorf("got invalid remote addr `%v`", key.Tuple.Daddr.Raw)
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
	return destination, nil
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
