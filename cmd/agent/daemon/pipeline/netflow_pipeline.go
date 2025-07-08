package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/net/iputil"
	"github.com/cespare/xxhash/v2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type clusterInfo struct {
	podCidr     []netip.Prefix
	serviceCidr []netip.Prefix
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

	if c.cfg.Netflow.CheckClusterNetworkRanges {
		clusterInfoCtx, clusterInfoCancel := context.WithTimeout(ctx, time.Second*60)
		defer clusterInfoCancel()
		clusterInfo, err := c.getClusterInfo(clusterInfoCtx)
		if err != nil {
			c.log.Errorf("getting cluster info: %v", err)
		}
		c.clusterInfo = clusterInfo
		if clusterInfo != nil {
			c.log.Infof("fetched cluster info, pod_cidr=%s, service_cidr=%s", clusterInfo.podCidr, clusterInfo.serviceCidr)
		}
	}

	groups := map[uint64]*netflowGroup{} // TODO: Consider reusing groups similar to events and container stats.
	netflowGroupKeyDigest := xxhash.New()
	stats := newDataBatchStats()

	send := func(reason string) {
		items := make([]*castaipb.DataBatchItem, 0, stats.totalItems)
		for _, group := range groups {
			if len(group.flows) == 0 {
				continue
			}
			for _, flow := range group.flows {
				if len(flow.pb.Destinations) == 0 {
					continue
				}
				items = append(items, &castaipb.DataBatchItem{
					Data: &castaipb.DataBatchItem_Netflow{Netflow: flow.pb},
				})
			}
		}
		c.sendDataBatch(reason, metrics.PipelineNetflows, items)

		// Reset after sent.
		stats.reset()
		groups = map[uint64]*netflowGroup{}
	}

	ticker := time.NewTicker(c.cfg.Netflow.ExportInterval)
	defer func() {
		ticker.Stop()
	}()

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
			c.handleNetflows(ctx, groups, stats, netflowGroupKeyDigest, keys, vals)
			send("netflows collected")
		}
	}
}

type netflowGroup struct {
	flows map[uint64]*netflowVal
}

type netflowVal struct {
	pb              *castaipb.Netflow
	mergeThreshold  int
	mergedDestIndex int
	updatedAt       time.Time
}

func newNetflowKey(digest *xxhash.Digest, key *ebpftracer.TrafficKey) uint64 {
	digest.Reset()
	digestAddUint64(digest, key.ProcessIdentity.PidStartTime)
	digestAddUint32(digest, key.ProcessIdentity.Pid)
	return digest.Sum64()
}

func digestAddUint32(digest *xxhash.Digest, val uint32) {
	var dst [4]byte
	binary.LittleEndian.PutUint32(dst[:], val)
	_, _ = digest.Write(dst[:])
}

func digestAddUint64(digest *xxhash.Digest, val uint64) {
	var dst [8]byte
	binary.LittleEndian.PutUint64(dst[:], val)
	_, _ = digest.Write(dst[:])
}

func (c *Controller) handleNetflows(ctx context.Context, groups map[uint64]*netflowGroup, stats *dataBatchStats, digest *xxhash.Digest, keys []ebpftracer.TrafficKey, vals []ebpftracer.TrafficSummary) {
	c.log.Infof("handling netflows, total=%v", len(keys))

	start := time.Now()
	// TODO: This could potentially return incorrect pods info. We may need to have timestamps in the key.
	podsByIPCache := map[netip.Addr]*kubepb.IPInfo{}

	for i, key := range keys {
		summary := vals[i]
		group, found := groups[key.ProcessIdentity.CgroupId]
		if !found {
			group = &netflowGroup{
				flows: make(map[uint64]*netflowVal),
			}
			groups[key.ProcessIdentity.CgroupId] = group
		}

		netflowKey := newNetflowKey(digest, &key)
		netflow, found := group.flows[netflowKey]
		if !found {
			d, err := c.toNetflow(ctx, key, start)
			if err != nil {
				c.log.Errorf("error while parsing netflow destination: %v", err)
				continue
			}
			val := &netflowVal{
				pb:        d,
				updatedAt: time.Now(),
			}
			group.flows[netflowKey] = val
			netflow = val
			stats.totalItems++
		}

		dest, isPublicDest, err := c.toNetflowDestination(key, summary, podsByIPCache)
		if err != nil {
			c.log.Errorf("cannot parse netflow destination: %v", err)
			continue
		}

		c.addNetflowDestination(netflow, dest, isPublicDest)
		stats.sizeBytes += proto.Size(dest)
	}
}

func (c *Controller) addNetflowDestination(netflow *netflowVal, dest *castaipb.NetflowDestination, isPublicDest bool) {
	netflow.updatedAt = time.Now()
	// To reduce cardinality we merge destinations to 0.0.0.0 range if
	// it's a public ip and doesn't have dns domain.
	maybeMerge := isNetflowDestCandidateForMerge(dest, isPublicDest, c.cfg.Netflow.MaxPublicIPs)
	if maybeMerge && netflow.mergeThreshold >= int(c.cfg.Netflow.MaxPublicIPs) {
		if netflow.mergedDestIndex == 0 {
			netflow.pb.Destinations = append(netflow.pb.Destinations, &castaipb.NetflowDestination{
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

func isNetflowDestCandidateForMerge(dest *castaipb.NetflowDestination, isPublic bool, maxPublicIPs int16) bool {
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

func (c *Controller) toNetflow(ctx context.Context, key ebpftracer.TrafficKey, t time.Time) (*castaipb.Netflow, error) {
	res := &castaipb.Netflow{
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
		Pid:      key.ProcessIdentity.Pid,
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

func (c *Controller) toNetflowDestination(key ebpftracer.TrafficKey, summary ebpftracer.TrafficSummary, podsByIPCache map[netip.Addr]*kubepb.IPInfo) (*castaipb.NetflowDestination, bool, error) {
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

	if (c.clusterInfo != nil && c.clusterInfo.serviceCidrContains(remote.Addr())) || !c.cfg.Netflow.CheckClusterNetworkRanges {
		if realDst, found := c.getConntrackDest(local, remote); found {
			remote = realDst
		}
	}

	destination := &castaipb.NetflowDestination{
		DnsQuestion: dns,
		Addr:        remote.Addr().AsSlice(),
		Port:        uint32(remote.Port()),
		TxBytes:     summary.TxBytes,
		RxBytes:     summary.RxBytes,
		TxPackets:   summary.TxPackets,
		RxPackets:   summary.RxPackets,
	}

	if (c.clusterInfo != nil && (c.clusterInfo.serviceCidrContains(remote.Addr()) || c.clusterInfo.podCidrContains(remote.Addr()))) || !c.cfg.Netflow.CheckClusterNetworkRanges {
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

func (c *clusterInfo) podCidrContains(ip netip.Addr) bool {
	for _, cidr := range c.podCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) serviceCidrContains(ip netip.Addr) bool {
	for _, cidr := range c.serviceCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func toProtoProtocol(proto uint8) castaipb.NetflowProtocol {
	switch proto {
	case unix.IPPROTO_TCP:
		return castaipb.NetflowProtocol_NETFLOW_PROTOCOL_TCP
	case unix.IPPROTO_UDP:
		return castaipb.NetflowProtocol_NETFLOW_PROTOCOL_UDP
	default:
		return castaipb.NetflowProtocol_NETFLOW_PROTOCOL_UNKNOWN
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
