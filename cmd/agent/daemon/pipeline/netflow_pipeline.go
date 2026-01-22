package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cloudprovider"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/net/iputil"
	"github.com/cespare/xxhash/v2"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/protobuf/proto"
)

type clusterInfo struct {
	mu          sync.RWMutex
	kubeClient  kubepb.KubeAPIClient
	log         *logging.Logger
	podCidr     []netip.Prefix
	serviceCidr []netip.Prefix
	nodeCidr    []netip.Prefix
	vpcCidr     []netip.Prefix
	cloudCidr   []netip.Prefix
	clusterCidr []netip.Prefix
}

func NewClusterInfo(kubeClient kubepb.KubeAPIClient, log *logging.Logger) *clusterInfo {
	return &clusterInfo{
		kubeClient: kubeClient,
		log:        log,
	}
}

func (c *clusterInfo) sync(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := c.kubeClient.GetClusterInfo(ctx, &kubepb.GetClusterInfoRequest{})
		if err != nil {
			c.log.Warnf("getting cluster info: %v", err)
			sleep(ctx, 2*time.Second)
			continue
		}

		var podCidr, serviceCidr, nodeCidr, vpcCidr, cloudCidr, clusterCidr []netip.Prefix

		for _, cidr := range resp.GetPodsCidr() {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("parsing pods cidr: %w", err)
			}
			podCidr = append(podCidr, subnet)
			clusterCidr = append(clusterCidr, subnet)
		}
		for _, cidr := range resp.GetServiceCidr() {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("parsing service cidr: %w", err)
			}
			serviceCidr = append(serviceCidr, subnet)
			clusterCidr = append(clusterCidr, subnet)
		}
		for _, cidr := range resp.GetNodeCidr() {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("parsing node cidr: %w", err)
			}
			nodeCidr = append(nodeCidr, subnet)
			clusterCidr = append(clusterCidr, subnet)
		}
		for _, cidr := range resp.GetVpcCidr() {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("parsing vpc cidr: %w", err)
			}
			vpcCidr = append(vpcCidr, subnet)
			clusterCidr = append(clusterCidr, subnet)
		}
		for _, cidr := range resp.GetOtherCidr() {
			subnet, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("parsing other cidr: %w", err)
			}
			cloudCidr = append(cloudCidr, subnet)
			clusterCidr = append(clusterCidr, subnet)
		}

		// Update internal state with lock
		c.mu.Lock()
		c.podCidr = podCidr
		c.serviceCidr = serviceCidr
		c.nodeCidr = nodeCidr
		c.vpcCidr = vpcCidr
		c.cloudCidr = cloudCidr
		c.clusterCidr = clusterCidr
		c.log.Infof(
			"fetched cluster info, pod_cidr=%s, service_cidr=%s, node_cidr=%s, vpc_cidr=%s, cloud_cidr=%s",
			c.podCidr, c.serviceCidr, c.nodeCidr, c.vpcCidr, c.cloudCidr,
		)
		c.mu.Unlock()

		return nil
	}
}

func (c *Controller) runNetflowPipeline(ctx context.Context) error {
	c.log.Info("running netflow pipeline")
	defer c.log.Info("netflow pipeline done")

	// Initialize and fetch cluster info periodically if enabled
	if c.cfg.Netflow.CheckClusterNetworkRanges {
		c.clusterInfo = NewClusterInfo(c.kubeClient, c.log)

		c.refreshClusterInfoOnce(ctx)

		// Start periodic refresh if interval is configured
		// this is needed to keep cluster CIDRs up to date
		if c.cfg.Netflow.ClusterInfoRefreshInterval > 0 {
			go c.runClusterInfoRefreshLoop(ctx)
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
		// Skip if no changes.
		if len(items) == 0 {
			return
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
			// TODO: Netflows export currently doesn't use max data batch size.
			// In the feature we may need to send partial collected netflows.
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

func (c *Controller) handleNetflows(
	ctx context.Context,
	groups map[uint64]*netflowGroup,
	stats *dataBatchStats,
	digest *xxhash.Digest,
	keys []ebpftracer.TrafficKey,
	vals []ebpftracer.TrafficSummary,
) {
	c.log.Debugf("handling netflows, total=%v", len(keys))

	start := time.Now()
	kubeDestinations := map[netip.Addr]struct{}{}

	var foundContainerdConnectErrors bool
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
			netflowPb, err := c.toNetflow(ctx, &key, &summary, start)
			if err != nil {
				// TODO: Investigate why containerd connect fails for some clusters. Most likely sock is in a different path.
				if strings.Contains(err.Error(), "/run/containerd/containerd.sock: connect: connection refused") {
					foundContainerdConnectErrors = true
					continue
				}
				c.log.Errorf("creating netflow: %v", err)
				continue
			}
			val := &netflowVal{
				pb:        netflowPb,
				updatedAt: time.Now(),
			}
			group.flows[netflowKey] = val
			netflow = val
			stats.totalItems++
		}

		dest, destAddr, err := c.toNetflowDestination(key, summary)
		if err != nil {
			c.log.Errorf("cannot parse netflow destination: %v", err)
			continue
		}

		if (c.clusterInfo != nil && c.clusterInfo.clusterCidrContains(destAddr)) || !c.cfg.Netflow.CheckClusterNetworkRanges {
			kubeDestinations[destAddr] = struct{}{}
		}

		c.addNetflowDestination(netflow, dest, destAddr)
		stats.sizeBytes += proto.Size(dest)
	}

	if len(kubeDestinations) > 0 {
		c.enrichKubeDestinations(ctx, groups, kubeDestinations)
	}

	if foundContainerdConnectErrors {
		c.log.Error("found containerd connect errors in netflow pipeline")
	}
}

func (c *Controller) enrichKubeDestinations(ctx context.Context, groups map[uint64]*netflowGroup, ips map[netip.Addr]struct{}) {
	req := &kubepb.GetIPsInfoRequest{
		Ips: make([][]byte, 0, len(ips)),
	}
	for ip := range ips {
		req.Ips = append(req.Ips, ip.AsSlice())
	}
	resp, err := c.kubeClient.GetIPsInfo(ctx, req, grpc.UseCompressor(gzip.Name))
	if err != nil {
		c.log.Errorf("getting ips info: %v", err)
		return
	}
	respIpsLookup := make(map[netip.Addr]*kubepb.IPInfo, len(resp.List))
	for _, info := range resp.List {
		addr, ok := netip.AddrFromSlice(info.GetIp())
		if !ok {
			continue
		}
		respIpsLookup[addr] = info
	}

	if len(respIpsLookup) == 0 {
		return
	}

	for _, group := range groups {
		for _, flow := range group.flows {
			for _, flowDest := range flow.pb.Destinations {
				destIP, ok := netip.AddrFromSlice(flowDest.Addr)
				if !ok {
					continue
				}
				if info, found := respIpsLookup[destIP]; found {
					flowDest.PodName = info.PodName
					flowDest.Namespace = info.Namespace
					flowDest.WorkloadName = info.WorkloadName
					flowDest.WorkloadKind = info.WorkloadKind
					flowDest.Zone = info.Zone
					flowDest.Region = info.Region
					flowDest.NodeName = info.NodeName

					// CloudDomain will be non empty if this is flow within cloud traffic
					if info.CloudDomain != "" {
						// set cloud domain as dns question when it's empty
						// i.e. googleapis.com or amazonaws.com
						if flowDest.DnsQuestion == "" {
							flowDest.DnsQuestion = info.CloudDomain
						}

						// Set cloud as kind and type as workload name for cloud IPs
						flowDest.WorkloadName = cloudprovider.DomainToProviderType(info.CloudDomain)
						flowDest.WorkloadKind = "cloud"
					}
				}
			}
		}
	}
}

func (c *Controller) addNetflowDestination(netflow *netflowVal, dest *castaipb.NetflowDestination, destAddr netip.Addr) {
	isPublicDest := !iputil.IsPrivateNetwork(destAddr)
	netflow.updatedAt = time.Now()

	var isCloudDest bool
	if c.clusterInfo != nil {
		isCloudDest = c.clusterInfo.cloudCidrContains(destAddr)
	}

	// To reduce cardinality we merge destinations to 0.0.0.0 range if
	// it's a public ip and doesn't have dns domain.
	maybeMerge := isNetflowDestCandidateForMerge(dest, isPublicDest, isCloudDest, c.cfg.Netflow.MaxPublicIPs)
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

	// If destination zone is unknown but IP is local network (loopback, link-local),
	// then destination must be on same zone/region
	if !isPublicDest && dest.Zone == "" && iputil.IsLocalNetwork(destAddr) {
		dest.Zone = netflow.pb.Zone
		dest.Region = netflow.pb.Region
	}

	// No merge, just append to destinations list.
	netflow.pb.Destinations = append(netflow.pb.Destinations, dest)
	if maybeMerge {
		netflow.mergeThreshold++
	}
}

func isNetflowDestCandidateForMerge(
	dest *castaipb.NetflowDestination,
	isPublic bool,
	isCloud bool,
	maxPublicIPs int16,
) bool {
	// No merge for private destinations.
	if !isPublic {
		return false
	}

	// No merge for cloud destinations.
	if isCloud {
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

func (c *Controller) toNetflow(ctx context.Context, key *ebpftracer.TrafficKey, val *ebpftracer.TrafficSummary, t time.Time) (*castaipb.Netflow, error) {
	res := &castaipb.Netflow{
		Timestamp:   uint64(t.UnixNano()), // nolint:gosec
		ProcessName: string(bytes.SplitN(val.Comm[:], []byte{0}, 2)[0]),
		Protocol:    toProtoProtocol(key.Proto),
		// TODO(patrick.pichler): only set local port if it is the listening port. ephemeral ports
		// are not that interesting and  generate a lot of additional data.
		// The main problem right is to figure out which port is the ephemeral and which the listening
		// one. I tried using `sk->state == 0xa`, but this is not working as expected. One way would be
		// to trace the full lifecycle of a socket, but this is rather expensive and would not fully work
		// for already existing sockets.
		Port:             uint32(key.Tuple.Sport),
		NodeName:         c.nodeName,
		Pid:              key.ProcessIdentity.Pid,
		ProcessStartTime: key.ProcessIdentity.PidStartTime,
	}

	if key.Tuple.Family == unix.AF_INET {
		res.Addr = key.Tuple.Saddr.Raw[:4]
	} else {
		res.Addr = key.Tuple.Saddr.Raw[:]
	}

	container, err := c.containersClient.GetOrLoadContainerByCgroupID(ctx, key.ProcessIdentity.CgroupId)
	if err != nil && !errors.Is(err, containers.ErrContainerNotFound) {
		return nil, fmt.Errorf("getting container: %w", err)
	}

	if container != nil {
		res.Namespace = container.PodNamespace
		res.PodName = container.PodName
		res.ContainerName = container.Name

		podInfo, found := c.getPodInfo(container.PodUID)
		if found {
			res.WorkloadName = podInfo.WorkloadName
			res.WorkloadKind = workloadKindString(podInfo.WorkloadKind)
			res.Zone = podInfo.Zone
			res.Region = podInfo.Region
			res.NodeName = podInfo.NodeName
		}
	}

	// in case when pod info is not found we still can get AZ info from node
	if res.Zone == "" || res.Region == "" {
		if nodeInfo, found := c.getNodeInfo(res.NodeName); found {
			if res.Zone == "" {
				res.Zone = getZone(nodeInfo)
			}
			if res.Region == "" {
				res.Region = getRegion(nodeInfo)
			}
		}
	}

	return res, nil
}

func (c *Controller) toNetflowDestination(key ebpftracer.TrafficKey, summary ebpftracer.TrafficSummary) (*castaipb.NetflowDestination, netip.Addr, error) {
	localIP := parseAddr(key.Tuple.Saddr.Raw, key.Tuple.Family)
	if !localIP.IsValid() {
		return nil, netip.Addr{}, fmt.Errorf("got invalid local addr `%v`", key.Tuple.Saddr.Raw)
	}
	local := netip.AddrPortFrom(localIP, key.Tuple.Sport)

	remoteIP := parseAddr(key.Tuple.Daddr.Raw, key.Tuple.Family)
	if !remoteIP.IsValid() {
		return nil, netip.Addr{}, fmt.Errorf("got invalid remote addr `%v`", key.Tuple.Daddr.Raw)
	}
	remote := netip.AddrPortFrom(remoteIP, key.Tuple.Dport)

	dns := c.tracer.GetDNSNameFromCache(key.ProcessIdentity.CgroupId, remote.Addr())

	if (c.clusterInfo != nil && c.clusterInfo.serviceCidrContains(remote.Addr())) || !c.cfg.Netflow.CheckClusterNetworkRanges {
		if realDst, found := c.getConntrackDest(local, remote); found {
			remote = realDst
		}
	}

	flowKind := "private"
	if iputil.IsPublicNetwork(remote.Addr()) {
		flowKind = "internet"
	}

	destination := &castaipb.NetflowDestination{
		DnsQuestion: dns,
		Addr:        remote.Addr().AsSlice(),
		Port:        uint32(remote.Port()),
		TxBytes:     summary.TxBytes,
		RxBytes:     summary.RxBytes,
		TxPackets:   summary.TxPackets,
		RxPackets:   summary.RxPackets,

		// Mark workload kind as private or internet,
		// but it later could be overriden by IP info from kube client
		// within `enrichKubeDestinations` method
		WorkloadKind: flowKind,
	}

	return destination, remote.Addr(), nil
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

func (c *clusterInfo) cloudCidrContains(ip netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cidr := range c.cloudCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) clusterCidrContains(ip netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cidr := range c.clusterCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) serviceCidrContains(ip netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
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

// refreshClusterInfoOnce fetches cluster info once and updates internal state
func (c *Controller) refreshClusterInfoOnce(ctx context.Context) {
	if c.clusterInfo == nil {
		c.log.Warn("clusterInfo not initialized, skipping refresh")
		return
	}

	clusterInfoCtx, clusterInfoCancel := context.WithTimeout(ctx, time.Second*10)
	defer clusterInfoCancel()

	if err := c.clusterInfo.sync(clusterInfoCtx); err != nil {
		c.log.Errorf("syncing cluster info: %v", err)
		return
	}
}

// runClusterInfoRefreshLoop periodically refreshes cluster info in the background
func (c *Controller) runClusterInfoRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Netflow.ClusterInfoRefreshInterval)
	defer ticker.Stop()

	c.log.Infof("starting cluster info refresh with interval %s", c.cfg.Netflow.ClusterInfoRefreshInterval)

	for {
		select {
		case <-ctx.Done():
			c.log.Info("stopping cluster info refresh")
			return
		case <-ticker.C:
			c.log.Debug("refreshing cluster info")
			c.refreshClusterInfoOnce(ctx)
		}
	}
}
