package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
)

const (
	maxRetries     = 10
	initialBackoff = 2 * time.Second
	maxBackoff     = 1 * time.Minute
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

func (c *Controller) runClusterInfoPipeline(ctx context.Context) {
	c.clusterInfo = newClusterInfo(c.kubeClient, c.log)

	clusterInfoCtx, clusterInfoCancel := context.WithTimeout(ctx, maxBackoff)
	defer clusterInfoCancel()

	// initial sync of cluster CIDRs info
	if err := c.clusterInfo.sync(clusterInfoCtx); err != nil {
		c.log.Errorf("syncing cluster info: %v", err)
	}

	// Start periodic refresh if interval is configured
	// this is needed to keep cluster CIDRs up to date
	if c.cfg.Netflow.ClusterInfoRefreshInterval == 0 {
		return
	}

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

			clusterInfoCtx, clusterInfoCancel := context.WithTimeout(ctx, maxBackoff)
			defer clusterInfoCancel()

			if err := c.clusterInfo.sync(clusterInfoCtx); err != nil {
				c.log.Errorf("syncing cluster info failed: %v, retry in %s", err, c.cfg.Netflow.ClusterInfoRefreshInterval)
			}
		}
	}
}

func newClusterInfo(kubeClient kubepb.KubeAPIClient, log *logging.Logger) *clusterInfo {
	return &clusterInfo{
		kubeClient: kubeClient,
		log:        log,
	}
}

func (c *clusterInfo) sync(ctx context.Context) error {
	var resp *kubepb.GetClusterInfoResponse
	var err error

	backoff := initialBackoff
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// There is no point to refersh cloud CIDRs as they are changed very infrequently
		resp, err = c.kubeClient.GetClusterInfo(ctx, &kubepb.GetClusterInfoRequest{ExcludeOtherCidr: len(c.cloudCidr) > 0})
		if err == nil {
			break
		}

		if attempt < maxRetries {
			c.log.Warnf("getting cluster info (attempt %d/%d): %v, retrying in %v", attempt, maxRetries, err, backoff)

			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		} else {
			return fmt.Errorf("getting cluster info after %d attempts: %w", maxRetries, err)
		}
	}

	var podCidr, serviceCidr, nodeCidr, vpcCidr, cloudCidr, clusterCidr []netip.Prefix

	for _, cidr := range resp.GetPodsCidr() {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.log.Errorf("parsing pods cidr: %v", err)
			continue
		}
		podCidr = append(podCidr, subnet)
		clusterCidr = append(clusterCidr, subnet)
	}
	for _, cidr := range resp.GetServiceCidr() {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.log.Errorf("parsing service cidr: %v", err)
			continue
		}
		serviceCidr = append(serviceCidr, subnet)
		clusterCidr = append(clusterCidr, subnet)
	}
	for _, cidr := range resp.GetNodeCidr() {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.log.Errorf("parsing node cidr: %v", err)
			continue
		}
		nodeCidr = append(nodeCidr, subnet)
		clusterCidr = append(clusterCidr, subnet)
	}
	for _, cidr := range resp.GetVpcCidr() {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.log.Errorf("parsing vpc cidr: %v", err)
			continue
		}
		vpcCidr = append(vpcCidr, subnet)
		clusterCidr = append(clusterCidr, subnet)
	}
	for _, cidr := range resp.GetOtherCidr() {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.log.Errorf("parsing other cidr: %v", err)
			continue
		}
		cloudCidr = append(cloudCidr, subnet)
		clusterCidr = append(clusterCidr, subnet)
	}

	c.mu.Lock()
	c.podCidr = podCidr
	c.serviceCidr = serviceCidr
	c.nodeCidr = nodeCidr
	c.vpcCidr = vpcCidr
	c.clusterCidr = clusterCidr
	if len(cloudCidr) > 0 {
		c.cloudCidr = cloudCidr
	}
	c.log.Infof(
		"fetched cluster info, pod_cidr=%s, service_cidr=%s, node_cidr=%s, vpc_cidr=%s, cloud_cidr_count=%d",
		c.podCidr, c.serviceCidr, c.nodeCidr, c.vpcCidr, len(c.cloudCidr),
	)
	c.mu.Unlock()

	return nil
}

func (c *clusterInfo) cloudCidrContains(ip netip.Addr) bool {
	if c == nil {
		// happens when netflow-check-cluster-network-ranges=false
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cidr := range c.cloudCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) serviceCidrContains(ip netip.Addr) bool {
	if c == nil {
		// happens when netflow-check-cluster-network-ranges=false
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cidr := range c.serviceCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) clusterCidrContains(ip netip.Addr) bool {
	if c == nil {
		// happens when netflow-check-cluster-network-ranges=false
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, cidr := range c.clusterCidr {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
