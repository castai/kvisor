package state

import (
	"context"
	"net/netip"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// egressd-compatible metrics
	egressdTransmitBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "egressd_transmit_bytes_total",
		Help: "Total number of bytes transmitted",
	}, []string{
		"cross_zone",
		"dst_dns_name",
		"dst_ip",
		"dst_ip_type",
		"dst_namespace",
		"dst_node",
		"dst_pod",
		"dst_zone",
		"proto",
		"src_ip",
		"src_namespace",
		"src_node",
		"src_pod",
		"src_zone",
	})

	egressdReceivedBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "egressd_received_bytes_total",
		Help: "Total number of bytes received",
	}, []string{
		"cross_zone",
		"dst_dns_name",
		"dst_ip",
		"dst_ip_type",
		"dst_namespace",
		"dst_node",
		"dst_pod",
		"dst_zone",
		"proto",
		"src_ip",
		"src_namespace",
		"src_node",
		"src_pod",
		"src_zone",
	})
)

type PrometheusNetflowExporter struct {
	log         *logging.Logger
	queue       chan *castaipb.Netflow
	customCIDRs []netip.Prefix
}

func NewPrometheusNetflowExporter(log *logging.Logger, queueSize int, customPrivateCIDRs []string) *PrometheusNetflowExporter {
	cidrs := make([]netip.Prefix, 0, len(customPrivateCIDRs))
	for _, cidrStr := range customPrivateCIDRs {
		if prefix, err := netip.ParsePrefix(cidrStr); err == nil {
			cidrs = append(cidrs, prefix)
		}
	}

	return &PrometheusNetflowExporter{
		log:         log.WithField("component", "prometheus_netflow_exporter"),
		queue:       make(chan *castaipb.Netflow, queueSize),
		customCIDRs: cidrs,
	}
}

func (p *PrometheusNetflowExporter) Run(ctx context.Context) error {
	p.log.Info("running export loop")
	defer p.log.Info("export loop done")

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("prometheus_netflow")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("prometheus_netflow")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-p.queue:
			if err := p.exportMetrics(e); err != nil {
				p.log.Errorf("failed to export metrics: %v", err)
				sendErrorMetric.Inc()
				continue
			}
			sendMetric.Inc()
		}
	}
}

func (p *PrometheusNetflowExporter) Enqueue(e *castaipb.Netflow) {
	select {
	case p.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("prometheus_netflow").Inc()
	}
}

func (p *PrometheusNetflowExporter) exportMetrics(e *castaipb.Netflow) error {
	protocol := toDBProtocol(e.Protocol)
	srcIP, _ := netip.AddrFromSlice(e.Addr)
	srcIPStr := "unknown"
	if srcIP.IsValid() {
		srcIPStr = srcIP.String()
	}

	for _, dst := range e.Destinations {
		dstIP, _ := netip.AddrFromSlice(dst.Addr)
		dstIPStr := "unknown"
		if dstIP.IsValid() {
			dstIPStr = dstIP.String()
		}

		dstIPType := "public"
		if isPrivateIP(dstIP, p.customCIDRs...) {
			dstIPType = "private"
		}

		crossZoneValue := "false"
		if e.Zone != dst.Zone && e.Zone != "" && dst.Zone != "" {
			crossZoneValue = "true"
		}

		// TX metrics
		egressdLabels := []string{
			crossZoneValue,
			dst.DnsQuestion,
			dstIPStr,
			dstIPType,
			dst.Namespace,
			dst.NodeName, // Node name from destination pod info
			dst.PodName,
			dst.Zone,
			protocol,
			srcIPStr,
			e.Namespace,
			e.NodeName, // Node name from source
			e.PodName,
			e.Zone,
		}
		egressdTransmitBytesTotal.WithLabelValues(egressdLabels...).Add(float64(dst.TxBytes))

		// RX metrics (swapped source and destination)
		egressdRxLabels := []string{
			crossZoneValue,
			"", // src DNS name becomes dst DNS name
			srcIPStr,
			dstIPType,
			e.Namespace,
			e.NodeName, // Node name from source for RX metrics
			e.PodName,
			e.Zone,
			protocol,
			dstIPStr,
			dst.Namespace,
			dst.NodeName, // Node name from destination for RX metrics
			dst.PodName,
			dst.Zone,
		}
		egressdReceivedBytesTotal.WithLabelValues(egressdRxLabels...).Add(float64(dst.RxBytes))
	}

	return nil
}

// isPrivateIP checks if the given IP is a private address considering both standard private ranges
// and any custom CIDR ranges provided
func isPrivateIP(ip netip.Addr, customCIDRs ...netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}

	// Check standard private ranges first
	if ip.IsPrivate() {
		return true
	}

	// Then check custom CIDR ranges
	for _, cidr := range customCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
