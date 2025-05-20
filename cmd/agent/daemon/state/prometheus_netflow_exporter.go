package state

import (
	"context"
	"net/netip"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	netflowBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_netflow_bytes_total",
		Help: "Total number of bytes transferred in netflow connections",
	}, []string{"direction", "namespace", "pod_name", "container_name", "workload_name", "workload_kind", "protocol", "dst_namespace", "dst_pod_name"})

	netflowPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_netflow_packets_total",
		Help: "Total number of packets transferred in netflow connections",
	}, []string{"direction", "namespace", "pod_name", "container_name", "workload_name", "workload_kind", "protocol", "dst_namespace", "dst_pod_name"})

	activeConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kvisor_netflow_active_connections",
		Help: "Number of active netflow connections",
	}, []string{"namespace", "pod_name", "container_name", "workload_name", "workload_kind", "protocol"})
)

func NewPrometheusNetflowExporter(log *logging.Logger, queueSize int, cleanupInterval time.Duration) *PrometheusNetflowExporter {
	return &PrometheusNetflowExporter{
		log:             log.WithField("component", "prometheus_netflow_exporter"),
		queue:           make(chan *castaipb.Netflow, queueSize),
		cleanupInterval: cleanupInterval,
		activeConns:     make(map[string]time.Time),
		activeConnMutex: &sync.RWMutex{},
	}
}

type PrometheusNetflowExporter struct {
	log             *logging.Logger
	queue           chan *castaipb.Netflow
	cleanupInterval time.Duration
	activeConns     map[string]time.Time
	activeConnMutex *sync.RWMutex
}

func (p *PrometheusNetflowExporter) Run(ctx context.Context) error {
	p.log.Info("running export loop")
	defer p.log.Info("export loop done")

	cleanupTicker := time.NewTicker(p.cleanupInterval)
	defer cleanupTicker.Stop()

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("prometheus_netflow")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("prometheus_netflow")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-cleanupTicker.C:
			p.cleanupStaleConnections()
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
	labels := []string{
		e.Namespace,
		e.PodName,
		e.ContainerName,
		e.WorkloadName,
		e.WorkloadKind,
		protocol,
	}

	activeConnections.WithLabelValues(labels...).Inc()
	p.updateActiveConnection(e)

	for _, dst := range e.Destinations {
		netflowLabels := append([]string{"tx"},
			e.Namespace,
			e.PodName,
			e.ContainerName,
			e.WorkloadName,
			e.WorkloadKind,
			protocol,
			dst.Namespace,
			dst.PodName,
		)
		netflowBytesTotal.WithLabelValues(netflowLabels...).Add(float64(dst.TxBytes))
		netflowPacketsTotal.WithLabelValues(netflowLabels...).Add(float64(dst.TxPackets))

		// RX metrics
		netflowLabels[0] = "rx"
		netflowBytesTotal.WithLabelValues(netflowLabels...).Add(float64(dst.RxBytes))
		netflowPacketsTotal.WithLabelValues(netflowLabels...).Add(float64(dst.RxPackets))
	}

	return nil
}

func (p *PrometheusNetflowExporter) updateActiveConnection(e *castaipb.Netflow) {
	p.activeConnMutex.Lock()
	defer p.activeConnMutex.Unlock()

	// Create a unique connection identifier
	addr, _ := netip.AddrFromSlice(e.Addr)
	connID := addr.String()
	p.activeConns[connID] = time.Now()
}

func (p *PrometheusNetflowExporter) cleanupStaleConnections() {
	p.activeConnMutex.Lock()
	defer p.activeConnMutex.Unlock()

	threshold := time.Now().Add(-p.cleanupInterval)
	for connID, lastSeen := range p.activeConns {
		if lastSeen.Before(threshold) {
			delete(p.activeConns, connID)
			// Decrement the active connections gauge for the connection that's no longer active
			activeConnections.DeleteLabelValues(connID)
		}
	}
}
