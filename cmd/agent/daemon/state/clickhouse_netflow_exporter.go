package state

import (
	"context"
	"net/netip"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
)

func NewClickhouseNetflowExporter(log *logging.Logger, conn clickhouse.Conn, queueSize int) *ClickHouseNetflowExporter {
	return &ClickHouseNetflowExporter{
		log:   log.WithField("component", "clickhouse_netflow_exporter"),
		conn:  conn,
		queue: make(chan *castaipb.Netflow, queueSize),
	}
}

type ClickHouseNetflowExporter struct {
	log   *logging.Logger
	conn  clickhouse.Conn
	queue chan *castaipb.Netflow
}

func (c *ClickHouseNetflowExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("clickhouse_netflow")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("clickhouse_netflow")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			if err := c.asyncWrite(ctx, false, e); err != nil {
				sendErrorMetric.Inc()
				continue
			}
			sendMetric.Inc()
		}
	}
}

func (c *ClickHouseNetflowExporter) Enqueue(e *castaipb.Netflow) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("clickhouse_netflow").Inc()
	}
}

func (c *ClickHouseNetflowExporter) asyncWrite(ctx context.Context, wait bool, e *castaipb.Netflow) error {
	q := `INSERT INTO netflows(
			start,
			end,
			protocol,
			process,
			container_name,
			pod_name,
			namespace,
			zone,
			workload_name,
			workload_kind,
			addr,
			port,
			dst_addr,
			dst_port,
			dst_domain,
			dst_pod_name,
			dst_namespace,
			dst_zone,
			dst_workload_name,
			dst_workload_kind,
			tx_bytes,
			tx_packets,
			rx_bytes,
			rx_packets
			) VALUES(
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?,
			?
			)`

	for _, dst := range e.Destinations {
		srcAddr, _ := netip.AddrFromSlice(e.Addr)
		dstAddr, _ := netip.AddrFromSlice(dst.Addr)

		if err := c.conn.AsyncInsert(
			ctx,
			q,
			wait,

			time.UnixMicro(int64(e.StartTs)/1000),
			time.UnixMicro(int64(e.EndTs)/1000),
			toDBProtocol(e.Protocol),
			e.ProcessName,
			e.ContainerName,
			e.PodName,
			e.Namespace,
			e.Zone,
			e.WorkloadName,
			e.WorkloadKind,
			srcAddr.Unmap(),
			e.Port,
			dstAddr.Unmap(),
			dst.Port,
			dst.DnsQuestion,
			dst.PodName,
			dst.Namespace,
			dst.Zone,
			dst.WorkloadName,
			dst.WorkloadKind,
			dst.TxBytes,
			dst.TxPackets,
			dst.RxBytes,
			dst.RxPackets,
		); err != nil {
			return err
		}
	}
	return nil
}

func toDBProtocol(proto castaipb.NetflowProtocol) string {
	switch proto {
	case castaipb.NetflowProtocol_NETFLOW_PROTOCOL_TCP:
		return "tcp"
	case castaipb.NetflowProtocol_NETFLOW_PROTOCOL_UDP:
		return "udp"
	default:
		return "unknown"
	}
}

func ClickhouseNetflowSchema() string {
	return `
CREATE TABLE IF NOT EXISTS netflows
(
	start DateTime('UTC'),
	end DateTime('UTC'),
	protocol LowCardinality(String),
	process LowCardinality(String),
	container_name LowCardinality(String),
	pod_name LowCardinality(String),
	namespace LowCardinality(String),
	zone LowCardinality(String),
	workload_name LowCardinality(String),
	workload_kind LowCardinality(String),
	addr IPv6,
	port UInt16,
	dst_addr IPv6,
	dst_port UInt16,
	dst_domain String,
	dst_pod_name LowCardinality(String),
	dst_namespace LowCardinality(String),
	dst_zone LowCardinality(String),
	dst_workload_name LowCardinality(String),
	dst_workload_kind LowCardinality(String),
	tx_bytes UInt64,
	tx_packets UInt64,
	rx_bytes UInt64,
	rx_packets UInt64
)
ENGINE = MergeTree()
ORDER BY (start, end, namespace, container_name)
TTL toDateTime(start) + INTERVAL 3 HOUR;
`
}
