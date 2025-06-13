package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/logging"
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

var netflowInsertQuery = newInsertQueryTemplate(tableConfig{
	name: "netflows",
	columns: []string{
		"ts",
		"protocol",
		"process",
		"container_name",
		"pod_name",
		"namespace",
		"zone",
		"workload_name",
		"workload_kind",
		"addr",
		"port",
		"dst_addr",
		"dst_port",
		"dst_domain",
		"dst_pod_name",
		"dst_namespace",
		"dst_zone",
		"dst_workload_name",
		"dst_workload_kind",
		"tx_bytes",
		"tx_packets",
		"rx_bytes",
		"rx_packets",
	},
})

func (c *ClickHouseNetflowExporter) asyncWrite(ctx context.Context, wait bool, e *castaipb.Netflow) error {
	for _, dst := range e.Destinations {
		srcAddr, _ := netip.AddrFromSlice(e.Addr)
		dstAddr, _ := netip.AddrFromSlice(dst.Addr)

		if err := c.conn.AsyncInsert(
			ctx,
			netflowInsertQuery,
			wait,

			time.UnixMicro(int64(e.Timestamp)/1000), // nolint:gosec
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
	ts DateTime('UTC'),
	protocol Enum('tcp' = 1, 'udp' = 2, 'unknown' = 3),
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
ORDER BY (ts, namespace, container_name)
TTL toDateTime(ts) + INTERVAL 3 HOUR;
`
}

type tableConfig struct {
	name    string
	columns []string
}

func newInsertQueryTemplate(t tableConfig) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("INSERT INTO %s", t.name))
	buf.WriteString(" (")
	for i, c := range t.columns {
		buf.WriteString(c)
		if i != len(t.columns)-1 {
			buf.WriteString(",")
		}
	}
	buf.WriteString(" )")
	buf.WriteString(" VALUES (")
	for i := range t.columns {
		buf.WriteString("?")
		if i != len(t.columns)-1 {
			buf.WriteString(",")
		}
	}
	buf.WriteString(")")
	return buf.String()
}
