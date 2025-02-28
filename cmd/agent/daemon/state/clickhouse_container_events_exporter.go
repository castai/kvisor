package state

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/google/uuid"
)

const (
	clickhouseContainerEventsLabel      = "clickhouse_container_events"
	clickhouseContainerEventsGroupLabel = "clickhouse_container_events_group"
)

type Event struct {
	// Base event field.
	TS               time.Time `ch:"ts"`
	OrganizationID   uuid.UUID `ch:"organization_id"`
	ClusterID        uuid.UUID `ch:"cluster_id"`
	Name             string    `ch:"name"`
	Process          string    `ch:"process"`
	ProcessPid       uint32    `ch:"process_pid"`
	ProcessStartTime uint64    `ch:"process_start_time"`
	CgroupID         uint64    `ch:"cgroup_id"`
	HostPid          uint32    `ch:"host_pid"`

	// Kubernetes context fields.
	Namespace         string            `ch:"namespace"`
	WorkloadID        uuid.UUID         `ch:"workload_id"` // Point to last known pod owner or pod uid.
	PodName           string            `ch:"pod_name"`
	ContainerName     string            `ch:"container_name"`
	ContainerID       string            `ch:"container_id"`
	NodeName          string            `ch:"node_name"`
	ObjectLabels      map[string]string `ch:"object_labels"`
	ObjectAnnotations map[string]string `ch:"object_annotations"`

	// Network fields.
	DstIP       netip.Addr `ch:"dst_ip"`
	DstPort     uint16     `ch:"dst_port"`
	DstDomain   string     `ch:"dst_domain"`
	DstIPPublic bool       `ch:"dst_ip_public"`

	FlowDirection castpb.FlowDirection `ch:"flow_direction"`

	// DNS related fields.
	DNSQuestionDomain  string   `ch:"dns_question_domain"`
	DNSAnswerIPPublic  []net.IP `ch:"dns_answer_ip_public"`
	DNSAnswerIPPrivate []net.IP `ch:"dns_answer_ip_private"`
	DNSAnswerCname     []string `ch:"dns_answer_cname"`

	// Exec and file fields.
	FilePath       string   `ch:"file_path"`
	Args           []string `ch:"args"`
	ExecHashSha256 [32]byte `ch:"exec_hash_sha256"`

	// Signature related fields.
	Fd int32 `ch:"fd"`

	// SOCKS5 related fields
	SOCKS5Role        castpb.SOCKS5Role        `ch:"socks5_role"`
	SOCKS5CmdOrReply  uint8                    `ch:"socks5_cmd_or_reply"`
	SOCKS5AddressType castpb.SOCKS5AddressType `ch:"socks5_address_type"`

	// PayloadDigest is used to calculate digest for event payload.
	// For example exec file_path and args are hashed.
	// This allows to simplify events query grouping.
	PayloadDigest uint64 `ch:"payload_digest"`

	// Reusable field to hold flags any event.
	Flags uint64 `ch:"flags"`
}

type ClickhouseContainerEventsExporter struct {
	log  *logging.Logger
	conn clickhouse.Conn
}

func NewClickhouseContainerEventsExporter(log *logging.Logger, conn clickhouse.Conn) *ClickhouseContainerEventsExporter {
	return &ClickhouseContainerEventsExporter{
		log:  log.WithField("component", fmt.Sprintf("%s_exporter", clickhouseContainerEventsLabel)),
		conn: conn,
	}
}

func (c *ClickhouseContainerEventsExporter) Send(ctx context.Context, batch *castpb.ContainerEventsBatch) error {
	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues(clickhouseContainerEventsGroupLabel)
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues(clickhouseContainerEventsGroupLabel)

	for _, group := range batch.Items {
		if err := c.insertEventsGroup(ctx, group); err != nil {
			sendErrorMetric.Inc()
			return err
		}
		sendMetric.Inc()
	}
	return nil
}

func (c *ClickhouseContainerEventsExporter) insertEventsGroup(ctx context.Context, group *castpb.ContainerEvents) error {
	batch := make([]Event, 0, len(group.Items))
	for _, event := range group.Items {
		if !shouldAddEvent(event) {
			continue
		}
		item := Event{
			TS:               time.UnixMicro(int64(event.Timestamp) / 1000), // nolint:gosec
			Process:          event.ProcessName,
			Namespace:        group.Namespace,
			PodName:          group.PodName,
			ContainerName:    group.ContainerName,
			ContainerID:      group.ContainerId,
			NodeName:         group.NodeName,
			CgroupID:         group.CgroupId,
			HostPid:          event.HostPid,
			ProcessPid:       event.Pid,
			ProcessStartTime: event.ProcessStartTime,
		}
		switch event.EventType {
		case castpb.EventType_EVENT_EXEC:
			item.Name = types.EventExec.String()
			exec := event.GetExec()
			if exec != nil {
				item.FilePath = exec.Path
				item.Args = exec.Args
				if len(exec.HashSha256) == 32 {
					item.ExecHashSha256 = [32]byte(exec.HashSha256)
				}
			}
		case castpb.EventType_EVENT_TCP_CONNECT:
			item.Name = types.EventTCPConnect.String()
		case castpb.EventType_EVENT_TCP_CONNECT_ERROR:
			item.Name = types.EventTCPConnectError.String()
		case castpb.EventType_EVENT_TCP_LISTEN:
			item.Name = types.EventTCPListen.String()
		case castpb.EventType_EVENT_DNS:
			item.Name = types.EventDNS.String()
		case castpb.EventType_EVENT_FILE_CHANGE:
			item.Name = types.EventFileChange.String()
			item.FilePath = event.GetFile().Path
		case castpb.EventType_EVENT_PROCESS_OOM:
			item.Name = types.EventProcessOOMKilled.String()
		case castpb.EventType_EVENT_MAGIC_WRITE:
			item.Name = types.EventMagicWrite.String()
			item.FilePath = event.GetFile().Path
		case castpb.EventType_EVENT_STDIO_VIA_SOCKET:
			item.Name = types.EventStdioViaSocket.String()
		case castpb.EventType_EVENT_TTY_WRITE:
			item.Name = types.EventTtyWrite.String()
		case castpb.EventType_EVENT_SSH:
			item.Name = types.EventSSH.String()
		default:
			item.Name = "unknown"
		}
		batch = append(batch, item)
		err := insertBatch(ctx, c.conn, "events", batch)
		if err != nil {
			return err
		}
	}
	return nil
}

func shouldAddEvent(e *castpb.ContainerEvent) bool {
	switch e.EventType {
	case castpb.EventType_EVENT_PROCESS_FORK, castpb.EventType_EVENT_PROCESS_EXIT:
		return false
	}
	return true
}

func ClickhouseContainerEventsSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS events
		(
			ts DateTime64(9, 'UTC'),
			name LowCardinality(String),
			process LowCardinality(String),
			process_pid UInt32,
			process_start_time UInt64,
			cgroup_id UInt64,
			host_pid UInt32,
			namespace LowCardinality(String) CODEC(ZSTD(1)),
			workload_id UUID,
			pod_name LowCardinality(String) CODEC(ZSTD(1)),
			container_id String,
			container_name LowCardinality(String) CODEC(ZSTD(1)),
			node_name String,
			dst_ip IPv6,
			dst_port UInt16,
			dst_domain String,
			dst_ip_public boolean,
			dns_question_domain String,
			dns_answer_ip_public Array(IPv6),
			dns_answer_ip_private Array(IPv6),
			dns_answer_cname Array(String),
			file_path String,
			args Array(String),
			exec_hash_sha256 FixedString(32),
			flags UInt64,
			fd Int32,
			flow_direction UInt8,
			socks5_role UInt8,
			socks5_cmd_or_reply UInt8,
			socks5_address_type UInt8,
			payload_digest UInt64
		)
		ENGINE = ReplacingMergeTree()
		ORDER BY (ts)
		TTL toDateTime(ts) + INTERVAL 24 HOUR;
	`
}

func insertBatch[T any](ctx context.Context, conn clickhouse.Conn, table string, batch []T) error {
	dbBatch, err := conn.PrepareBatch(ctx, "INSERT INTO "+table)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}
	for _, b := range batch {
		b := b
		if err := dbBatch.AppendStruct(&b); err != nil {
			return fmt.Errorf("append to batch: %w", err)
		}
	}
	if err := dbBatch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}
	return nil
}
