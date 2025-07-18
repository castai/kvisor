package clickhouse

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/export"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

func NewDataBatchWriter(conn clickhouse.Conn) export.DataBatchWriter {
	return &dataBatchWriter{
		conn: conn,
	}
}

type dataBatchWriter struct {
	conn clickhouse.Conn
}

func (d *dataBatchWriter) Name() string {
	return "clickhouse"
}

func (d *dataBatchWriter) Write(ctx context.Context, req *castaipb.WriteDataBatchRequest) error {
	var netflows []*castaipb.Netflow
	var events []*castaipb.ContainerEvents
	for _, item := range req.Items {
		if v := item.GetContainerEvents(); v != nil {
			events = append(events, v)
		} else if v := item.GetNetflow(); v != nil {
			netflows = append(netflows, v)
		}
	}

	for _, n := range netflows {
		if err := d.insertNetflows(ctx, true, n); err != nil {
			return err
		}
	}
	for _, e := range events {
		if err := d.insertEventsGroup(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// TODO(anjmao): Rewrite method to write batches. Many small writes to async is also not efficient.
func (d *dataBatchWriter) insertNetflows(ctx context.Context, wait bool, e *castaipb.Netflow) error {
	for _, dst := range e.Destinations {
		srcAddr, _ := netip.AddrFromSlice(e.Addr)
		dstAddr, _ := netip.AddrFromSlice(dst.Addr)

		if err := d.conn.AsyncInsert(
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
			e.Pid,
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

func (d *dataBatchWriter) insertEventsGroup(ctx context.Context, group *castaipb.ContainerEvents) error {
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
		case castaipb.EventType_EVENT_EXEC:
			item.Name = types.EventExec.String()
			exec := event.GetExec()
			if exec != nil {
				item.FilePath = exec.Path
				item.Args = exec.Args
				if len(exec.HashSha256) == 32 {
					item.ExecHashSha256 = [32]byte(exec.HashSha256)
				}
			}
		case castaipb.EventType_EVENT_TCP_CONNECT:
			item.Name = types.EventTCPConnect.String()
		case castaipb.EventType_EVENT_TCP_CONNECT_ERROR:
			item.Name = types.EventTCPConnectError.String()
		case castaipb.EventType_EVENT_TCP_LISTEN:
			item.Name = types.EventTCPListen.String()
		case castaipb.EventType_EVENT_DNS:
			item.Name = types.EventDNS.String()
		case castaipb.EventType_EVENT_FILE_CHANGE:
			item.Name = types.EventFileChange.String()
			item.FilePath = event.GetFile().Path
		case castaipb.EventType_EVENT_PROCESS_OOM:
			item.Name = types.EventProcessOOMKilled.String()
		case castaipb.EventType_EVENT_MAGIC_WRITE:
			item.Name = types.EventMagicWrite.String()
			item.FilePath = event.GetFile().Path
		case castaipb.EventType_EVENT_STDIO_VIA_SOCKET:
			item.Name = types.EventStdioViaSocket.String()
		case castaipb.EventType_EVENT_TTY_WRITE:
			item.Name = types.EventTtyWrite.String()
		case castaipb.EventType_EVENT_SSH:
			item.Name = types.EventSSH.String()
		default:
			item.Name = "unknown"
		}
		batch = append(batch, item)
		err := insertBatch(ctx, d.conn, "events", batch)
		if err != nil {
			return err
		}
	}
	return nil
}

func shouldAddEvent(e *castaipb.ContainerEvent) bool {
	switch e.EventType {
	case castaipb.EventType_EVENT_PROCESS_FORK, castaipb.EventType_EVENT_PROCESS_EXIT:
		return false
	}
	return true
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
		"pid",
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
