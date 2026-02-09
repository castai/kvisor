package clickhouse

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/castai/logging"
)

const (
	processInsertQuery = `INSERT INTO processes (
  ts,
  container_id,
  pid,
  start_time,
  ppid,
  parent_start_time,
  args,
  file_path,
  exit_time
 ) VALUES (@ts, @container_id, @pid, @start_time, @ppid, @parent_start_time, @args, @file_path, @exit_time)`

	clickhouseProcessTreeLabel = "clickhouse_process_tree"
)

type ClickhouseProcessTreeExporter struct {
	log   *logging.Logger
	conn  clickhouse.Conn
	queue chan processtree.ProcessTreeEvent
}

func NewClickhouseProcessTreeExporter(log *logging.Logger, conn clickhouse.Conn, queueSize int) *ClickhouseProcessTreeExporter {
	return &ClickhouseProcessTreeExporter{
		log:   log.WithField("component", "clickhouse_process_tree_exporter"),
		conn:  conn,
		queue: make(chan processtree.ProcessTreeEvent, queueSize),
	}
}

func (c *ClickhouseProcessTreeExporter) Enqueue(e processtree.ProcessTreeEvent) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues(clickhouseProcessTreeLabel).Inc()
	}
}

func (c *ClickhouseProcessTreeExporter) Run(ctx context.Context) error {
	c.log.Info("running process tree export loop")
	defer c.log.Info("export process tree loop done")

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues(clickhouseProcessTreeLabel)
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues(clickhouseProcessTreeLabel)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-c.queue:
			for _, e := range event.Events {
				if err := c.asyncWrite(ctx, true, e); err != nil {
					sendErrorMetric.Inc()
					continue
				}
				sendMetric.Inc()
			}
		}
	}
}

func (c *ClickhouseProcessTreeExporter) asyncWrite(ctx context.Context, wait bool, e processtree.ProcessEvent) error {
	return c.conn.AsyncInsert(ctx, processInsertQuery, wait,
		clickhouse.DateNamed("ts", e.Timestamp, clickhouse.NanoSeconds),
		clickhouse.Named("container_id", e.ContainerID),
		clickhouse.Named("pid", e.Process.PID),
		// NOTE: StartTime will be stored in seconds since boot, since this is the best resolution we can get everywhere
		// we need. This should still be good enough to identify a process.
		clickhouse.Named("start_time", uint64(e.Process.StartTime/time.Second)), // nolint:gosec
		clickhouse.Named("ppid", e.Process.PPID),
		clickhouse.Named("parent_start_time", uint64(e.Process.ParentStartTime/time.Second)), // nolint:gosec
		clickhouse.Named("args", e.Process.Args),
		clickhouse.Named("file_path", e.Process.FilePath),
		clickhouse.Named("exit_time", e.Process.ExitTime),
	)
}

func ClickhouseProcessTreeSchema() string {
	return `
CREATE TABLE IF NOT EXISTS processes
(
	ts DateTime64(9, 'UTC'),
  container_id String,
  pid UInt32,
  -- start time in nanoseconds
  start_time UInt64,
  ppid UInt32,
  parent_start_time UInt64,
  args Array(String),
  file_path String,
  exit_time UInt64,
)
ENGINE = ReplacingMergeTree()
ORDER BY (container_id, ts, pid, start_time)
TTL toDateTime(ts) + INTERVAL 3 MONTHS;
`
}
