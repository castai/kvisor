package state

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/samber/lo"
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
			if event.Initial {
				err := c.generateExitEvents(ctx, event.Events)
				if err != nil {
					return err
				}
			}

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

func (c *ClickhouseProcessTreeExporter) generateExitEvents(ctx context.Context, processTree []processtree.ProcessEvent) error {
	lookup := map[string]map[processtree.ProcessKey]struct{}{}
	for _, pe := range processTree {
		containerMap := lookup[pe.ContainerID]
		if containerMap == nil {
			containerMap = map[processtree.ProcessKey]struct{}{}
			lookup[pe.ContainerID] = containerMap
		}

		containerMap[processtree.ProcessKey{
			PID:       pe.Process.PID,
			StartTime: pe.Process.StartTime,
		}] = struct{}{}
	}

	containerIds := lo.MapToSlice(lookup, func(key string, value map[processtree.ProcessKey]struct{}) any {
		return key
	})

	rows, err := c.conn.Query(ctx, selectRunningProcessesQuery,
		clickhouse.Named("container_ids", containerIds),
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var exitEvents []processtree.ProcessEvent
	now := time.Now()

	for rows.Next() {
		var containerID string
		var pid uint32
		var rawStartTime uint64
		var ppid uint32
		var rawParentStartTime uint64

		err := rows.Scan(&containerID, &pid, &rawStartTime, &ppid, &rawParentStartTime)
		if err != nil {
			return err
		}

		startTime := time.Duration(rawStartTime) * time.Second
		parentStartTime := time.Duration(rawParentStartTime) * time.Second

		if processes, found := lookup[containerID]; found {
			key := processtree.ProcessKey{
				PID:       pid,
				StartTime: startTime,
			}
			if _, found := processes[key]; !found {
				exitEvents = append(exitEvents, processtree.ProcessEvent{
					Timestamp:   now,
					ContainerID: containerID,
					Process: processtree.Process{
						PID:             pid,
						StartTime:       startTime,
						PPID:            ppid,
						ParentStartTime: parentStartTime,
						ExitTime:        uint64(now.UnixNano()),
					},
					Action: processtree.ProcessExit,
				})
			}
		}
	}

	if c.log.IsEnabled(slog.LevelDebug) {
		for _, pe := range exitEvents {
			c.log.Debugf("generated exit event: containerID: %s PID: %d StartTime: %v PPID: %d ParentStartTime: %v", pe.ContainerID, pe.Process.PID,
				pe.Process.StartTime, pe.Process.PPID, pe.Process.ParentStartTime)
		}
	}

	for _, pe := range exitEvents {
		err := c.asyncWrite(ctx, true, pe)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *ClickhouseProcessTreeExporter) asyncWrite(ctx context.Context, wait bool, e processtree.ProcessEvent) error {
	return c.conn.AsyncInsert(ctx, processInsertQuery, wait,
		clickhouse.DateNamed("ts", e.Timestamp, clickhouse.NanoSeconds),
		clickhouse.Named("container_id", e.ContainerID),
		clickhouse.Named("pid", e.Process.PID),
		// NOTE: StartTime will be stored in seconds since boot, since this is the best resolution we can get everywhere
		// we need. This should still be good enough to identify a process.
		clickhouse.Named("start_time", uint64(e.Process.StartTime/time.Second)),
		clickhouse.Named("ppid", e.Process.PPID),
		clickhouse.Named("parent_start_time", uint64(e.Process.ParentStartTime/time.Second)),
		clickhouse.Named("args", e.Process.Args),
		clickhouse.Named("file_path", e.Process.FilePath),
		clickhouse.Named("exit_time", e.Process.ExitTime),
	)
}

var selectRunningProcessesQuery = `
select
  container_id,
  pid,
  start_time,
  last_value(ppid),
  last_value(parent_start_time),
from processes
where  1 = 1
and container_id in @container_ids
group by container_id, pid, start_time
having exit_time = 0
`

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
