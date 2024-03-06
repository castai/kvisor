package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	EventTypeLabel string = "event_type"
	EventIDLabel   string = "event_id"
)

var (
	ServerStorageDroppedEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_server_storage_dropped_events_total",
	})

	ServerCastaiExportedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_castai_exported_events_total",
	})

	ServerCastaiExportedContainerStatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_castai_exported_container_stats_total",
	})

	ControllerImagesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kvisor_controller_images_count",
	})

	ControllerPendingImagesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kvisor_controller_pending_images_count",
	})

	AgentPulledEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_kernel_pulled_events_total",
		Help: "Counter for tracking pulled events from kernel rate",
	})

	AgentPulledEventsBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_kernel_pulled_events_bytes_total",
		Help: "Counter for tracking pulled events bytes from kernel rate",
	})

	AgentKernelLostEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_kernel_lost_events_total",
		Help: "Counter for tracking lost events from kernel rate",
	})

	AgentSkippedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisord_agent_skipped_events_total",
		Help: "Counter for tracking skipped events rate",
	}, []string{EventIDLabel})

	AgentExportedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisord_agent_exported_events_total",
		Help: "Counter for tracking exported events rate",
	}, []string{EventTypeLabel})

	AgentDroppedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisord_agent_dropped_events_total",
		Help: "Counter for tracking dropped events rate",
	}, []string{EventTypeLabel})

	AgentExportedContainerStatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_exported_container_stats_total",
		Help: "Counter for tracking exported container stats rate",
	})

	AgentMissingContainersTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_fetch_container_errors_total",
		Help: "Counter for containers metadata errors rate",
	})

	AgentDecodeEventErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_decode_event_errors_total",
		Help: "Counter for agent decode events errors rate",
	})

	AgentAnalyzersProcessedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_analyzers_processed_total",
		Help: "Counter for agent analyzers processed rate",
	})

	AgentAnalyzersQueueDroppedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_analyzers_queue_dropped_events_total",
		Help: "Counter for agent analyzers dropped events rate",
	})

	AgentRetriedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_retried_events_total",
		Help: "Counter for tracking events scheduled for retry",
	})

	AgentRetryDroppedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_retry_dropped_events_total",
		Help: "Counter for tracking dropped events rate by retry logic",
	})

	AgentLoadContainerByCgroup = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_load_container_by_cgroup_total",
		Help: "Counter for tracking amount of containers loaded by cgroup rather than via container id",
	})

	AgentLoadContainerByContainerID = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_load_container_by_container_id_total",
		Help: "Counter for tracking amount of containers loaded by container id",
	})

	AgentEbpfArgError = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_ebpf_arg_errors_total",
		Help: "Counter for tracking agent ebpf args parsing errors",
	})

	AgentDNSPacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_dns_packets_total",
		Help: "Counter for tracking the total number of DNS events we received to process",
	})

	AgentDNSPacketFailedParse = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisord_agent_dns_packets_failed_parse",
		Help: "Counter for tracking the number of DNS packets we failed to parse",
	})
)
