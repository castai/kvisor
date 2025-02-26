package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	EventTypeLabel   string = "event_type"
	ExporterName     string = "exporter"
	EnricherName     string = "enricher"
	MetricLabel      string = "metric"
	EBPFProgramLabel string = "program"
	StatsKind        string = "kind"
	PodName          string = "pod"
	PodNamespace     string = "pod_namespace"
	PodUID           string = "pod_uid"
)

var (
	AgentPulledEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_kernel_pulled_events_total",
		Help: "Counter for tracking pulled events from kernel rate",
	}, []string{EventTypeLabel})

	AgentPulledEventsBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_kernel_pulled_events_bytes_total",
		Help: "Counter for tracking pulled events bytes from kernel rate",
	}, []string{EventTypeLabel})

	AgentSkippedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_skipped_events_total",
		Help: "Counter for tracking skipped events rate",
	}, []string{EventTypeLabel})

	AgentExportedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_exported_events_total",
		Help: "Counter for tracking exported events rate",
	}, []string{EventTypeLabel})

	AgentDroppedEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_dropped_events_total",
		Help: "Counter for tracking dropped events rate",
	}, []string{EventTypeLabel})

	AgentDecodeEventErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_agent_decode_event_errors_total",
		Help: "Counter for agent decode events errors rate",
	})

	AgentAnalyzersQueueDroppedEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_agent_analyzers_queue_dropped_events_total",
		Help: "Counter for agent analyzers dropped events rate",
	})

	AgentLoadContainerByCgroup = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_agent_load_container_by_cgroup_total",
		Help: "Counter for tracking amount of containers loaded by cgroup rather than via container id",
	})

	AgentDNSPacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_agent_dns_packets_total",
		Help: "Counter for tracking the total number of DNS events we received to process",
	})

	AgentFindCgroupFS = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_find_cgroup_from_filesystem",
		Help: "Counter for keeping track how often we fall back to finding cgroups via the filesystem",
	})

	AgentExporterSendTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_exporter_send_total",
		Help: "Send exporter events",
	}, []string{ExporterName})

	AgentExporterSendErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_exporter_send_errors_total",
		Help: "Dropped exporter events",
	}, []string{ExporterName})

	AgentExporterQueueDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_exporter_queue_dropped_total",
		Help: "Dropped exporter events",
	}, []string{ExporterName})

	AgentEnricherEventsTotalEnriched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_enricher_events_total_enriched",
		Help: "Enriched events",
	}, []string{EnricherName, PodName, PodNamespace, PodUID})

	AgentEnricherEventsTotalErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_enricher_events_total_errors",
		Help: "Enricher errors",
	}, []string{EnricherName, PodName, PodNamespace, PodUID})

	AgentFileHashEnricherProcMissingTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_file_hash_enricher_proc_missing_total",
		Help: "Counter for tracking process files missing during file hash enrichment",
	}, []string{PodName, PodNamespace, PodUID})

	AgentFetchKubeIPInfoErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "kvisor_agent_fetch_kube_ip_info_errors_total",
		Help: "Counter for tracking kube info calls errors",
	})

	EBPFExposedMetrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kvisor_agent_ebpf_exposed_metrics",
	}, []string{MetricLabel})

	EBPFProgramRunTimeMetrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kvisor_agent_ebpf_program_run_time_ms",
		Help: "Run time of eBPF programs in milliseconds as reported by the kernel",
	}, []string{EBPFProgramLabel})

	EBPFProgramRunCountMetrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kvisor_agent_ebpf_program_run_count",
		Help: "Number of times a certain eBPF program run as reported by the kernel",
	}, []string{EBPFProgramLabel})

	AgentStatsScrapeErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kvisor_agent_stats_scrape_errors_total",
		Help: "Stats scrape errors",
	}, []string{StatsKind})
)
