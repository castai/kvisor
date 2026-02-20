package config

import "fmt"

// Build generates the OTel collector pipeline configuration as a raw config
// map that can be fed directly to confmap. The pipeline is fully defined in
// code; no external YAML file is needed.
func Build(cfg *Config) map[string]any {
	return map[string]any{
		"receivers":  buildReceivers(cfg),
		"processors": buildProcessors(cfg),
		"exporters":  buildExporters(cfg),
		"extensions": buildExtensions(cfg),
		"service":    buildService(cfg),
	}
}

func buildReceivers(cfg *Config) map[string]any {
	return map[string]any{
		"otlp": map[string]any{
			"protocols": map[string]any{
				"http": map[string]any{
					"endpoint": cfg.OTLPHTTPEndpoint,
				},
			},
		},
	}
}

func buildProcessors(cfg *Config) map[string]any {
	processors := map[string]any{
		// Keep only golden-signal metrics from OBI instrumentation.
		// Running before cumulativetodelta keeps delta state memory low.
		"filter/golden-signals": map[string]any{
			"metrics": map[string]any{
				"include": map[string]any{
					"match_type": "regexp",
					"metric_names": []string{
						`http\.server\.request\.duration`,
						`http\.client\.request\.duration`,
						`rpc\.server\.duration`,
						`rpc\.client\.duration`,
						`db\.client\.operation\.duration`,
						`messaging\.publish\.duration`,
						`messaging\.process\.duration`,
					},
				},
			},
		},

		// Drop k8s infrastructure metrics to avoid duplicates with the
		// controller collector's k8s_cluster receiver.
		"filter/drop-k8s": map[string]any{
			"metrics": map[string]any{
				"exclude": map[string]any{
					"match_type": "regexp",
					"metric_names": []string{
						`k8s\..*`,
						`kube_.*`,
					},
				},
			},
		},

		// Strip high-cardinality attributes that would create per-pod or
		// per-instance series multipliers with no analytical value.
		"transform/cardinality": map[string]any{
			"metric_statements": []any{
				map[string]any{
					"context": "datapoint",
					"statements": []string{
						`delete_key(attributes, "url.full")`,
						`delete_key(attributes, "url.path")`,
						`delete_key(attributes, "url.query")`,
						`delete_key(attributes, "http.route")`,
						`delete_key(attributes, "server.address")`,
						`delete_key(attributes, "server.port")`,
						`delete_key(attributes, "client.address")`,
						`delete_key(attributes, "client.port")`,
						`delete_key(attributes, "network.peer.address")`,
						`delete_key(attributes, "network.peer.port")`,
						`delete_key(attributes, "user_agent.original")`,
						`delete_key(attributes, "db.statement")`,
						`delete_key(attributes, "messaging.message.id")`,
						`replace_pattern(attributes["messaging.destination.name"], "^([a-zA-Z0-9._-]+).*", "$1")`,
					},
				},
				map[string]any{
					"context": "resource",
					"statements": []string{
						`delete_key(attributes, "host.id")`,
						`delete_key(attributes, "host.name")`,
						`delete_key(attributes, "os.type")`,
						`delete_key(attributes, "telemetry.sdk.language")`,
						`delete_key(attributes, "telemetry.sdk.name")`,
						`delete_key(attributes, "telemetry.sdk.version")`,
						`delete_key(attributes, "service.instance.id")`,
						`delete_key(attributes, "k8s.pod.name")`,
						`delete_key(attributes, "k8s.pod.uid")`,
						`delete_key(attributes, "k8s.pod.start_time")`,
						`delete_key(attributes, "k8s.container.name")`,
						`delete_key(attributes, "k8s.replicaset.name")`,
						`delete_key(attributes, "k8s.cluster.name")`,
						`delete_key(attributes, "k8s.owner.name")`,
						`delete_key(attributes, "k8s.kind")`,
					},
				},
			},
		},

		// Prometheus pipeline batch: low timeout so rate() queries stay smooth.
		"batch": map[string]any{
			"send_batch_size": 1024,
			"timeout":         "1s",
		},

		"memory_limiter": map[string]any{
			"check_interval":  "5s",
			"limit_mib":       100,
			"spike_limit_mib": 25,
		},
	}

	if cfg.ClickHouseEnabled {
		// Convert cumulative counters to delta so Silver MVs produce correct
		// per-interval aggregates (sum(Count), sum(Sum), etc.).
		// NOT added to the Prometheus pipeline — Prometheus expects cumulative.
		// No include filter: all metrics reaching this pipeline should be converted.
		processors["cumulativetodelta"] = map[string]any{
			"max_staleness": "600s",
		}

		// ClickHouse pipeline batch: larger batches reduce ClickHouse merge pressure.
		chBatchTimeout := cfg.ClickHouseBatchTimeout
		if chBatchTimeout == "" {
			chBatchTimeout = "30s"
		}
		processors["batch/clickhouse"] = map[string]any{
			"send_batch_size":     10000,
			"send_batch_max_size": 15000,
			"timeout":             chBatchTimeout,
		}
	}

	return processors
}

func buildExporters(cfg *Config) map[string]any {
	exporters := map[string]any{
		// TODO: replace with prometheusexporter once the prometheus/prometheus
		// replace directive in go.mod is updated past v0.54.0.
		// prometheusexporter will expose a /metrics scrape endpoint on MetricsExporterPort.
		// For now, otlp_http forwards processed metrics to a downstream OTLP endpoint.
		"otlp_http": map[string]any{
			"endpoint": fmt.Sprintf("http://0.0.0.0:%d", cfg.MetricsExporterPort),
		},
		"debug": map[string]any{
			"verbosity": "detailed",
		},
	}

	if cfg.ClickHouseEnabled {
		exporters["clickhouse"] = map[string]any{
			"endpoint": cfg.ClickHouseAddr,
			"database": cfg.ClickHouseDatabase,
			"username": cfg.ClickHouseUsername,
			"password": cfg.ClickHousePassword,
			// Let ClickHouse batch small inserts server-side combined with
			// the batch/clickhouse processor for two levels of batching.
			"async_insert": true,
			"timeout":      "10s",
			"retry_on_failure": map[string]any{
				"enabled":          true,
				"initial_interval": "5s",
				"max_interval":     "30s",
				"max_elapsed_time": "300s",
			},
		}
	}

	return exporters
}

func buildExtensions(cfg *Config) map[string]any {
	return map[string]any{
		"health_check": map[string]any{
			"endpoint": cfg.HealthCheckEndpoint,
		},
	}
}

func buildService(cfg *Config) map[string]any {
	pipelines := map[string]any{
		// TODO: restore "prometheus" exporter once the prometheus/prometheus
		// replace directive is updated. Currently using otlp_http + debug.
		"metrics": map[string]any{
			"receivers":  []string{"otlp"},
			"processors": []string{"memory_limiter", "filter/drop-k8s", "filter/golden-signals", "transform/cardinality", "batch"},
			"exporters":  []string{"otlp_http", "debug"},
		},
	}

	if cfg.ClickHouseEnabled {
		// ClickHouse pipeline — delta temporality for correct Silver MV aggregates.
		// cumulativetodelta must run after filter processors (fewer series = less state).
		pipelines["metrics/clickhouse"] = map[string]any{
			"receivers":  []string{"otlp"},
			"processors": []string{"memory_limiter", "filter/drop-k8s", "filter/golden-signals", "cumulativetodelta", "transform/cardinality", "batch/clickhouse"},
			"exporters":  []string{"clickhouse"},
		}
	}

	return map[string]any{
		"telemetry": map[string]any{
			"metrics": map[string]any{
				"readers": []any{
					map[string]any{
						"pull": map[string]any{
							"exporter": map[string]any{
								"prometheus": map[string]any{
									"host": "0.0.0.0",
									"port": 8888,
								},
							},
						},
					},
				},
			},
		},
		"extensions": []string{"health_check"},
		"pipelines":  pipelines,
	}
}
