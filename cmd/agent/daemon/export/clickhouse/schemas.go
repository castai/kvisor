package clickhouse

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
	pid UInt64,
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
TTL toDateTime(ts) + INTERVAL 72 HOUR DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;
`
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
ENGINE = MergeTree()
ORDER BY (ts, namespace, container_name)
TTL toDateTime(ts) + INTERVAL 72 HOUR DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;
	`
}
