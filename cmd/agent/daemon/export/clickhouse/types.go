package clickhouse

import (
	"net"
	"net/netip"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/google/uuid"
)

var netflowsInsertQuery = `INSERT INTO netflows (
		ts, protocol, process, container_name, pod_name, namespace, zone,
		workload_name, workload_kind, pid, addr, port, dst_addr, dst_port,
		dst_domain, dst_pod_name, dst_namespace, dst_zone, dst_workload_name,
		dst_workload_kind, tx_bytes, tx_packets, rx_bytes, rx_packets
	)`

type Event struct {
	// Base event field.
	TS               time.Time `ch:"ts"`
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

	FlowDirection castaipb.FlowDirection `ch:"flow_direction"`

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
	SOCKS5Role        castaipb.SOCKS5Role        `ch:"socks5_role"`
	SOCKS5CmdOrReply  uint8                      `ch:"socks5_cmd_or_reply"`
	SOCKS5AddressType castaipb.SOCKS5AddressType `ch:"socks5_address_type"`

	// PayloadDigest is used to calculate digest for event payload.
	// For example exec file_path and args are hashed.
	// This allows to simplify events query grouping.
	PayloadDigest uint64 `ch:"payload_digest"`

	// Reusable field to hold flags any event.
	Flags uint64 `ch:"flags"`
}

type Netflow struct {
	Ts              time.Time `ch:"ts"`
	Protocol        string    `ch:"protocol"`
	Process         string    `ch:"process"`
	ContainerName   string    `ch:"container_name"`
	PodName         string    `ch:"pod_name"`
	Namespace       string    `ch:"namespace"`
	Zone            string    `ch:"zone"`
	WorkloadName    string    `ch:"workload_name"`
	WorkloadKind    string    `ch:"workload_kind"`
	PID             uint64    `ch:"pid"`
	Addr            net.IP    `ch:"addr"`
	Port            uint16    `ch:"port"`
	DstAddr         net.IP    `ch:"dst_addr"`
	DstPort         uint16    `ch:"dst_port"`
	DstDomain       string    `ch:"dst_domain"`
	DstPodName      string    `ch:"dst_pod_name"`
	DstNamespace    string    `ch:"dst_namespace"`
	DstZone         string    `ch:"dst_zone"`
	DstWorkloadName string    `ch:"dst_workload_name"`
	DstWorkloadKind string    `ch:"dst_workload_kind"`
	TxBytes         uint64    `ch:"tx_bytes"`
	TxPackets       uint64    `ch:"tx_packets"`
	RxBytes         uint64    `ch:"rx_bytes"`
	RxPackets       uint64    `ch:"rx_packets"`
}
