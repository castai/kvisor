package clickhouse

import (
	"net"
	"net/netip"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/google/uuid"
)

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
