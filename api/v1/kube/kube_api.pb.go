// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: api/v1/kube/kube_api.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type WorkloadKind int32

const (
	WorkloadKind_WORKLOAD_KIND_UNKNOWN      WorkloadKind = 0
	WorkloadKind_WORKLOAD_KIND_DEPLOYMENT   WorkloadKind = 1
	WorkloadKind_WORKLOAD_KIND_REPLICA_SET  WorkloadKind = 2
	WorkloadKind_WORKLOAD_KIND_STATEFUL_SET WorkloadKind = 3
	WorkloadKind_WORKLOAD_KIND_DAEMON_SET   WorkloadKind = 4
	WorkloadKind_WORKLOAD_KIND_JOB          WorkloadKind = 5
	WorkloadKind_WORKLOAD_KIND_CRONJOB      WorkloadKind = 6
	WorkloadKind_WORKLOAD_KIND_POD          WorkloadKind = 7
)

// Enum value maps for WorkloadKind.
var (
	WorkloadKind_name = map[int32]string{
		0: "WORKLOAD_KIND_UNKNOWN",
		1: "WORKLOAD_KIND_DEPLOYMENT",
		2: "WORKLOAD_KIND_REPLICA_SET",
		3: "WORKLOAD_KIND_STATEFUL_SET",
		4: "WORKLOAD_KIND_DAEMON_SET",
		5: "WORKLOAD_KIND_JOB",
		6: "WORKLOAD_KIND_CRONJOB",
		7: "WORKLOAD_KIND_POD",
	}
	WorkloadKind_value = map[string]int32{
		"WORKLOAD_KIND_UNKNOWN":      0,
		"WORKLOAD_KIND_DEPLOYMENT":   1,
		"WORKLOAD_KIND_REPLICA_SET":  2,
		"WORKLOAD_KIND_STATEFUL_SET": 3,
		"WORKLOAD_KIND_DAEMON_SET":   4,
		"WORKLOAD_KIND_JOB":          5,
		"WORKLOAD_KIND_CRONJOB":      6,
		"WORKLOAD_KIND_POD":          7,
	}
)

func (x WorkloadKind) Enum() *WorkloadKind {
	p := new(WorkloadKind)
	*p = x
	return p
}

func (x WorkloadKind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (WorkloadKind) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v1_kube_kube_api_proto_enumTypes[0].Descriptor()
}

func (WorkloadKind) Type() protoreflect.EnumType {
	return &file_api_v1_kube_kube_api_proto_enumTypes[0]
}

func (x WorkloadKind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use WorkloadKind.Descriptor instead.
func (WorkloadKind) EnumDescriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{0}
}

type GetClusterInfoRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetClusterInfoRequest) Reset() {
	*x = GetClusterInfoRequest{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetClusterInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetClusterInfoRequest) ProtoMessage() {}

func (x *GetClusterInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetClusterInfoRequest.ProtoReflect.Descriptor instead.
func (*GetClusterInfoRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{0}
}

type GetClusterInfoResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PodsCidr      []string               `protobuf:"bytes,1,rep,name=pods_cidr,json=podsCidr,proto3" json:"pods_cidr,omitempty"`
	ServiceCidr   []string               `protobuf:"bytes,2,rep,name=service_cidr,json=serviceCidr,proto3" json:"service_cidr,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetClusterInfoResponse) Reset() {
	*x = GetClusterInfoResponse{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetClusterInfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetClusterInfoResponse) ProtoMessage() {}

func (x *GetClusterInfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetClusterInfoResponse.ProtoReflect.Descriptor instead.
func (*GetClusterInfoResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{1}
}

func (x *GetClusterInfoResponse) GetPodsCidr() []string {
	if x != nil {
		return x.PodsCidr
	}
	return nil
}

func (x *GetClusterInfoResponse) GetServiceCidr() []string {
	if x != nil {
		return x.ServiceCidr
	}
	return nil
}

type GetIPInfoRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Ip            []byte                 `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetIPInfoRequest) Reset() {
	*x = GetIPInfoRequest{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetIPInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIPInfoRequest) ProtoMessage() {}

func (x *GetIPInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIPInfoRequest.ProtoReflect.Descriptor instead.
func (*GetIPInfoRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{2}
}

func (x *GetIPInfoRequest) GetIp() []byte {
	if x != nil {
		return x.Ip
	}
	return nil
}

type GetIPInfoResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Info          *IPInfo                `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetIPInfoResponse) Reset() {
	*x = GetIPInfoResponse{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetIPInfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIPInfoResponse) ProtoMessage() {}

func (x *GetIPInfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIPInfoResponse.ProtoReflect.Descriptor instead.
func (*GetIPInfoResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{3}
}

func (x *GetIPInfoResponse) GetInfo() *IPInfo {
	if x != nil {
		return x.Info
	}
	return nil
}

type IPInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PodUid        string                 `protobuf:"bytes,1,opt,name=pod_uid,json=podUid,proto3" json:"pod_uid,omitempty"`
	PodName       string                 `protobuf:"bytes,3,opt,name=pod_name,json=podName,proto3" json:"pod_name,omitempty"`
	Namespace     string                 `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	WorkloadName  string                 `protobuf:"bytes,4,opt,name=workload_name,json=workloadName,proto3" json:"workload_name,omitempty"`
	WorkloadKind  string                 `protobuf:"bytes,5,opt,name=workload_kind,json=workloadKind,proto3" json:"workload_kind,omitempty"`
	WorkloadUid   string                 `protobuf:"bytes,6,opt,name=workload_uid,json=workloadUid,proto3" json:"workload_uid,omitempty"`
	Zone          string                 `protobuf:"bytes,7,opt,name=zone,proto3" json:"zone,omitempty"`
	NodeName      string                 `protobuf:"bytes,8,opt,name=node_name,json=nodeName,proto3" json:"node_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *IPInfo) Reset() {
	*x = IPInfo{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IPInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IPInfo) ProtoMessage() {}

func (x *IPInfo) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IPInfo.ProtoReflect.Descriptor instead.
func (*IPInfo) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{4}
}

func (x *IPInfo) GetPodUid() string {
	if x != nil {
		return x.PodUid
	}
	return ""
}

func (x *IPInfo) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

func (x *IPInfo) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *IPInfo) GetWorkloadName() string {
	if x != nil {
		return x.WorkloadName
	}
	return ""
}

func (x *IPInfo) GetWorkloadKind() string {
	if x != nil {
		return x.WorkloadKind
	}
	return ""
}

func (x *IPInfo) GetWorkloadUid() string {
	if x != nil {
		return x.WorkloadUid
	}
	return ""
}

func (x *IPInfo) GetZone() string {
	if x != nil {
		return x.Zone
	}
	return ""
}

func (x *IPInfo) GetNodeName() string {
	if x != nil {
		return x.NodeName
	}
	return ""
}

type GetPodRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Uid           string                 `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPodRequest) Reset() {
	*x = GetPodRequest{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPodRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPodRequest) ProtoMessage() {}

func (x *GetPodRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPodRequest.ProtoReflect.Descriptor instead.
func (*GetPodRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{5}
}

func (x *GetPodRequest) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

type GetPodResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Pod           *Pod                   `protobuf:"bytes,1,opt,name=pod,proto3" json:"pod,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPodResponse) Reset() {
	*x = GetPodResponse{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPodResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPodResponse) ProtoMessage() {}

func (x *GetPodResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPodResponse.ProtoReflect.Descriptor instead.
func (*GetPodResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{6}
}

func (x *GetPodResponse) GetPod() *Pod {
	if x != nil {
		return x.Pod
	}
	return nil
}

type Pod struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	WorkloadUid   string                 `protobuf:"bytes,1,opt,name=workload_uid,json=workloadUid,proto3" json:"workload_uid,omitempty"`
	WorkloadName  string                 `protobuf:"bytes,2,opt,name=workload_name,json=workloadName,proto3" json:"workload_name,omitempty"`
	WorkloadKind  WorkloadKind           `protobuf:"varint,3,opt,name=workload_kind,json=workloadKind,proto3,enum=kube.v1.WorkloadKind" json:"workload_kind,omitempty"`
	Zone          string                 `protobuf:"bytes,4,opt,name=zone,proto3" json:"zone,omitempty"`
	NodeName      string                 `protobuf:"bytes,5,opt,name=node_name,json=nodeName,proto3" json:"node_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Pod) Reset() {
	*x = Pod{}
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Pod) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Pod) ProtoMessage() {}

func (x *Pod) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kube_kube_api_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Pod.ProtoReflect.Descriptor instead.
func (*Pod) Descriptor() ([]byte, []int) {
	return file_api_v1_kube_kube_api_proto_rawDescGZIP(), []int{7}
}

func (x *Pod) GetWorkloadUid() string {
	if x != nil {
		return x.WorkloadUid
	}
	return ""
}

func (x *Pod) GetWorkloadName() string {
	if x != nil {
		return x.WorkloadName
	}
	return ""
}

func (x *Pod) GetWorkloadKind() WorkloadKind {
	if x != nil {
		return x.WorkloadKind
	}
	return WorkloadKind_WORKLOAD_KIND_UNKNOWN
}

func (x *Pod) GetZone() string {
	if x != nil {
		return x.Zone
	}
	return ""
}

func (x *Pod) GetNodeName() string {
	if x != nil {
		return x.NodeName
	}
	return ""
}

var File_api_v1_kube_kube_api_proto protoreflect.FileDescriptor

const file_api_v1_kube_kube_api_proto_rawDesc = "" +
	"\n" +
	"\x1aapi/v1/kube/kube_api.proto\x12\akube.v1\"\x17\n" +
	"\x15GetClusterInfoRequest\"X\n" +
	"\x16GetClusterInfoResponse\x12\x1b\n" +
	"\tpods_cidr\x18\x01 \x03(\tR\bpodsCidr\x12!\n" +
	"\fservice_cidr\x18\x02 \x03(\tR\vserviceCidr\"\"\n" +
	"\x10GetIPInfoRequest\x12\x0e\n" +
	"\x02ip\x18\x01 \x01(\fR\x02ip\"8\n" +
	"\x11GetIPInfoResponse\x12#\n" +
	"\x04info\x18\x01 \x01(\v2\x0f.kube.v1.IPInfoR\x04info\"\xf8\x01\n" +
	"\x06IPInfo\x12\x17\n" +
	"\apod_uid\x18\x01 \x01(\tR\x06podUid\x12\x19\n" +
	"\bpod_name\x18\x03 \x01(\tR\apodName\x12\x1c\n" +
	"\tnamespace\x18\x02 \x01(\tR\tnamespace\x12#\n" +
	"\rworkload_name\x18\x04 \x01(\tR\fworkloadName\x12#\n" +
	"\rworkload_kind\x18\x05 \x01(\tR\fworkloadKind\x12!\n" +
	"\fworkload_uid\x18\x06 \x01(\tR\vworkloadUid\x12\x12\n" +
	"\x04zone\x18\a \x01(\tR\x04zone\x12\x1b\n" +
	"\tnode_name\x18\b \x01(\tR\bnodeName\"!\n" +
	"\rGetPodRequest\x12\x10\n" +
	"\x03uid\x18\x02 \x01(\tR\x03uid\"0\n" +
	"\x0eGetPodResponse\x12\x1e\n" +
	"\x03pod\x18\x01 \x01(\v2\f.kube.v1.PodR\x03pod\"\xba\x01\n" +
	"\x03Pod\x12!\n" +
	"\fworkload_uid\x18\x01 \x01(\tR\vworkloadUid\x12#\n" +
	"\rworkload_name\x18\x02 \x01(\tR\fworkloadName\x12:\n" +
	"\rworkload_kind\x18\x03 \x01(\x0e2\x15.kube.v1.WorkloadKindR\fworkloadKind\x12\x12\n" +
	"\x04zone\x18\x04 \x01(\tR\x04zone\x12\x1b\n" +
	"\tnode_name\x18\x05 \x01(\tR\bnodeName*\xed\x01\n" +
	"\fWorkloadKind\x12\x19\n" +
	"\x15WORKLOAD_KIND_UNKNOWN\x10\x00\x12\x1c\n" +
	"\x18WORKLOAD_KIND_DEPLOYMENT\x10\x01\x12\x1d\n" +
	"\x19WORKLOAD_KIND_REPLICA_SET\x10\x02\x12\x1e\n" +
	"\x1aWORKLOAD_KIND_STATEFUL_SET\x10\x03\x12\x1c\n" +
	"\x18WORKLOAD_KIND_DAEMON_SET\x10\x04\x12\x15\n" +
	"\x11WORKLOAD_KIND_JOB\x10\x05\x12\x19\n" +
	"\x15WORKLOAD_KIND_CRONJOB\x10\x06\x12\x15\n" +
	"\x11WORKLOAD_KIND_POD\x10\a2\xdb\x01\n" +
	"\aKubeAPI\x12Q\n" +
	"\x0eGetClusterInfo\x12\x1e.kube.v1.GetClusterInfoRequest\x1a\x1f.kube.v1.GetClusterInfoResponse\x12B\n" +
	"\tGetIPInfo\x12\x19.kube.v1.GetIPInfoRequest\x1a\x1a.kube.v1.GetIPInfoResponse\x129\n" +
	"\x06GetPod\x12\x16.kube.v1.GetPodRequest\x1a\x17.kube.v1.GetPodResponseB&Z$github.com/castai/kvisor/api/kube/v1b\x06proto3"

var (
	file_api_v1_kube_kube_api_proto_rawDescOnce sync.Once
	file_api_v1_kube_kube_api_proto_rawDescData []byte
)

func file_api_v1_kube_kube_api_proto_rawDescGZIP() []byte {
	file_api_v1_kube_kube_api_proto_rawDescOnce.Do(func() {
		file_api_v1_kube_kube_api_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_api_v1_kube_kube_api_proto_rawDesc), len(file_api_v1_kube_kube_api_proto_rawDesc)))
	})
	return file_api_v1_kube_kube_api_proto_rawDescData
}

var file_api_v1_kube_kube_api_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_v1_kube_kube_api_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_api_v1_kube_kube_api_proto_goTypes = []any{
	(WorkloadKind)(0),              // 0: kube.v1.WorkloadKind
	(*GetClusterInfoRequest)(nil),  // 1: kube.v1.GetClusterInfoRequest
	(*GetClusterInfoResponse)(nil), // 2: kube.v1.GetClusterInfoResponse
	(*GetIPInfoRequest)(nil),       // 3: kube.v1.GetIPInfoRequest
	(*GetIPInfoResponse)(nil),      // 4: kube.v1.GetIPInfoResponse
	(*IPInfo)(nil),                 // 5: kube.v1.IPInfo
	(*GetPodRequest)(nil),          // 6: kube.v1.GetPodRequest
	(*GetPodResponse)(nil),         // 7: kube.v1.GetPodResponse
	(*Pod)(nil),                    // 8: kube.v1.Pod
}
var file_api_v1_kube_kube_api_proto_depIdxs = []int32{
	5, // 0: kube.v1.GetIPInfoResponse.info:type_name -> kube.v1.IPInfo
	8, // 1: kube.v1.GetPodResponse.pod:type_name -> kube.v1.Pod
	0, // 2: kube.v1.Pod.workload_kind:type_name -> kube.v1.WorkloadKind
	1, // 3: kube.v1.KubeAPI.GetClusterInfo:input_type -> kube.v1.GetClusterInfoRequest
	3, // 4: kube.v1.KubeAPI.GetIPInfo:input_type -> kube.v1.GetIPInfoRequest
	6, // 5: kube.v1.KubeAPI.GetPod:input_type -> kube.v1.GetPodRequest
	2, // 6: kube.v1.KubeAPI.GetClusterInfo:output_type -> kube.v1.GetClusterInfoResponse
	4, // 7: kube.v1.KubeAPI.GetIPInfo:output_type -> kube.v1.GetIPInfoResponse
	7, // 8: kube.v1.KubeAPI.GetPod:output_type -> kube.v1.GetPodResponse
	6, // [6:9] is the sub-list for method output_type
	3, // [3:6] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_api_v1_kube_kube_api_proto_init() }
func file_api_v1_kube_kube_api_proto_init() {
	if File_api_v1_kube_kube_api_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_api_v1_kube_kube_api_proto_rawDesc), len(file_api_v1_kube_kube_api_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1_kube_kube_api_proto_goTypes,
		DependencyIndexes: file_api_v1_kube_kube_api_proto_depIdxs,
		EnumInfos:         file_api_v1_kube_kube_api_proto_enumTypes,
		MessageInfos:      file_api_v1_kube_kube_api_proto_msgTypes,
	}.Build()
	File_api_v1_kube_kube_api_proto = out.File
	file_api_v1_kube_kube_api_proto_goTypes = nil
	file_api_v1_kube_kube_api_proto_depIdxs = nil
}
