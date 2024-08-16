package signature

import (
	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

func toProtocolFlowDirection(f types.FlowDirection) v1.FlowDirection {
	switch f {
	case types.FlowDirectionIngress:
		return v1.FlowDirection_FLOW_INGRESS
	case types.FlowDirectionEgress:
		return v1.FlowDirection_FLOW_EGRESS
	default:
		return v1.FlowDirection_FLOW_UNKNOWN
	}
}
