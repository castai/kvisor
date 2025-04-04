package signature

import (
	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"golang.org/x/sys/unix"
)

var _ Signature = (*IngressNightmareDetected)(nil)

type IngressNightmareDetected struct {
	log *logging.Logger
}

type IngressNightmareDetectedConfig struct {
}

func NewIngressNightmareDetectedSignature(log *logging.Logger, cfg IngressNightmareDetectedConfig) *IngressNightmareDetected {
	return &IngressNightmareDetected{
		log: log,
	}
}

func (*IngressNightmareDetected) GetMetadata() SignatureMetadata {
	return SignatureMetadata{
		ID:      v1.SignatureEventID_SIGNATURE_INGRESS_NIGHTMARE_EXPLOIT_DETECTED,
		Name:    "ingress_nightmare_exploit_detected",
		Version: "0.0.1",
		TargetEvents: []events.ID{
			events.ProcFdLinkResolved,
		},
	}
}

func (s *IngressNightmareDetected) OnEvent(event *types.Event) *v1.SignatureFinding {
	// TODO(patrick.pichler): figure out if we want to do something with the event data.

	// args, ok := event.Args.(types.ProcFdLinkResolvedArgs)
	// if !ok {
	// 	return nil
	// }

	if unix.ByteSliceToString(event.Context.Comm[:]) != "nginx" {
		return nil
	}

	return &v1.SignatureFinding{
		Data: &v1.SignatureFinding_IngressNightmareExploitDetected{},
	}
}
