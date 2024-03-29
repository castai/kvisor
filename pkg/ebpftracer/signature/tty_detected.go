package signature

import (
	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

var _ Signature = (*TTYDetected)(nil)

type TTYDetected struct{}

func NewTTYDetectedSignature() Signature {
	return &TTYDetected{}
}

func (*TTYDetected) GetMetadata() SignatureMetadata {
	return SignatureMetadata{
		ID:      v1.SignatureEventID_SIGNATURE_TTY_DETECTED,
		Name:    "tty_detected",
		Version: "0.0.1",
		TargetEvents: []events.ID{
			events.TtyOpen,
		},
	}
}

func (s *TTYDetected) OnEvent(event *types.Event) *v1.SignatureFinding {
	// For now each tty open event will be treated as an anomaly. We might want to add
	// more logic to it later.
	return &v1.SignatureFinding{}
}
