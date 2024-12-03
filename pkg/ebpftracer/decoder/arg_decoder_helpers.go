package decoder

import (
	"errors"

	"github.com/castai/kvisor/pkg/ebpftracer/events"
)

var (
	ErrUnknownArgsType  error = errors.New("unknown args type")
	ErrTooManyArguments       = errors.New("too many arguments from event")
)

// eventMaxByteSliceBufferSize is used to determine the max slice size allowed for different
// event types. For example, most events have a max size of 4096, but for network we limit to 512 bytes.
func eventMaxByteSliceBufferSize(id events.ID) int {
	// For non network event, we have a max byte slice size of 4096
	if id < events.NetPacketBase || id > events.MaxNetID {
		return 4096
	}

	return 512
}
