//go:build !linux

package ebpftracer

import (
	"errors"

	"github.com/cilium/ebpf"
)

func newRingbufReader(target *ebpf.Map) (*ringbufReader, error) {
	return &ringbufReader{}, nil
}

type ringbufReader struct {
}

func (r *ringbufReader) read(rec *ringbufRecord) error {
	return errors.New("not implemented")
}

func (r *ringbufReader) close() error {
	return errors.New("not implemented")
}
