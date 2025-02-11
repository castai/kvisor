package ebpftracer

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func newRingbufReader(target *ebpf.Map) (*ringbufReader, error) {
	reader, err := ringbuf.NewReader(target)
	if err != nil {
		return nil, err
	}

	return &ringbufReader{
		reader: reader,
		record: &ringbuf.Record{},
	}, nil
}

type ringbufReader struct {
	reader *ringbuf.Reader
	record *ringbuf.Record
}

func (r *ringbufReader) read(rec *ringbufRecord) error {
	if err := r.reader.ReadInto(r.record); err != nil {
		return err
	}
	rec.buf = r.record.RawSample
	return nil
}

func (r *ringbufReader) close() error {
	return nil
}
