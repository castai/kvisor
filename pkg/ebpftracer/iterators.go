package ebpftracer

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
)

func (m *module) InitializeExistingSockets() error {
	socketsIter, err := link.AttachIter(link.IterOptions{
		Program: m.objects.SocketTaskFileIter,
	})
	if err != nil {
		return err
	}
	defer socketsIter.Close()

	// We do not care about the output of the iterator.
	_, err = readIterator(socketsIter)
	if err != nil {
		return err
	}

	return nil
}

func readIterator(iter *link.Iter) ([]byte, error) {
	r, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("error while opening BPF interator: %w", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error while reading from BPF interator: %w", err)
	}
	return data, nil
}
