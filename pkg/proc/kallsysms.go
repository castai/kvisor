package proc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

// TODO(patrick.pichler): replace this with a `__ksym` defined variable once
// this PR gets merged https://github.com/cilium/ebpf/pull/1587

var errKsymIsAmbiguous = errors.New("ksym is ambiguous")

func LoadSymbolAddresses(symbols map[string]uint64) error {
	if len(symbols) == 0 {
		return nil
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}

	if err := loadSymbolAddresses(f, symbols); err != nil {
		return fmt.Errorf("error loading symbol addresses: %w", err)
	}

	return nil
}

func loadSymbolAddresses(f io.Reader, symbols map[string]uint64) error {
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var (
			addr   uint64
			t      rune
			symbol string
		)

		line := scan.Text()

		_, err := fmt.Sscanf(line, "%x %c %s", &addr, &t, &symbol)
		if err != nil {
			return err
		}
		// Multiple addresses for a symbol have been found. Lets return an error to not confuse any
		// users and handle it the same as libbpf.
		if existingAddr, found := symbols[symbol]; existingAddr != 0 {
			return fmt.Errorf("symbol %s(0x%x): duplicate found at address 0x%x %w",
				symbol, existingAddr, addr, errKsymIsAmbiguous)
		} else if found {
			symbols[symbol] = addr
		}
	}

	if scan.Err() != nil {
		return scan.Err()
	}

	return nil
}
