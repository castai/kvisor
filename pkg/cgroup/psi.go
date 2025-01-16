package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"golang.org/x/sys/unix"
)

func StatPSI(dirPath string, file string) (*castaipb.PSIStats, error) {
	f, err := openFile(dirPath, file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Kernel < 4.20, or CONFIG_PSI is not set,
			// or PSI stats are turned off for the cgroup
			// ("echo 0 > cgroup.pressure", kernel >= 6.1).
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var psistats castaipb.PSIStats
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		switch parts[0] {
		case "some":
			psistats.Some, err = parsePSIData(parts[1:])
			if err != nil {
				return nil, &parseError{Path: dirPath, File: file, Err: err}
			}
		case "full":
			psistats.Full, err = parsePSIData(parts[1:])
			if err != nil {
				return nil, &parseError{Path: dirPath, File: file, Err: err}
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			// Some kernels (e.g. CS9) may return ENOTSUP on read
			// if psi=1 kernel cmdline parameter is required.
			return nil, nil
		}
		return nil, &parseError{Path: dirPath, File: file, Err: err}
	}
	return &psistats, nil
}

func parsePSIData(psi []string) (*castaipb.PSIData, error) {
	data := castaipb.PSIData{}
	for _, f := range psi {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid psi data: %q", f)
		}
		switch kv[0] {
		case "total":
			v, err := strconv.ParseUint(kv[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid %s PSI value: %w", kv[0], err)
			}
			data.Total = v
			// For now we care only about total value.
			return &data, nil
		}
	}
	return &data, nil
}
