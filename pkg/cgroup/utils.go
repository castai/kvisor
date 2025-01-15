package cgroup

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

type parseError struct {
	Path string
	File string
	Err  error
}

func (e *parseError) Error() string {
	return "unable to parse " + path.Join(e.Path, e.File) + ": " + e.Err.Error()
}

func (e *parseError) Unwrap() error { return e.Err }

func parseKeyValue(t string) (string, uint64, error) {
	parts := strings.SplitN(t, " ", 3)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("line %q is not in key value format", t)
	}

	value, err := parseUint(parts[1], 10, 64)
	if err != nil {
		return "", 0, err
	}

	return parts[0], value, nil
}

func parseUint(s string, base, bitSize int) (uint64, error) {
	value, err := strconv.ParseUint(s, base, bitSize)
	if err != nil {
		intValue, intErr := strconv.ParseInt(s, base, bitSize)
		// 1. Handle negative values greater than MinInt64 (and)
		// 2. Handle negative values lesser than MinInt64
		if intErr == nil && intValue < 0 {
			return 0, nil
		} else if errors.Is(intErr, strconv.ErrRange) && intValue < 0 {
			return 0, nil
		}

		return value, err
	}

	return value, nil
}

func openFile(dirPath, fileName string) (*os.File, error) {
	return os.OpenFile(path.Join(dirPath, fileName), os.O_RDONLY, 0o600)
}

func readCgroupFile(dirPath, fileName string) (string, error) {
	data, err := os.ReadFile(path.Join(dirPath, fileName))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func getCgroupParamUint(path, file string) (uint64, error) {
	contents, err := getCgroupParamString(path, file)
	if err != nil {
		return 0, err
	}
	contents = strings.TrimSpace(contents)
	if contents == "max" {
		return math.MaxUint64, nil
	}

	res, err := parseUint(contents, 10, 64)
	if err != nil {
		return res, &parseError{Path: path, File: file, Err: err}
	}
	return res, nil
}

func getCgroupParamString(path, file string) (string, error) {
	contents, err := readCgroupFile(path, file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(contents), nil
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}
