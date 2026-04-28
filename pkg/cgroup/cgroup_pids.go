// Adapted from https://github.com/opencontainers/runc (libcontainer/cgroups).
// Licensed under Apache-2.0. Modified by CAST AI on 2026-04-28.

package cgroup

import (
	"errors"
	"math"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func statPidsV2(dirPath string, stats *Stats) error {
	current, err := getCgroupParamUint(dirPath, "pids.current")
	if err != nil {
		if os.IsNotExist(err) {
			return statPidsFromCgroupProcs(dirPath, stats)
		}
		return err
	}

	maxVal, err := getCgroupParamUint(dirPath, "pids.max")
	if err != nil {
		return err
	}
	// If no limit is set, read from pids.max returns "max", which is
	// converted to MaxUint64 by GetCgroupParamUint. Historically, we
	// represent "no limit" for pids as 0, thus this conversion.
	if maxVal == math.MaxUint64 {
		maxVal = 0
	}

	stats.PidsStats.Current = current
	stats.PidsStats.Limit = maxVal
	return nil
}

func statPidsFromCgroupProcs(dirPath string, stats *Stats) error {
	// if the controller is not enabled, let's read PIDS from cgroups.procs
	// (or threads if cgroup.threads is enabled)
	contents, err := readCgroupFile(dirPath, "cgroup.procs")
	if errors.Is(err, unix.ENOTSUP) {
		contents, err = readCgroupFile(dirPath, "cgroup.threads")
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	pids := strings.Count(contents, "\n")
	stats.PidsStats.Current = uint64(pids) //nolint:gosec
	stats.PidsStats.Limit = 0
	return nil
}

func statPidsV1(path string, stats *Stats) error {
	if !pathExists(path) {
		return nil
	}
	current, err := getCgroupParamUint(path, "pids.current")
	if err != nil {
		return err
	}

	maxVal, err := getCgroupParamUint(path, "pids.max")
	if err != nil {
		return err
	}
	// If no limit is set, read from pids.max returns "max", which is
	// converted to MaxUint64 by GetCgroupParamUint. Historically, we
	// represent "no limit" for pids as 0, thus this conversion.
	if maxVal == math.MaxUint64 {
		maxVal = 0
	}

	stats.PidsStats.Current = current
	stats.PidsStats.Limit = maxVal
	return nil
}
