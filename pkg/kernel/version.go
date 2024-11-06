// Copyright 2016-2017 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var versionRegex = regexp.MustCompile(`^(\d+)\.(\d+).(\d+).*$`)

type Version struct {
	Major       int
	Minor       int
	Patch       int
	VersionCode int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// KernelVersionFromReleaseString converts a release string with format
// 4.4.2[-1] to a kernel version number in LINUX_VERSION_CODE format.
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func KernelVersionFromReleaseString(releaseString string) (Version, error) {
	versionParts := versionRegex.FindStringSubmatch(releaseString)
	if len(versionParts) != 4 {
		return Version{}, fmt.Errorf("got invalid release version %q (expected format '4.3.2-1')", releaseString) //nolint:goerr113
	}
	major, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return Version{}, err
	}

	minor, err := strconv.Atoi(versionParts[2])
	if err != nil {
		return Version{}, err
	}

	patch, err := strconv.Atoi(versionParts[3])
	if err != nil {
		return Version{}, err
	}
	out := major*256*256 + minor*256 + patch
	return Version{
		Major:       major,
		Minor:       minor,
		Patch:       patch,
		VersionCode: out,
	}, nil
}

func currentVersionUbuntu() (Version, error) {
	procVersion, err := os.ReadFile("/proc/version_signature")
	if err != nil {
		return Version{}, err
	}
	var u1, u2, releaseString string
	_, err = fmt.Sscanf(string(procVersion), "%s %s %s", &u1, &u2, &releaseString)
	if err != nil {
		return Version{}, err
	}
	return KernelVersionFromReleaseString(releaseString)
}

var debianVersionRegex = regexp.MustCompile(`.* SMP Debian (\d+\.\d+.\d+-\d+)(?:\+[[:alnum:]]*)?.*`)

func parseDebianVersion(str string) (Version, error) {
	match := debianVersionRegex.FindStringSubmatch(str)
	if len(match) != 2 {
		return Version{}, fmt.Errorf("failed to parse kernel version from /proc/version: %s", str) //nolint:goerr113
	}
	return KernelVersionFromReleaseString(match[1])
}

func currentVersionDebian() (Version, error) {
	procVersion, err := os.ReadFile("/proc/version")
	if err != nil {
		return Version{}, fmt.Errorf("error reading /proc/version: %w", err)
	}

	return parseDebianVersion(string(procVersion))
}

var cachedKernelVersion *Version

func init() {
	if res, err := CurrentKernelVersion(); err == nil {
		cachedKernelVersion = res
	}
}

// CurrentKernelVersion returns the current kernel version.
func CurrentKernelVersion() (*Version, error) {
	if cachedKernelVersion != nil {
		return cachedKernelVersion, nil
	}

	// We need extra checks for Debian and Ubuntu as they modify
	// the kernel version patch number for compatibilty with
	// out-of-tree modules. Linux perf tools do the same for Ubuntu
	// systems: https://github.com/torvalds/linux/commit/d18acd15c
	//
	// See also:
	// https://kernel-handbook.alioth.debian.org/ch-versions.html
	// https://wiki.ubuntu.com/Kernel/FAQ
	version, err := currentVersionUbuntu()
	if err == nil {
		return &version, nil
	}
	version, err = currentVersionDebian()
	if err == nil {
		return &version, nil
	}
	version, err = currentVersionUname()
	if err != nil {
		return nil, err
	}
	return &version, nil
}
