# NOTICE

kvisor
Copyright 2022-2026 CAST AI Group, Inc.

This product includes software developed at CAST AI Group, Inc.
(https://cast.ai/).

Licensed under the Apache License, Version 2.0 (the "License"); see the
`LICENSE` file in this distribution.

A complete listing of statically linked Go module dependencies, with their
SPDX license types and URLs pointing to the upstream LICENSE text, is bundled
inside each container image at `/licenses/THIRD_PARTY_NOTICES.md`. The same
listing is reproduced under `licenses/<image>/THIRD_PARTY_NOTICES.md` in the
source tree. Full license text for any module can be retrieved from the
listed URL or by requesting it from support@cast.ai.

## Source-level attributions

The following files contain code adapted from third-party Apache-2.0 projects.
Each adapted file carries a "Modified by CAST AI" header in addition to this
notice.

### Trivy — https://github.com/aquasecurity/trivy (Apache-2.0)

- `cmd/imagescan/trivy/package.go`
- `cmd/imagescan/trivy/jar-offline/analyzer/jar.go`
- `cmd/imagescan/trivy/golang/analyzer/binary/binary.go`
- `cmd/imagescan/trivy/golang/parser/binary/parse.go`
- `cmd/imagescan/collector/collector.go` (uses Trivy as a library; small
  adapted sections, not a full copy)

### Syft — https://github.com/anchore/syft (Apache-2.0)

- `cmd/imagescan/trivy/golang/parser/binary/regex_helpers.go` — adapted from
  Syft's `internal/regex_helpers.go`. (Lives under the `trivy/` directory by
  historical accident; the upstream is Syft.)

### Tracee — https://github.com/aquasecurity/tracee

The eBPF C source under `pkg/ebpftracer/c/` is adapted from Tracee's
`tracee.bpf.c` and headers. Note that the eBPF program ships under
**GPL-2.0** (per Tracee's upstream licensing for kernel eBPF code), not
Apache-2.0; the SPDX identifier in `tracee.bpf.c` is authoritative.

- `pkg/ebpftracer/c/tracee.bpf.c` — GPL-2.0
- `pkg/ebpftracer/c/headers/**/*.h` — GPL-2.0 (headers used by the eBPF program)

The compiled eBPF object files (`pkg/ebpftracer/tracer_*_bpfel.o`) are
embedded into the kvisor agent binary. A copy of the GPL-2.0 license text is
bundled at `/licenses/GPL-2.0.txt` inside the agent image. The corresponding
eBPF source is shipped in this source tree and is also available on request
from `support@cast.ai`.

### runc — https://github.com/opencontainers/runc (Apache-2.0)

- `pkg/cgroup/cgroup.go`, `pkg/cgroup/cgroup_cpu.go`, `pkg/cgroup/cgroup_memory.go`,
  `pkg/cgroup/cgroup_pids.go`, `pkg/cgroup/cgroup_io.go`, `pkg/cgroup/utils.go` —
  cgroup path resolution and stats parsing patterns adapted from runc's
  `libcontainer/cgroups/`.

### falcosecurity/libs — https://github.com/falcosecurity/libs (Apache-2.0)

- `pkg/ebpftracer/c/headers/common/filesystem.h` — `get_exe_upper_layer`
  detection adapted from falcosecurity/libs `driver/bpf/fillers.h`. Note this
  file ships under GPL-2.0 with the rest of the eBPF program, which is
  compatible with the upstream falcosecurity/libs Apache-2.0 license.
