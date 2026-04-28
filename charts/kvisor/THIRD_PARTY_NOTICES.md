# Third-Party Notices for the kvisor Helm chart

The Helm chart `castai-kvisor` is distributed under the Apache License 2.0
(see `LICENSE`). The chart itself contains no third-party binaries — it
deploys CAST AI container images that bundle their own third-party
attribution files at `/licenses/THIRD_PARTY_NOTICES.md` inside each image:

- `kvisor-agent`      — `/licenses/THIRD_PARTY_NOTICES.md` (also includes a copy of GPL-2.0 for the embedded eBPF program)
- `kvisor-controller` — `/licenses/THIRD_PARTY_NOTICES.md`
- `kvisor-scanners`   — `/licenses/THIRD_PARTY_NOTICES.md`

Each image's `THIRD_PARTY_NOTICES.md` lists every statically linked Go module
with its SPDX license type and a URL pointing to the upstream LICENSE text.
Full license text for any module can be retrieved from the listed URL or by
requesting it from support@cast.ai.

For the kvisor source-level attributions of code adapted from Trivy, Tracee,
runc, falcosecurity/libs and Syft, see `NOTICE.md`.
