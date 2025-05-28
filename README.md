# CAST AI Kubernetes Security

Real time Kubernetes issues detection and vulnerabilities scanning and runtime.

## Getting started

Visit the [docs](https://docs.cast.ai/docs/getting-started) to connect your cluster.

## Build Instructions

### Prerequisites

- Go 1.22 or later
- Make
- Clang (for eBPF compilation)

### Local Build

To build the project locally for your current architecture:

```bash
make kvisor-agent
```

### Cross Compilation

To cross-compile for a different architecture, use the `UNAME_M` variable:

For AMD64/x86_64:
```bash
UNAME_M=x86_64 make kvisor-agent
```

For ARM64:
```bash
UNAME_M=aarch64 make kvisor-agent
```

The compiled binaries will be available in the `bin/` directory with architecture-specific suffixes.

Available Make Targets:
- `kvisor-agent`: Builds the agent binary
- `kvisor-controller`: Builds the controller binary
- `kvisor-image-scanner`: Builds the image scanner
- `kvisor-linter`: Builds the linter
- `kvisor-event-generator`: Builds the event generator

Add `clean-` prefix to any target to clean its build artifacts (e.g., `clean-kvisor-agent`).

## Helm chart

The helm chart for the CAST AI Kvisor is published in the [castai/helm-charts](https://github.com/castai/helm-charts) repo.

## Licence

[Apache 2.0 License](LICENSE) See [NOTICE.md](NOTICE.md) for complete details, including software and third-party licenses and permissions.

