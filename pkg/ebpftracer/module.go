package ebpftracer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -type event_context_t -type task_context_t -type ip_key -type traffic_summary -type config_t -no-global-types -cc clang-14 -strip=llvm-strip -target arm64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -type event_context_t -type task_context_t -type ip_key -type traffic_summary -type config_t -no-global-types -cc clang-14 -strip=llvm-strip -target amd64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2

type TracerEventContextT = tracerEventContextT

type moduleConfig struct {
	BTFObjPath string
}

func newModule(log *logging.Logger, cfg moduleConfig) *module {
	return &module{
		log:            log,
		cfg:            cfg,
		loaded:         &atomic.Bool{},
		attachedProbes: map[handle]struct{}{},
	}
}

// module is responsible for loading ebpf objects (programs and maps).
type module struct {
	log     *logging.Logger
	objects *tracerObjects
	cfg     moduleConfig

	networkTrafficSummaryMapSpec *ebpf.MapSpec

	loaded *atomic.Bool

	probes         map[handle]probe
	attachedProbes map[handle]struct{}
	probesMu       sync.Mutex
}

func (m *module) load(cfg Config) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := tracerObjects{}

	spec, err := loadTracer()
	if err != nil {
		return err
	}

	ksymAddrs := map[string]uint64{"socket_file_ops": 0}
	if err := proc.LoadSymbolAddresses(ksymAddrs); err != nil {
		return fmt.Errorf("error while resolving kallsym addresses: %w", err)
	}

	var kernelTypes *btf.Spec
	if m.cfg.BTFObjPath != "" {
		kernelTypes, err = btf.LoadSpec(m.cfg.BTFObjPath)
		if err != nil {
			return fmt.Errorf("loading custom btf: %w", err)
		}
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"global_config": tracerGlobalConfigT{
			SelfPid:                         uint32(os.Getpid()), // nolint:gosec
			PidNsId:                         cfg.HomePIDNS,
			FlowSampleSubmitIntervalSeconds: cfg.NetflowSampleSubmitIntervalSeconds,
			FlowGrouping:                    uint64(cfg.NetflowGrouping),
			TrackSyscallStats:               cfg.TrackSyscallStats,
			ExportMetrics:                   cfg.MetricsReporting.TracerMetricsEnabled,
			CgroupV1:                        cfg.DefaultCgroupsVersion == "V1",
			SocketFileOpsAddr:               ksymAddrs["socket_file_ops"],
		},
	}); err != nil {
		return err
	}

	mapBufferSpec, found := spec.Maps["network_traffic_buffer_map"]
	if !found {
		return fmt.Errorf("error network_traffic_buffer_map map spec not found")
	}
	m.networkTrafficSummaryMapSpec = mapBufferSpec
	summaryMapBuffer, err := buildNetworkSummaryBufferMap(mapBufferSpec)
	if err != nil {
		return fmt.Errorf("erro while building summary map buffer: %w", err)
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogDisabled: false,
			KernelTypes: kernelTypes,
		},
		MapReplacements: map[string]*ebpf.Map{
			"network_traffic_buffer_map": summaryMapBuffer,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			m.log.Errorf("Verifier error: %+v", ve)
		}
		return err
	}

	m.objects = &objs

	// TODO(Kvisord): Mount cgroupv2 if not mounted.
	cgroupPath, err := detectCgroupPath(cfg.CgroupClient.GetCgroupsRootPath())
	if err != nil {
		cgroupPath = "/cgroupv2"
		m.log.Debugf("mounting cgroupv2 to path %s", cgroupPath)
		if err := mountCgroup2(cgroupPath); err != nil {
			return fmt.Errorf("mounting cgroupv2: %w", err)
		}
	}
	m.log.Debugf("using cgroup path: %s", cgroupPath)
	m.probes = newProbes(m.objects, cgroupPath)

	m.loaded.Store(true)

	// Should reduce allocated memory, see https://github.com/cilium/ebpf/issues/1063
	btf.FlushKernelSpec()

	return nil
}

func (m *module) close() error {
	if !m.loaded.Load() {
		return nil
	}

	m.probesMu.Lock()
	defer m.probesMu.Unlock()

	// Close bpf probes.
	for handle := range m.attachedProbes {
		probe := m.probes[handle]
		if err := probe.detach(); err != nil {
			return fmt.Errorf("detach probe: %s: %w", probe.String(), err)
		}
	}

	// Close programs.
	return m.objects.Close()
}

func (m *module) attachProbe(handle handle) error {
	m.probesMu.Lock()
	defer m.probesMu.Unlock()

	if _, found := m.attachedProbes[handle]; found {
		return nil
	}

	probe, found := m.probes[handle]
	if !found {
		return fmt.Errorf("probe %d not registered", handle)
	}
	m.log.Infof("attaching probe: %s", probe.String())
	if err := probe.attach(); err != nil {
		return err
	}
	m.attachedProbes[handle] = struct{}{}
	return nil
}

func detectCgroupPath(rootPath string) (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		// Find the mount point for the root cgroup path (e.g., /cgroups),
		// which corresponds to the host's cgroup hierarchy.
		// This is necessary because the container's cgroup path (/sys/fs/cgroup)
		// does not have visibility into the host's cgroup hierarchy.
		if len(fields) >= 3 && fields[2] == "cgroup2" && strings.HasPrefix(fields[1], rootPath) {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroupv2 not found, need to mount")
}
