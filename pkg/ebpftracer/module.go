package ebpftracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/castai/kvisor/pkg/ebpftracer/helpers"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -type event_context_t -type task_context_t -type ip_key -type traffic_summary -type netflow_config_t -type file_access_key -type file_access_stats -type file_access_config_t -no-global-types -cc clang-14 -strip=llvm-strip -target arm64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -type event_context_t -type task_context_t -type ip_key -type traffic_summary -type netflow_config_t -type file_access_key -type file_access_stats -type file_access_config_t -no-global-types -cc clang-14 -strip=llvm-strip -target amd64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2

type TracerEventContextT = tracerEventContextT

func (t TracerEventContextT) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	err := binary.Write(buf, binary.LittleEndian, t)
	if err != nil {
		return nil, err
	}

	// writes argument length
	err = binary.Write(buf, binary.LittleEndian, uint8(0))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func newModule(log *logging.Logger) *module {
	return &module{
		log:            log,
		loaded:         &atomic.Bool{},
		attachedProbes: map[handle]struct{}{},
	}
}

// module is responsible for loading ebpf objects (programs and maps).
type module struct {
	log     *logging.Logger
	objects *tracerObjects

	networkTrafficSummaryMapSpec *ebpf.MapSpec
	fileAccessMapSpec            *ebpf.MapSpec

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

	var kernelTypes *btf.Spec

	// If the given `BTFPath` points to the kernels, we also want to load
	// it via the `btf.LoadKernelSpec` function, as otherwise the kernel
	// BTF will get parsed twice, causing quite the memory churn.
	if cfg.BTFPath != "" && cfg.BTFPath != "/sys/kernel/btf/vmlinux" {
		kernelTypes, err = btf.LoadSpec(cfg.BTFPath)
		if err != nil {
			return fmt.Errorf("loading custom btf: %w", err)
		}
	} else {
		kernelTypes, err = btf.LoadKernelSpec()
		if err != nil {
			return fmt.Errorf("loading kernel btf: %w", err)
		}
	}

	if err := helpers.SetVariable(spec, "global_config", tracerGlobalConfigT{
		SelfPid:                         uint32(os.Getpid()), // nolint:gosec
		PidNsId:                         cfg.HomePIDNS,
		FlowSampleSubmitIntervalSeconds: cfg.NetflowSampleSubmitIntervalSeconds,
		FlowGrouping:                    uint64(cfg.NetflowGrouping),
		TrackSyscallStats:               false, // TODO: Due high perf impact we do not track syscall stats.
		ExportMetrics:                   cfg.MetricsReporting.TracerMetricsEnabled,
		CgroupV1:                        cfg.DefaultCgroupsVersion == "V1",
	}); err != nil {
		return err
	}

	mapsReplacement := map[string]*ebpf.Map{}
	if cfg.NetflowsEnabled {
		mapBufferSpec, found := spec.Maps["network_traffic_buffer_map"]
		if !found {
			return fmt.Errorf("error network_traffic_buffer_map map spec not found")
		}
		m.networkTrafficSummaryMapSpec = mapBufferSpec
		summaryMapBuffer, err := buildSummaryBufferMap(mapBufferSpec)
		if err != nil {
			return fmt.Errorf("error while building summary map buffer: %w", err)
		}
		mapsReplacement["network_traffic_buffer_map"] = summaryMapBuffer
	}

	if cfg.FileAccessEnabled {
		fileAccessMapBufferSpec, found := spec.Maps["file_access_stats_map"]
		if !found {
			return fmt.Errorf("error file_access_stats_map map spec not found")
		}
		m.fileAccessMapSpec = fileAccessMapBufferSpec
		fileAccessMapBuffer, err := buildSummaryBufferMap(fileAccessMapBufferSpec)
		if err != nil {
			return fmt.Errorf("error while building file access map buffer: %w", err)
		}
		mapsReplacement["file_access_stats_map"] = fileAccessMapBuffer
	}

	spec.Maps["signal_events"].MaxEntries = cfg.SignalEventsRingBufferSize
	spec.Maps["events"].MaxEntries = cfg.EventsRingBufferSize
	spec.Maps["skb_events"].MaxEntries = cfg.SkbEventsRingBufferSize

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogDisabled: false,
			KernelTypes: kernelTypes,
		},
		MapReplacements: mapsReplacement,
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			m.log.Errorf("Verifier error: %+v", ve)
		}
		return err
	}

	m.objects = &objs

	// Should reduce allocated memory, see https://github.com/cilium/ebpf/issues/1063
	btf.FlushKernelSpec()
	runtime.GC()

	// Make sure cgroupv2 is mounted. It's required for cgroup networking ebpf programs.
	cgroupPath, err := detectCgroupPath(cfg.CgroupClient.GetCgroupsRootPath())
	if err != nil && cfg.AutomountCgroupv2 {
		// Path /cgroup2-manual-mount is created as a temp dir from the host using volume mount.
		cgroupPath = "/cgroup2-manual-mount/cgroupv2"
		m.log.Infof("mounting cgroupv2 to path %s", cgroupPath)
		if err := mountCgroup2(cgroupPath); err != nil {
			return fmt.Errorf("mounting cgroupv2: %w", err)
		}
	}
	m.log.Infof("using cgroup path: %s", cgroupPath)
	m.probes = newProbes(m.objects, cgroupPath)

	m.loaded.Store(true)

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
