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
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -no-global-types -cc clang-14 -target arm64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type global_config_t -no-global-types -cc clang-14 -target amd64 tracer ./c/tracee.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2

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

	loaded *atomic.Bool

	probes         map[handle]probe
	attachedProbes map[handle]struct{}
	probesMu       sync.Mutex
}

func (m *module) load(targetPIDNSID proc.NamespaceID) error {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 4096,
		Max: 4096,
	}); err != nil {
		return fmt.Errorf("setting temporary rlimit: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := tracerObjects{}

	spec, err := loadTracer()
	if err != nil {
		return err
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
			PidNsId: targetPIDNSID,
		},
	}); err != nil {
		return err
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogLevel:    0,
			LogSize:     200_000_000,
			LogDisabled: false,
			KernelTypes: kernelTypes,
		},
		MapReplacements: nil,
	}); err != nil {
		return err
	}

	m.objects = &objs

	// TODO(Kvisord): Mount cgroupv2 if not mounted.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		cgroupPath = "/cgroupv2"
		m.log.Debugf("mounting cgroupv2 to path %s", cgroupPath)
		if err := mountCgroup2(cgroupPath); err != nil {
			return fmt.Errorf("mounting cgroupv2: %w", err)
		}
	}
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
	m.log.Debugf("attaching probe: %s", probe.String())
	if err := probe.attach(); err != nil {
		return err
	}
	m.attachedProbes[handle] = struct{}{}
	return nil
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroupv2 not found, need to mount")
}
