package debug

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type net_task_context -type task_context -type debug_socket_context -type socket_info -type tuple_t -type process_bpf_map -no-global-types -cc clang-14 -strip=llvm-strip -target arm64 debug c/debug.bpf.c -- -I../c/headers -Wno-address-of-packed-member -O2
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type net_task_context -type task_context -type debug_socket_context -type socket_info -type tuple_t -type process_bpf_map -no-global-types -cc clang-14 -strip=llvm-strip -target amd64 debug c/debug.bpf.c -- -I../c/headers -Wno-address-of-packed-member -O2

type PID = uint32

type DebugCfg struct {
	TargetPID PID
}

type Debug struct {
	loaded          atomic.Bool
	objects         *debugObjects
	log             *logging.Logger
	socketTargetMap *ebpf.Map
	cfg             DebugCfg
}

const targetMapName = "net_taskctx_map"

var (
	errKvisorNotDetected = errors.New("kvisor-agent not detected")
	errTargetMapNotFound = fmt.Errorf("map `%s` not found", targetMapName)
)

func guessTargetPID(log *logging.Logger) (PID, error) {
	processes, err := proc.New().SnapshotProcessTree(1)
	if err != nil {
		return 0, fmt.Errorf("error while loading processes from /proc: %w", err)
	}

	var kvisorPIDs []proc.PID
	var kvisorAgentDetected bool

	for _, p := range processes {
		// Binary name when kvisor runs as a container.
		if path.Base(p.FilePath) == "kvisor-agent" {
			kvisorAgentDetected = true
			kvisorPIDs = append(kvisorPIDs, p.PID)
			log.Infof("detected kvisor-agent running as PID %d", p.PID)
			continue
		}

		// Case for detecting test tracer. If for whatever reason we already detected a kvisor-agent running,
		// test executions are ignored.
		if !kvisorAgentDetected && path.Base(p.FilePath) == "ebpftracer.test" &&
			slices.ContainsFunc(p.Args, func(arg string) bool {
				return strings.Contains(arg, "-test.run=TestTracer")
			}) {
			log.Infof("detected kvisor test running as PID %d", p.PID)
			kvisorPIDs = append(kvisorPIDs, p.PID)
			continue
		}
	}

	if len(kvisorPIDs) == 1 {
		return kvisorPIDs[0], nil
	} else if len(kvisorPIDs) > 1 {
		return 0, fmt.Errorf("error: detected multiple kvisor-agent versions with the following PIDs: %v", kvisorPIDs)
	}

	return 0, errKvisorNotDetected
}

func New(log *logging.Logger, cfg DebugCfg) (*Debug, error) {
	if cfg.TargetPID == 0 {
		pid, err := guessTargetPID(log)
		if err != nil {
			return nil, fmt.Errorf("error while trying to find target pid: %w", err)
		}
		cfg.TargetPID = pid
	}

	return &Debug{
		log: log,
		cfg: cfg,
	}, nil
}

func (d *Debug) Load() error {
	if !d.loaded.CompareAndSwap(false, true) {
		return fmt.Errorf("debug ebpf modules already loaded")
	}

	spec, err := loadDebug()
	if err != nil {
		return fmt.Errorf("error while loading spec: %w", err)
	}

	var objects debugObjects

	ksymAddrs := map[string]uint64{"bpf_map_fops": 0}
	if err := proc.LoadSymbolAddresses(ksymAddrs); err != nil {
		return fmt.Errorf("error while resolving kallsym addresses: %w", err)
	}

	if err := spec.RewriteConstants(map[string]any{
		"target_pid":   d.cfg.TargetPID,
		"bpf_map_fops": ksymAddrs["bpf_map_fops"],
	}); err != nil {
		return fmt.Errorf("error while rewriting constants: %w", err)
	}

	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Maps:            ebpf.MapOptions{},
		Programs:        ebpf.ProgramOptions{},
		MapReplacements: map[string]*ebpf.Map{},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			d.log.Errorf("Verifier error: %+v", ve)
		}
		return fmt.Errorf("error while loading ebpf programs: %w", err)
	}

	targetMap, err := findTargetMap(d.log, objects.debugPrograms.IterMaps)
	if err != nil {
		return fmt.Errorf("error while searching for target map: %w", err)
	}

	d.objects = &objects
	d.socketTargetMap = targetMap

	return nil
}

type SocketDebugInfo debugDebugSocketContext

func findTargetMap(log *logging.Logger, iterProg *ebpf.Program) (*ebpf.Map, error) {
	iter, err := link.AttachIter(link.IterOptions{
		Program: iterProg,
	})
	if err != nil {
		return nil, fmt.Errorf("error while attaching map iterator: %w", err)
	}
	defer iter.Close()

	r, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("error while opening map iterator output: %w", err)
	}
	defer r.Close()

	for {
		var m debugProcessBpfMap

		if err := binary.Read(r, binary.NativeEndian, &m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error while reading from map iterator output: %w", err)
		}
		ebpfMap, err := ebpf.NewMapFromID(ebpf.MapID(m.MapId))
		if err != nil {
			return nil, fmt.Errorf("error while loading map from id: %w", err)
		}

		mapName := string(bytes.SplitN(m.Name[:], []byte{0}, 2)[0])
		// Going by name is the easies solution to find the target map. We need to use a prefix
		// check, as map names are cut of after a certain number of chars.
		if !strings.HasPrefix("net_taskctx_map", mapName) {
			if err := ebpfMap.Close(); err != nil {
				log.Warnf("error while closing ebpf map `%s`: %v", mapName, err)
			}
			continue
		} else {
			return ebpfMap, nil
		}
	}

	return nil, errTargetMapNotFound
}

type SockeDebugInfoIterator struct {
	debug *Debug
	err   error
}

func (i *SockeDebugInfoIterator) Iter() func(func(int, SocketDebugInfo) bool) {
	return func(yield func(int, SocketDebugInfo) bool) {
		socketMapIter, err := link.AttachIter(link.IterOptions{
			Program: i.debug.objects.DebugSockmapIterator,
			Map:     i.debug.socketTargetMap,
		})
		if err != nil {
			i.err = fmt.Errorf("error while attaching iterator: %w", err)
			return
		}
		defer socketMapIter.Close()

		r, err := socketMapIter.Open()
		if err != nil {
			i.err = fmt.Errorf("error while opening iterator output: %w", err)
			return
		}
		defer r.Close()

		var c int

		for {
			var netTaskContext SocketDebugInfo

			// Since debugNetTaskContext is generated from the C struct, we are able to simply read it
			// with binary.Read. This is more or less the same that cilium/ebpf is doing internally as well.
			if err := binary.Read(r, binary.NativeEndian, &netTaskContext); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				i.err = fmt.Errorf("error while reading from iterator output: %w", err)
				return
			}

			c++
			if !yield(c, netTaskContext) {
				return
			}
		}
	}
}

func (i *SockeDebugInfoIterator) Err() error {
	return i.err
}

func (d *Debug) SocketInfoIterator() SockeDebugInfoIterator {
	return SockeDebugInfoIterator{
		debug: d,
	}
}
