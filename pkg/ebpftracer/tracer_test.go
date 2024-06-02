package ebpftracer_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sync/errgroup"
)

func TestTracer(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx := context.Background()

	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	procHandle := proc.New()
	pidNS, err := procHandle.GetCurrentPIDNSID()
	if err != nil {
		t.Fatal(err)
	}

	tr := ebpftracer.New(log, ebpftracer.Config{
		//BTFPath:              fmt.Sprintf("./testdata/5.10.0-0.deb10.24-cloud-%s.btf", runtime.GOARCH),
		EventsPerCPUBuffer:    os.Getpagesize() * 64,
		EventsOutputChanSize:  10000,
		DefaultCgroupsVersion: "V2",
		DebugEnabled:          true,
		AllowAnyEvent:         true,
		ContainerClient: &ebpftracer.MockContainerClient{
			ContainerGetter: func(ctx context.Context, cgroupID uint64) (*containers.Container, error) {
				dummyContainerID := fmt.Sprint(cgroupID)
				return &containers.Container{
					ID:           dummyContainerID,
					Name:         "dummy-container",
					CgroupID:     cgroupID,
					PodNamespace: "default",
					PodUID:       dummyContainerID,
					PodName:      "dummy-container-" + dummyContainerID,
					Cgroup: &cgroup.Cgroup{
						Id:               cgroupID,
						Version:          cgroup.V2,
						ContainerRuntime: cgroup.ContainerdRuntime,
						ContainerID:      dummyContainerID,
						Path:             "",
					},
					PIDs: []uint32{},
				}, nil
			},
		},
		CgroupClient:                       &ebpftracer.MockCgroupClient{},
		MountNamespacePIDStore:             getInitializedMountNamespacePIDStore(procHandle),
		HomePIDNS:                          pidNS,
		NetflowSampleSubmitIntervalSeconds: 0,
		NetflowGrouping:                    ebpftracer.NetflowGroupingDropSrcPort,
	})
	defer tr.Close()

	if err := tr.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- tr.Run(ctx)
	}()

	signatures, err := signature.DefaultSignatures(log, signature.DefaultSignatureConfig{
		TTYDetectedSignatureEnabled:    true,
		SOCKS5DetectedSignatureEnabled: true,
	})
	if err != nil {
		t.Fatalf("error while configuring signatures: %v", err)
	}

	signatureEngine := signature.NewEngine(signatures, log, signature.SignatureEngineConfig{
		InputChanSize:  100,
		OutputChanSize: 100,
	})
	sigerr := make(chan error, 1)
	go func() {
		sigerr <- signatureEngine.Run(ctx)
	}()

	policy := &ebpftracer.Policy{
		Events: []*ebpftracer.EventPolicy{
			{ID: events.NetFlowBase},
			//{ID: events.SchedProcessExec},
			//{ID: events.SecuritySocketConnect},
			//{ID: events.SockSetState},
			//{ID: events.NetPacketDNSBase},
		},
	}

	if err := tr.ApplyPolicy(policy); err != nil {
		t.Fatalf("apply policy: %v", err)
	}

	//go printSyscallStatsLoop(ctx, tr, log)

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sigerr:
			t.Fatal(err)
		case s := <-signatureEngine.Events():
			printSignatureEvent(s)
		case e := <-tr.Events():
			printEvent(tr, e)
		case e := <-tr.NetflowEvents():
			printEvent(tr, e)
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

// NC_ADDR=localhost:8000 go test -v -count=1 . -run=TestGenerateConn
func TestGenerateConn(t *testing.T) {
	addr := os.Getenv("NC_ADDR")
	if addr == "" {
		t.Skip()
	}

	var errg errgroup.Group
	for i := 0; i < 100; i++ {
		errg.Go(func() error {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := conn.Write([]byte(fmt.Sprintf("hi %d\n", i))); err != nil {
				return err
			}
			return nil
		})
	}
	err := errg.Wait()
	if err != nil {
		t.Fatal(err)
	}
}

func printSignatureEvent(e *castaipb.Event) {
	fmt.Printf(
		"cgroup=%d, pid=%d, proc=%s, event=%s,args=%+v",
		e.CgroupId,
		e.HostPid,
		e.ProcessName,
		e.EventType,
		e.Data,
	)
	fmt.Print("\n")
}

func getInitializedMountNamespacePIDStore(procHandler *proc.Proc) *types.PIDsPerNamespace {
	mountNamespacePIDStore, err := types.NewPIDsPerNamespaceCache(2048, 5)
	if err != nil {
		panic(err)
	}

	processes, err := procHandler.LoadMountNSOldestProcesses()
	if err != nil {
		panic(err)
	}

	for ns, pid := range processes {
		mountNamespacePIDStore.ForceAddToBucket(ns, pid)
	}

	return mountNamespacePIDStore
}

func printEvent(tr *ebpftracer.Tracer, e *types.Event) {
	eventName := tr.GetEventName(e.Context.EventID)
	procName := string(bytes.TrimRight(e.Context.Comm[:], "\x00"))
	fmt.Printf(
		"ts=%d cgroup=%d, pid=%d, proc=%s, event=%s, args=%+v",
		e.Context.Ts,
		e.Context.CgroupID,
		e.Context.HostPid,
		procName,
		eventName,
		e.Args,
	)
	if e.Context.EventID == events.NetFlowBase {
		fmt.Printf(" ret=%d direction=%s, type=%s, initiator=%v", e.Context.Retval, e.Context.GetFlowDirection(), e.Context.GetNetflowType(), e.Context.IsSourceInitiator())
	}
	fmt.Print("\n")
}

func printSyscallStatsLoop(ctx context.Context, tr *ebpftracer.Tracer, log *logging.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			stats, err := tr.ReadSyscallStats()
			if err != nil {
				log.Errorf("reading syscall stats: %v", err)
				continue
			}
			spew.Dump(stats)
		}
	}
}
