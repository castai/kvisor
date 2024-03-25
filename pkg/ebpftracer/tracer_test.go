package ebpftracer_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/conntrack"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/davecgh/go-spew/spew"
)

func TestTracer(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx := context.Background()

	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	ct, err := conntrack.NewClient(log)
	if err != nil {
		t.Fatal(err)
	}
	defer ct.Close()

	procHandle := proc.New()
	pidNS, err := procHandle.GetCurrentPIDNSID()
	if err != nil {
		t.Fatal(err)
	}

	tr := ebpftracer.New(log, ebpftracer.Config{
		//BTFPath:              fmt.Sprintf("./testdata/5.10.0-0.deb10.24-cloud-%s.btf", runtime.GOARCH),
		EventsPerCPUBuffer:      os.Getpagesize() * 64,
		EventsOutputChanSize:    10000,
		ActualDestinationGetter: ct,
		DefaultCgroupsVersion:   "V2",
		DebugEnabled:            true,
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
		CgroupClient: &ebpftracer.MockCgroupClient{},
		EnrichEvent: func(er *enrichment.EnrichRequest) bool {
			return false
		},
		MountNamespacePIDStore: getInitializedMountNamespacePIDStore(procHandle),
		HomePIDNS:              pidNS,
	})
	defer tr.Close()

	if err := tr.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- tr.Run(ctx)
	}()

	signatureEngine := signature.NewEngine(signature.DefaultSignatures(log), log, signature.SignatureEngineConfig{
		InputChanSize:  0,
		OutputChanSize: 0,
	})

	policy := &ebpftracer.Policy{
		SignatureEngine: signatureEngine,
		Events: []*ebpftracer.EventPolicy{
			{ID: events.SchedProcessExec},
			{ID: events.SockSetState},
			//{ID: events.SecuritySocketConnect},
			//{ID: events.CgroupRmdir},
			// {ID: events.TrackSyscallStats},
			{ID: events.NetPacketDNS},
			//{
			//	ID: events.FileModification,
			//	RateLimit: &events.RateLimitPolicy{
			//		Interval: 2 * time.Second,
			//	},
			//},
			//{ID: events.CgroupMkdir},
			//{ID: events.CgroupRmdir},
			// {ID: events.ProcessOomKilled},
			// {ID: events.MagicWrite},
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
		case e := <-tr.Events():
			_ = e
			printEvent(e)
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		}
	}
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

func printEvent(event *castpb.Event) {
	fmt.Print(event.CgroupId, ": ", event.GetEventType(), "->", event.GetProcessName(), " ")
	switch event.EventType {
	case castpb.EventType_EVENT_TCP_LISTEN, castpb.EventType_EVENT_TCP_CONNECT, castpb.EventType_EVENT_TCP_CONNECT_ERROR:
		tuple := event.GetTuple()
		fmt.Print(tuple.GetDstIp())
	case castpb.EventType_EVENT_FILE_CHANGE:
		fmt.Print(event.GetFile().GetPath())
	case castpb.EventType_EVENT_DNS:
		fmt.Print(event.GetDns())
	case castpb.EventType_EVENT_MAGIC_WRITE:
		fmt.Print(event.GetFile().GetPath())
	case castpb.EventType_EVENT_SIGNATURE:
		signatureEvent := event.GetSignature()

		fmt.Printf("signature event: %s %s", signatureEvent.Metadata.Id.String(), signatureEvent.Metadata.Version)
	}

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
