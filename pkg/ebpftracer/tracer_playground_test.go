package ebpftracer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
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
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		t.Skip(err)
	}

	signatures, err := signature.DefaultSignatures(log, signature.SignatureEngineConfig{
		DefaultSignatureConfig: signature.DefaultSignatureConfig{
			SOCKS5DetectedSignatureEnabled: false,
		},
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

	tr := ebpftracer.New(log, ebpftracer.Config{
		//BTFPath:              fmt.Sprintf("./testdata/5.10.0-0.deb10.24-cloud-%s.btf", runtime.GOARCH),
		EventsOutputChanSize:       10000,
		SignalEventsRingBufferSize: 1 << 12,
		EventsRingBufferSize:       1 << 12,
		SkbEventsRingBufferSize:    1 << 12,

		DefaultCgroupsVersion: "V2",
		DebugEnabled:          true,
		AllowAnyEvent:         true,
		SignatureEngine:       signatureEngine,
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
		NetflowSampleSubmitIntervalSeconds: 2,
		NetflowGrouping:                    ebpftracer.NetflowGroupingDropSrcPort,
		ProcessTreeCollector:               processtree.NewNoop(),
		MetricsReporting: ebpftracer.MetricsReportingConfig{
			ProgramMetricsEnabled: true,
			TracerMetricsEnabled:  true,
		},
	})
	defer tr.Close()

	if err := tr.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- tr.Run(ctx)
	}()

	go func() {
		//errc <- printNetworkTracerSummary(ctx, log, tr)
	}()

	policy := &ebpftracer.Policy{
		Events: []*ebpftracer.EventPolicy{
			{ID: events.SockSetState},
			{ID: events.SchedProcessExec},
			{ID: events.NetPacketDNSBase},
			{ID: events.MagicWrite},
			{ID: events.ProcessOomKilled},
			{ID: events.StdioViaSocket},
			{ID: events.TtyWrite},
			{ID: events.NetPacketSSHBase},
		},
		SignatureEvents: signatureEngine.TargetEvents(),
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
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func printNetworkTracerSummary(ctx context.Context, log *logging.Logger, t *ebpftracer.Tracer) error {
	ticker := time.NewTicker(5 * time.Second)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			data, err := t.CollectNetworkSummary()
			if err != nil {
				log.Errorf("error while collecting network traffic summary: %v", err)
				continue
			}

			fmt.Println("=== Network Summary")
			for tk, ts := range data {
				var (
					daddr netip.Addr
					saddr netip.Addr
				)

				switch tk.Tuple.Family {
				case uint16(types.AF_INET):
					if ip, ok := netip.AddrFromSlice(tk.Tuple.Saddr.Raw[:4]); ok {
						saddr = ip
					} else {
						log.Warnf("cannot parse local addr v4 `%v`", tk.Tuple.Saddr.Raw[:4])
					}

					if ip, ok := netip.AddrFromSlice(tk.Tuple.Daddr.Raw[:4]); ok {
						daddr = ip
					} else {
						log.Warnf("cannot parse remote addr v4 `%v`", tk.Tuple.Daddr.Raw[:4])
					}
				case uint16(types.AF_INET6):
					saddr = netip.AddrFrom16(tk.Tuple.Saddr.Raw)
					daddr = netip.AddrFrom16(tk.Tuple.Daddr.Raw)
				}

				fmt.Printf("%s PID %d (protocol: %d): %s:%d -> %s:%d TX: %d RX: %d TX_Packets: %d RX_Packets: %d\n",
					string(bytes.SplitN(tk.ProcessIdentity.Comm[:], []byte{0}, 2)[0]), tk.ProcessIdentity.Pid, tk.Proto,
					saddr, tk.Tuple.Sport, daddr, tk.Tuple.Dport,
					ts.TxBytes, ts.RxBytes,
					ts.TxPackets, ts.RxPackets,
				)
			}
		}
	}
}

// Start server: nc -lk 8000
// Send data: NC_ADDR=localhost:8000 go test -v -count=1 . -run=TestGenerateConn
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

var ingoredProcesses = map[string]struct{}{
	"sshd":    {},
	"coredns": {},
	"kubelet": {},
}

func printEvent(tr *ebpftracer.Tracer, e *types.Event) {
	eventName := tr.GetEventName(e.Context.EventID)
	procName := string(bytes.TrimRight(e.Context.Comm[:], "\x00"))
	if _, ignored := ingoredProcesses[procName]; ignored {
		return
	}

	fmt.Printf(
		"ts=%d  event=%s cgroup=%d pid=%d proc=%s ",
		e.Context.Ts,
		eventName,
		e.Context.CgroupID,
		e.Context.HostPid,
		procName,
	)

	switch e.Context.EventID {
	case events.NetFlowBase:
		fmt.Printf("ret=%d direction=%s type=%s initiator=%v args=%+v", e.Context.Retval, e.Context.GetFlowDirection(), e.Context.GetNetflowType(), e.Context.IsSourceInitiator(), e.Args)
	case events.NetPacketTCPBase:
		pkt, err := createPacket(e.Args.(types.NetPacketTCPBaseArgs).Payload)
		if err != nil {
			panic(err)
		}
		l3, err := getLayer3FromPacket(pkt)
		if err != nil {
			fmt.Printf("err=%v\n", err)
			return
		}
		l4, err := getLayer4TCPFromPacket(pkt)
		if err != nil {
			fmt.Printf("err=%v\n", err)
			return
		}
		var flags []string
		if l4.SYN {
			flags = append(flags, "SYN")
		}
		if l4.ACK {
			flags = append(flags, "ACK")
		}
		if l4.RST {
			flags = append(flags, "RST")
		}
		if l4.FIN {
			flags = append(flags, "FIN")
		}
		fmt.Printf("direction=%s src=%s:%d dst=%s:%d, flags=%s", e.Context.GetFlowDirection(), l3.SrcIP.String(), l4.SrcPort, l3.DstIP.String(), l4.DstPort, strings.Join(flags, "|"))
	case events.NetPacketDNSBase:
		args, ok := e.Args.(types.NetPacketDNSBaseArgs)
		if !ok {
			panic("not dns args")
		}
		p := args.Payload
		fmt.Printf("src=%s:%d dst=%s:%d, dns_question_domain=%s", formatIP(p.Tuple.SrcIp), p.Tuple.SrcPort, formatIP(p.Tuple.DstIp), p.Tuple.DstPort, p.DNSQuestionDomain)
		for _, answer := range p.Answers {
			fmt.Printf(" answer=%s", answer.String())
		}
		fmt.Printf("\n")
	default:
		fmt.Printf("args=%+v", e.Args)
	}
	fmt.Print("\n")
}

func formatIP(ipBytes []byte) string {
	v, _ := netip.AddrFromSlice(ipBytes)
	return v.String()
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

func createPacket(payload []byte) (gopacket.Packet, error) {
	packet := gopacket.NewPacket(
		payload,
		layers.LayerTypeIPv4,
		gopacket.Default,
	)
	if packet == nil {
		return nil, errors.New("invalid packet")
	}
	return packet, nil
}

func getLayer3FromPacket(packet gopacket.Packet) (*layers.IPv4, error) {
	layer3 := packet.NetworkLayer()
	switch layer3.(type) {
	case (*layers.IPv4):
		return layer3.(*layers.IPv4), nil
	case (*layers.IPv6):
	default:
		return nil, fmt.Errorf("wrong layer 3 protocol type %T", layer3)
	}
	return nil, fmt.Errorf("todo: ipv6")
}

func getLayer4FromPacket(packet gopacket.Packet) (gopacket.TransportLayer, error) {
	layer4 := packet.TransportLayer()
	switch layer4.(type) {
	case (*layers.TCP):
	case (*layers.UDP):
	default:
		return nil, fmt.Errorf("wrong layer 4 protocol type %T", layer4)
	}
	return layer4, nil
}

func getLayer4TCPFromPacket(packet gopacket.Packet) (*layers.TCP, error) {
	layer4, err := getLayer4FromPacket(packet)
	if err != nil {
		return nil, err
	}
	tcp, ok := layer4.(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("wrong layer 4 protocol type %T", layer4)
	}
	return tcp, nil
}
