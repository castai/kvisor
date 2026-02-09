package debug

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/castai/kvisor/cmd/agent/daemon/cri"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/logging"
)

func NewNetflowsDebugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "netflows",
	}

	criEndpoint := cmd.Flags().String("cri-endpoint", "unix:///run/containerd/containerd.sock", "CRI endpoint")
	hostCgroupsDir := cmd.Flags().String("host-cgroups", "/cgroups", "Host /sys/fs/cgroups directory name mounted to container")
	containerdSockPath := cmd.Flags().String("containerd-sock", "/run/containerd/containerd.sock", "Path to containerd socket file")
	disableContainerd := cmd.Flags().Bool("disable-containerd", true, "Disable containerd-specific features")
	btfPath := cmd.Flags().String("btf-path", "/sys/kernel/btf/vmlinux", "btf file path")
	waitDuration := cmd.Flags().Duration("wait", 2*time.Second, "Wait duration before scraping netflows")
	limit := cmd.Flags().Int("limit", 500, "Limit netflows output")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		log := logging.New()

		procHandler := proc.New()

		pidNSID, err := procHandler.GetCurrentPIDNSID()
		if err != nil {
			return fmt.Errorf("proc handler: %w", err)
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		criClient, criCloseFn, err := cri.NewRuntimeClient(ctx, *criEndpoint)
		if err != nil {
			return fmt.Errorf("new CRI runtime client: %w", err)
		}
		defer criCloseFn() //nolint:errcheck

		cgroupClient, err := cgroup.NewClient(log, *hostCgroupsDir, procHandler.PSIEnabled())
		if err != nil {
			return err
		}

		containersClient, err := containers.NewClient(log, cgroupClient, *containerdSockPath, *disableContainerd, procHandler, criClient, []string{}, []string{})
		if err != nil {
			return err
		}
		defer containersClient.Close()

		tr := ebpftracer.New(log, ebpftracer.Config{
			BTFPath:                    *btfPath,
			SignalEventsRingBufferSize: 1 << 20,
			EventsRingBufferSize:       1 << 20,
			SkbEventsRingBufferSize:    1 << 20,
			EventsOutputChanSize:       1024,
			DefaultCgroupsVersion:      cgroupClient.DefaultCgroupVersion().String(),
			ContainerClient:            containersClient,
			CgroupClient:               cgroupClient,
			AutomountCgroupv2:          true,
			SignatureEngine:            nil,
			MountNamespacePIDStore:     nil,
			HomePIDNS:                  pidNSID,
			NetflowGrouping:            0,
			NetflowsEnabled:            true,
			PodName:                    os.Getenv("POD_NAME"),
		})

		if err := tr.Load(); err != nil {
			return err
		}

		defer tr.Close()

		if err := tr.ApplyPolicy(&ebpftracer.Policy{
			SystemEvents:    nil,
			SignatureEvents: nil,
			Events: []*ebpftracer.EventPolicy{
				{
					ID: events.NetFlowBase,
				},
			},
		}); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*waitDuration):
		}

		keys, vals, err := tr.CollectNetworkSummary()
		if err != nil {
			return err
		}

		log.Infof("found %d total netflows", len(keys))

		t := table.NewWriter()

		t.AppendHeader(table.Row{"Comm", "Cgroup", "PID", "Protocol", "From", "To", "Tx Bytes", "Tx Packets", "Rx Bytes", "Rx Packets"})
		t.SetAutoIndex(true)
		t.SetStyle(table.StyleLight)
		t.Style().Options.SeparateRows = true
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, AutoMerge: true},
		})

		if len(keys) > *limit {
			keys = keys[:*limit]
		}

		for i, key := range keys {
			val := vals[i]

			var (
				daddr netip.Addr
				saddr netip.Addr
			)

			switch key.Tuple.Family {
			case uint16(types.AF_INET):
				if ip, ok := netip.AddrFromSlice(key.Tuple.Saddr.Raw[:4]); ok {
					saddr = ip
				} else {
					log.Warnf("cannot parse local addr v4 `%v`", key.Tuple.Saddr.Raw[:4])
				}

				if ip, ok := netip.AddrFromSlice(key.Tuple.Daddr.Raw[:4]); ok {
					daddr = ip
				} else {
					log.Warnf("cannot parse remote addr v4 `%v`", key.Tuple.Daddr.Raw[:4])
				}
			case uint16(types.AF_INET6):
				saddr = netip.AddrFrom16(key.Tuple.Saddr.Raw)
				daddr = netip.AddrFrom16(key.Tuple.Daddr.Raw)
			}

			t.AppendRow(table.Row{
				string(bytes.SplitN(val.Comm[:], []byte{0}, 2)[0]),
				key.ProcessIdentity.CgroupId,
				key.ProcessIdentity.Pid,
				key.Proto,
				fmt.Sprintf("%s:%d", saddr, key.Tuple.Sport),
				fmt.Sprintf("%s:%d", daddr, key.Tuple.Dport),
				val.TxBytes,
				val.TxPackets,
				val.RxBytes,
				val.RxPackets,
			})
		}

		fmt.Println(t.Render())
		return nil
	}

	return cmd
}
