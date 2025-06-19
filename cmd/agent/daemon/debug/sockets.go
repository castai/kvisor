package debug

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/castai/kvisor/pkg/ebpftracer/debug"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func NewSocketDebugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "sockets",
	}

	var (
		targetPID = cmd.Flags().Uint32("kvisor-pid", 0, "PID of kvisor process to get data from")
	)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		log := logging.New(&logging.Config{})
		d, err := debug.New(log, debug.DebugCfg{
			TargetPID: *targetPID,
		})
		if err != nil {
			return err
		}

		if err := d.Load(); err != nil {
			return err
		}

		sockIter := d.SocketInfoIterator()

		t := table.NewWriter()

		t.AppendHeader(table.Row{"Process", "Process", "Process", "Process", "Socket", "Socket", "Socket", "Socket"}, table.RowConfig{AutoMerge: true})
		t.AppendHeader(table.Row{"Cgroup", "PID", "Host PID", "Comm", "Protocol", "From", "To", "State", "Inode"})
		t.SetAutoIndex(true)
		t.SetStyle(table.StyleLight)
		t.Style().Options.SeparateRows = true
		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, AutoMerge: true},
			{Number: 2, AutoMerge: true},
		})

		displayWarning := false

		for _, d := range sockIter.Iter() {
			if d.Netctx.Taskctx.Pid == 0 {
				displayWarning = true
				continue
			}

			t.AppendRow(table.Row{
				d.Netctx.Taskctx.CgroupId,
				d.Netctx.Taskctx.Pid,
				d.Netctx.Taskctx.HostPid,
				string(d.Netctx.Taskctx.Comm[:]),
				formatProto(d.SockInfo.Proto),
				formatAddr(d.SockInfo.Tuple.Saddr.Raw, d.SockInfo.Tuple.Sport, d.SockInfo.Family),
				formatAddr(d.SockInfo.Tuple.Daddr.Raw, d.SockInfo.Tuple.Dport, d.SockInfo.Family),
				formatSockState(d.SockInfo.State, d.SockInfo.Proto),
				d.SockInfo.Ino,
			})
		}

		fmt.Println(t.Render())

		if displayWarning {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "warning: some sockets could not be associated with any processes and might be missing")
		}

		return nil
	}

	return cmd
}

func formatSockState(state, proto uint8) string {
	if proto == unix.IPPROTO_TCP || proto == unix.IPPROTO_UDP {
		switch state {
		case 1:
			return "ESTABLISHED"
		case 2:
			return "SYN_SENT"
		case 3:
			return "SYN_RECV"
		case 4:
			return "FIN_WAIT1"
		case 5:
			return "FIN_WAIT2"
		case 6:
			return "TIME_WAIT"
		case 7:
			return "CLOSE"
		case 8:
			return "CLOSE_WAIT"
		case 9:
			return "LAST_ACK"
		case 10:
			return "LISTEN"
		case 11:
			return "CLOSING"
		case 12:
			return "NEW_SYN_RECV"
		case 13:
			return "MAX_STATES"
		}
	}

	return strconv.FormatUint(uint64(state), 10)
}

func formatProto(proto uint8) string {
	switch proto {
	case unix.IPPROTO_ICMP:
		return "ICMP"
	case unix.IPPROTO_ICMPV6:
		return "ICMP6"
	case unix.IPPROTO_TCP:
		return "TCP"
	case unix.IPPROTO_UDP:
		return "UDP"
	}

	return strconv.FormatUint(uint64(proto), 10)
}

func formatAddr(addr [16]byte, port uint16, family uint16) string {
	ip := formatIP(addr, family)
	return fmt.Sprintf("%s:%d", ip, port)
}

func formatIP(addr [16]byte, family uint16) string {
	switch family {
	case unix.AF_INET:
		addr, _ := netip.AddrFromSlice(addr[:4])
		return addr.String()
	case unix.AF_INET6:
		addr := netip.AddrFrom16(addr)
		return addr.String()
	}

	return "<unknown>"
}
