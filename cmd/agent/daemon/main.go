package main

import (
	"log/slog"
	"os"

	"github.com/castai/kvisor/cmd/agent/daemon/debug"
	"github.com/spf13/cobra"
)

var (
	Version = "local"
)

func main() {
	root := cobra.Command{
		Use: "kvisor-daemon",
	}

	debugCmd := &cobra.Command{
		Use: "debug",
	}
	debugCmd.AddCommand(debug.NewSocketDebugCommand())
	debugCmd.AddCommand(debug.NewNetflowsDebugCommand())

	root.AddCommand(
		NewRunCommand(Version),
		NewClickhouseInitCommand(),
		debugCmd,
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
