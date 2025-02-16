package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "local"
)

func main() {
	root := cobra.Command{
		Use: "kvisor-daemon",
	}

	root.AddCommand(
		NewRunCommand(Version),
		NewClickhouseInitCommand(),
		NewDebugCommand(),
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
