package main

import (
	"log/slog"
	"os"

	"github.com/castai/kvisor/cmd/agent/daemon"
	"github.com/castai/kvisor/cmd/agent/imagescan"
	"github.com/castai/kvisor/cmd/agent/kubebench"
	"github.com/spf13/cobra"
)

var (
	Version = "local"
)

func main() {
	root := cobra.Command{
		Use: "kvisor",
	}

	root.AddCommand(
		daemon.NewCommand(Version),
		imagescan.NewCommand(Version),
		kubebench.NewCommand(),
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
