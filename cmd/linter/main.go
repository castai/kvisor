package main

import (
	"log/slog"
	"os"

	"github.com/castai/kvisor/cmd/linter/kubebench"
	"github.com/spf13/cobra"
)

var (
	Version = "local"
)

func main() {
	root := cobra.Command{
		Use: "kvisor-linter",
	}

	root.AddCommand(
		kubebench.NewCommand(),
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
