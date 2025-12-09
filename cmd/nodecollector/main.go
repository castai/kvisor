package main

import (
	"log/slog"
	"os"

	"github.com/castai/kvisor/cmd/nodecollector/nodecomponentscollector"
	"github.com/spf13/cobra"
)

var (
	Version = "local"
)

func main() {
	root := cobra.Command{
		Use: "nodecollector",
	}

	root.AddCommand(
		nodecomponentscollector.NewRunCommand(Version),
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
