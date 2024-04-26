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
		Use: "kvisor-image-scanner",
	}

	root.AddCommand(
		NewCommand(Version),
	)

	if err := root.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
