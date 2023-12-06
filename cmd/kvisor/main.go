package main

import (
	"fmt"
	"os"

	"github.com/castai/kvisor/cmd/kvisor/agent"
	"github.com/castai/kvisor/cmd/kvisor/imgcollector"
	kubebench2 "github.com/castai/kvisor/cmd/kvisor/kubebench"
	"github.com/spf13/cobra"
)

// These should be set via `go build` during a release.
var (
	GitCommit = "undefined"
	GitRef    = "no-ref"
	Version   = "local"
)

func main() {
	root := cobra.Command{
		Use: "kvisor",
	}

	kubeBenchCmd := kubebench2.NewCommand()
	kubeBenchCmd.AddCommand(kubebench2.NewRunCommand())

	root.AddCommand(
		agent.NewCommand(Version, GitCommit, GitRef),
		imgcollector.NewCommand(Version, GitCommit),
		kubeBenchCmd,
	)

	if err := root.Execute(); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
