package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEventContextFile(t *testing.T) {
	r := require.New(t)

	data, err := os.ReadFile("testdata/context.txt")
	r.NoError(err)

	contextDefinition, err := parseEventContextFile("testdata/definition.go", string(data))
	r.NoError(err)

	r.Len(contextDefinition.fields, 20)

	sourceNames := make([]string, len(contextDefinition.fields))
	for i, cf := range contextDefinition.fields {
		sourceNames[i] = cf.source
	}

	r.Equal([]string{
		"Ts",
		"Task.StartTime",
		"Task.CgroupId",
		"Task.Pid",
		"Task.Tid",
		"Task.Ppid",
		"Task.HostPid",
		"Task.HostTid",
		"Task.HostPpid",
		"Task.NodeHostPid",
		"Task.Uid",
		"Task.MntId",
		"Task.PidId",
		"Task.Comm",
		"Task.LeaderStartTime",
		"Task.ParentStartTime",
		"Eventid",
		"Syscall",
		"Retval",
		"ProcessorId",
	},
		sourceNames)
}
