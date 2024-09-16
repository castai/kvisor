package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEventDefinitionSetForFile(t *testing.T) {
	r := require.New(t)

	data, err := os.ReadFile("testdata/definition.txt")
	r.NoError(err)

	contextDefinition, err := parseEventDefinitionSetForFile("testdata/definition.go", string(data))
	r.NoError(err)

	r.Len(contextDefinition.fields, 21)
	r.EqualValues(0x78, contextDefinition.totalSize())

	names := make([]string, len(contextDefinition.fields))
	for i, cf := range contextDefinition.fields {
		names[i] = cf.name
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
    "_",
  },
		names)
}
