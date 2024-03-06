package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	type testCase struct {
		title               string
		filePath            string
		src                 string
		expectedDefinitions []eventDefinition
		expectError         bool
	}

	testCases := []testCase{
		{
			title:    "parse simple definitions",
			filePath: "./events.go",
			src: `package ebpftracer

import (
	"github.com/castai/kvisord/pkg/ebpftracer/events"
)

func newEventsDefinitionSet(objs *tracerObjects) map[events.ID]definition {
	return map[events.ID]definition{
		events.Read: {
			ID:      events.Read,
			id32Bit: events.Sys32read,
			name:    "read",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []argMeta{
				{Type: "int", Name: "fd"},
				{Type: "void*", Name: "buf"},
				{Type: "size_t", Name: "count"},
			},
		},
		events.Open: {
			ID:      events.Open,
			id32Bit: events.Sys32open,
			name:    "open",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_file_ops"},
			params: []argMeta{
				{Type: "const char*", Name: "pathname"},
				{Type: "int", Name: "flags"},
				{Type: "mode_t", Name: "mode"},
			},
		},
		events.TrackSyscallStats: {
			ID:           events.TrackSyscallStats,
			id32Bit:      events.Sys32Undefined,
			name:         "track_syscall_stats",
			syscall:      true,
			sets:         []string{"syscalls"},
			dependencies: dependencies{skipDefaultTailCalls: true},
			params:       []argMeta{},
		},
  }
}
`,
			expectedDefinitions: []eventDefinition{
				{
					event: "Read",
					params: []param{
						{name: "fd", paramType: intT},
						{name: "buf", paramType: pointerT},
						{name: "count", paramType: sizeT},
					},
				},
				{
					event: "Open",
					params: []param{
						{name: "pathname", paramType: strT},
						{name: "flags", paramType: intT},
						{name: "mode", paramType: modeT},
					},
				},
				{
					event: "TrackSyscallStats",
				},
			},
		},

		{
			title:    "should fail on invalid event definition referencing variable",
			filePath: "./events.go",
			src: `package ebpftracer

import (
	"github.com/castai/kvisord/pkg/ebpftracer/events"
)

func newEventsDefinitionSet(objs *tracerObjects) map[events.ID]definition {
	return map[events.ID]definition{
		events.Read: {
			ID:      events.Read,
			id32Bit: events.Sys32read,
			name:    "read",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []argMeta{
				{Type: "int", Name: fdName},
			},
		},
  }
}
`,
			expectError: true,
		},

		{
			title:    "should fail on key not from events package",
			filePath: "./events.go",
			src: `package ebpftracer

import (
	"github.com/castai/kvisord/pkg/ebpftracer/events"
)

func newEventsDefinitionSet(objs *tracerObjects) map[events.ID]definition {
	return map[events.ID]definition{
		Read: {
			ID:      events.Read,
			id32Bit: events.Sys32read,
			name:    "read",
			syscall: true,
			sets:    []string{"syscalls", "fs", "fs_read_write"},
			params: []argMeta{
				{Type: "int", Name: "fs"},
			},
		},
  }
}
`,
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			result, err := parseEventDefinitionSetForFile(test.filePath, test.src)
			if test.expectError {
				r.Error(err)
				return
			}

			r.Len(result, len(test.expectedDefinitions))

			for i, ed := range test.expectedDefinitions {
				r.Equal(ed.event, result[i].event)
				r.Len(result[i].params, len(ed.params), "event: %s", ed.event)

				params := result[i].params

				for paramIdx, param := range ed.params {
					r.Equal(param.name, params[paramIdx].name, "event: %s, paramIdx: %d", ed.event, paramIdx)
					r.Equal(param.paramType, params[paramIdx].paramType, "event: %s, param: %s", ed.event, param.name)
				}
			}
		})
	}
}
