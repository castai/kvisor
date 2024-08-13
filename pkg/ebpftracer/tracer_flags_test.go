package ebpftracer

import (
	"errors"
	"testing"

	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/stretchr/testify/require"
)

func TestParseNetflowGrouping(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    NetflowGrouping
		wantErr error
	}{
		{
			name: "empty returns valid zero result", input: "", want: 0,
		},
		{
			name: "single group value", input: "drop_src_port", want: NetflowGroupingDropSrcPort,
		},
		{
			name: "multiple group values", input: "drop_src_port|drop_src_port", want: NetflowGroupingDropSrcPort,
		},
		{
			name: "invalid group", input: "not_found", wantErr: errors.New("unknown grouping flag \"not_found\""),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			res, err := parseNetflowGrouping(test.input)
			if test.wantErr != nil {
				r.EqualError(err, test.wantErr.Error())
			}
			r.Equal(test.want, res)
		})
	}
}

func TestParseEventsPolicyConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    EventsPolicyConfig
		wantErr error
	}{
		{
			name: "empty returns valid zero result", input: "", want: EventsPolicyConfig{EnabledEvents: []events.ID{}},
		},
		{
			name: "single event", input: "magic_write", want: EventsPolicyConfig{EnabledEvents: []events.ID{events.MagicWrite}},
		},
		{
			name: "multiple events", input: "magic_write,sched_process_exec", want: EventsPolicyConfig{
				EnabledEvents: []events.ID{events.MagicWrite, events.SchedProcessExec},
			},
		},
		{
			name: "invalid events", input: "not_found", wantErr: errors.New("unknown event name \"not_found\""),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			res := EventsPolicyConfig{}
			err := res.Set(test.input)
			if test.wantErr != nil {
				r.EqualError(err, test.wantErr.Error())
				return
			}
			r.Equal(test.want, res)
		})
	}
}
