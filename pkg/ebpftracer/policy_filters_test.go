package ebpftracer

import (
	"errors"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestFilterAnd(t *testing.T) {
	errFilterFail := errors.New("")

	filterPass := GlobalEventFilterGenerator(
		func(event *types.Event) error {
			return FilterPass
		},
	)

	filterFail := GlobalEventFilterGenerator(
		func(event *types.Event) error {
			return errFilterFail
		},
	)

	type testCase struct {
		name     string
		filters  []EventFilterGenerator
		expected error
	}

	testCases := []testCase{
		{
			name:     "multiple filters all returning true should produce true",
			filters:  []EventFilterGenerator{filterPass, filterPass, filterPass},
			expected: FilterPass,
		},
		{
			name:     "multiple filter one returning false should produce false",
			filters:  []EventFilterGenerator{filterPass, filterPass, filterFail},
			expected: errFilterFail,
		},
		{
			name:     "single true filter should return true",
			filters:  []EventFilterGenerator{filterPass},
			expected: FilterPass,
		},
		{
			name:     "single false filter should return false",
			filters:  []EventFilterGenerator{filterFail},
			expected: errFilterFail,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			combinedFilters := FilterAnd(testCase.filters...)()

			actual := combinedFilters(&types.Event{})

			require.Equal(t, testCase.expected, actual)
		})
	}
}

func TestDNSPolicyFilter(t *testing.T) {
	r := require.New(t)
	log := logging.NewTestLog()
	f := DeduplicateDnsEvents(log, 2, 1*time.Hour)
	g := f()

	// Pass non dns event.
	err := g(&types.Event{Context: &types.EventContext{EventID: events.Connect}})
	r.NoError(err)

	// Pass first dns event.
	dnsEvent := &types.Event{
		Context: &types.EventContext{EventID: events.NetPacketDNSBase},
		Args: types.NetPacketDNSBaseArgs{
			Payload: &castaipb.DNS{DNSQuestionDomain: "google.com"},
		},
	}
	err = g(dnsEvent)
	r.NoError(err)

	// Should not pass since this is duplicate.
	err = g(dnsEvent)
	r.ErrorIs(err, FilterErrDNSDuplicateDetected)
}
