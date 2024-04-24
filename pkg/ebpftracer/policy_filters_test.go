package ebpftracer

import (
	"errors"
	"testing"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
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
