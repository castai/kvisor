package analyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplit(t *testing.T) {
	r := require.New(t)

	testCases := []struct {
		input     string
		separator uint8
		output1   string
		output2   string
	}{
		{
			input:     "var/lib/dpkg/info",
			separator: '/',
			output1:   "var/lib/dpkg",
			output2:   "info",
		},
		{
			input:     "var/lib/dpkg/info/",
			separator: '/',
			output1:   "var/lib/dpkg/info",
			output2:   "",
		},
		{
			input:     "lib:amd64.list",
			separator: '.',
			output1:   "lib:amd64",
			output2:   "list",
		},
		{
			input:     "lib:amd64",
			separator: ':',
			output1:   "lib",
			output2:   "amd64",
		},
		{
			input:     "lib:",
			separator: ':',
			output1:   "lib",
			output2:   "",
		},
		{
			input:     "lib",
			separator: ':',
			output1:   "lib",
			output2:   "",
		},
		{
			input:     ":lib",
			separator: ':',
			output1:   "",
			output2:   "lib",
		},
		{
			input:     "var/lib/dpkg/info/",
			separator: ':',
			output1:   "var/lib/dpkg/info/",
			output2:   "",
		},
	}

	for i := range testCases {
		output1, output2 := Split(testCases[i].input, testCases[i].separator)
		r.Equal(testCases[i].output1, output1)
		r.Equal(testCases[i].output2, output2)
	}
}

func TestBinariesPathFilter(t *testing.T) {
	testCases := []struct {
		input  string
		result bool
	}{
		{
			input:  "",
			result: false,
		},
		{
			input:  "/bin/test",
			result: true,
		},
		{
			input:  "/sbin/test",
			result: true,
		},
		{
			input:  "/usr/bin/test",
			result: true,
		},
		{
			input:  "/home/user/.local/bin/test",
			result: true,
		},
		{
			input:  "/home/user/.local/config/y.yaml",
			result: false,
		},
		{
			input:  "/usr/sbin/adduser",
			result: true,
		},
		{
			input:  "/usr/share/doc/libpam-modules-bin/changelog.gz",
			result: false,
		},
		{
			input:  "/bin",
			result: false,
		},
		{
			input:  "/bin/",
			result: false,
		},
	}

	for i := range testCases {
		if testCases[i].result != BinariesPathFilter(testCases[i].input, 0) {
			t.Errorf("expected result to be %v for %q input", testCases[i].result, testCases[i].input)
		}
	}
}