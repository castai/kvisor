package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinterRuleSet(t *testing.T) {
	r := require.New(t)

	set := new(LinterRuleSet)
	r.False(set.Has(RunAsNonRoot))
	set.Add(RunAsNonRoot)
	r.True(set.Has(RunAsNonRoot))
	set.Add(WritableHostMount)
	set.Add(LatestTag)
	r.Len(set.Rules(), 3)
	r.Contains(set.Rules(), "latest-tag")
	r.Contains(set.Rules(), "writable-host-mount")
	r.Contains(set.Rules(), "run-as-non-root")
}
