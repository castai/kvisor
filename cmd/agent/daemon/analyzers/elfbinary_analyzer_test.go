package analyzers

import (
	"os"
	"testing"

	commonpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
)

func TestElfBinaryAnalyzer(t *testing.T) {
	t.Run("parse binary", func(t *testing.T) {
		r := require.New(t)
		f, err := os.Open("./testdata/c1/rootfs/xmrig.out")
		r.NoError(err)
		analyzer := NewElfBinaryAnalyzer()
		res, err := analyzer.Analyze(f)
		r.NoError(err)
		r.Equal(commonpb.Language_LANG_C, res.Lang)
		r.Len(res.Libraries, 1)
		r.Equal("xmrig", res.Libraries[0].Name)
	})

	t.Run("parse no results", func(t *testing.T) {
		r := require.New(t)
		f, err := os.Open("./testdata/c1/rootfs/unknown.out")
		r.NoError(err)
		analyzer := NewElfBinaryAnalyzer()
		_, err = analyzer.Analyze(f)
		r.ErrorIs(err, errAnalyzerNoResult)
	})

	t.Run("parse error", func(t *testing.T) {
		r := require.New(t)
		f, err := os.Open("./testdata/c1/rootfs/unknown.c")
		r.NoError(err)
		analyzer := NewElfBinaryAnalyzer()
		_, err = analyzer.Analyze(f)
		r.ErrorIs(err, errAnalyzerParse)
	})
}
