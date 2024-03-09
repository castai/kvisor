package analyzers

import (
	"os"
	"testing"

	commonpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
)

func TestGobinaryAnalyzer(t *testing.T) {
	t.Run("parse binary", func(t *testing.T) {
		r := require.New(t)
		f, err := os.Open("./testdata/c2/rootfs/server")
		r.NoError(err)
		analyzer := NewGoBinaryAnalyzer()
		res, err := analyzer.Analyze(f)
		r.NoError(err)
		r.Equal(commonpb.Language_LANG_GOLANG, res.Lang)
		r.Len(res.Libraries, 2)
		r.Equal("github.com/sirupsen/logrus", res.Libraries[0].Name)
		r.Equal("golang.org/x/sys", res.Libraries[1].Name)
	})

	t.Run("parse error", func(t *testing.T) {
		r := require.New(t)
		f, err := os.Open("./testdata/c2/rootfs/server.go")
		r.NoError(err)
		analyzer := NewElfBinaryAnalyzer()
		_, err = analyzer.Analyze(f)
		r.ErrorIs(err, errAnalyzerParse)
	})
}
