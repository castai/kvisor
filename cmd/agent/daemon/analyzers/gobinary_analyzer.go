package analyzers

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"

	commonpb "github.com/castai/kvisor/api/v1/runtime"
)

func NewGoBinaryAnalyzer() *GoBinaryAnalyzer {
	return &GoBinaryAnalyzer{}
}

type GoBinaryAnalyzer struct {
}

func (a *GoBinaryAnalyzer) Analyze(r io.ReaderAt) (res *AnalyzerResult, rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			rerr = errors.Join(rerr, fmt.Errorf("%v", perr))
		}
	}()

	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, errAnalyzerParse
	}
	var libs []*commonpb.Library
	for _, dep := range info.Deps {
		if dep.Path == "" {
			continue
		}
		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}
		libs = append(libs, &commonpb.Library{
			Name:    mod.Path,
			Version: mod.Version,
		})
	}
	return &AnalyzerResult{
		Lang:      commonpb.Language_LANG_GOLANG,
		Libraries: libs,
	}, nil
}
