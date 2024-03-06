package analyzers

import (
	"errors"
	"io"

	castpb "github.com/castai/kvisor/api/v1/runtime"
)

var (
	errAnalyzerNoResult = errors.New("no results")
	errAnalyzerParse    = errors.New("parse failed")
)

type AnalyzerResult struct {
	Lang      castpb.Language
	Libraries []*castpb.Library
}

type Analyzer interface {
	Analyze(r io.ReaderAt) (*AnalyzerResult, error)
}

type Result struct {
	AnalyzerResult *AnalyzerResult
	Event          *castpb.Event
}
