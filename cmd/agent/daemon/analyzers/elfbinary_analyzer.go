package analyzers

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"

	commonpb "github.com/castai/kvisor/api/v1/runtime"
)

func NewElfBinaryAnalyzer() *ElfBinaryAnalyzer {
	return &ElfBinaryAnalyzer{
		cryptoBinaryChecks: [][]byte{
			[]byte("XMRIG_VERSION"),
		},
		// maxChunksCount sets max number of 1k chunks to read. XMRIG is usually detect in the first 10 chunks.
		// Should be adjusted based on new detection rules.
		maxChunksCount: 100,
	}
}

type ElfBinaryAnalyzer struct {
	cryptoBinaryChecks [][]byte
	maxChunksCount     int
}

func (a *ElfBinaryAnalyzer) Analyze(r io.ReaderAt) (res *AnalyzerResult, rerr error) {
	defer func() {
		if perr := recover(); perr != nil {
			rerr = errors.Join(rerr, fmt.Errorf("%v", perr))
		}
	}()

	f, err := elf.NewFile(r)
	if err != nil {
		return nil, errAnalyzerParse
	}
	defer f.Close()

	for _, s := range f.Sections {
		if s.Name != ".rodata" {
			continue
		}
		reader := s.Open()
		buf := make([]byte, 1024)
		var chunks int
		for {
			n, err := reader.Read(buf)
			if n == 0 {
				return nil, errAnalyzerNoResult
			}
			chunks++
			for _, check := range a.cryptoBinaryChecks {
				if bytes.Contains(buf, check) {
					return &AnalyzerResult{
						Lang: commonpb.Language_LANG_C,
						Libraries: []*commonpb.Library{
							{Name: "xmrig"},
						},
					}, nil
				}
			}
			if chunks > a.maxChunksCount {
				return nil, errAnalyzerNoResult
			}
			if err != nil {
				return nil, errAnalyzerNoResult
			}
		}
	}
	return nil, errAnalyzerNoResult
}
