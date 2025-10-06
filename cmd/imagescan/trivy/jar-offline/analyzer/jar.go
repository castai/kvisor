package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// This is a fork of https://github.com/aquasecurity/trivy/blob/v0.61.1/pkg/fanal/analyzer/language/java/jar/jar.go#L46
// until upstream supports offline mode to parse JAR files without calling trivy java-db

const (
	TypeJarOffline analyzer.Type = "jar-offline"
)

func Register() {
	analyzer.RegisterPostAnalyzer(TypeJarOffline, newJavaLibraryAnalyzer)
}

const version = 1

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	parallel int
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		parallel: options.Parallel,
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(&javadb.DB{}, jar.WithSize(info.Size()), jar.WithFilePath(path), jar.WithOffline(input.Options.Offline))
		return language.ParsePackage(types.Jar, path, r, p, input.Options.FileChecksum)
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	}

	if err := parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult); err != nil {
		return nil, xerrors.Errorf("walk dir error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}
