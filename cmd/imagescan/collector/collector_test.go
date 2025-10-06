package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/castai/image-analyzer/image"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/imagescan/config"
	mockblobcache "github.com/castai/kvisor/pkg/blobscache/mock"
)

func TestCollector(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name  string
		image string

		expectedMetadata string
	}{
		{
			name:             "scan by tag",
			image:            "alpine:3.21.3",
			expectedMetadata: "testdata/metadata/alpine-3-21-3-index.json",
		},
		{
			name:             "scan by index digest",
			image:            "alpine@sha256:2c62ccfd5af3cacd327127a22a2f80277c5f6acbec9e5b1cbc18a1b435336b40",
			expectedMetadata: "testdata/metadata/alpine-3-21-3-index.json",
		},
		{
			name:             "scan by manifest digest",
			image:            "alpine@sha256:1c4eef651f65e2f7daee7ee785882ac164b02b78fb74503052a26dc061c90474", // linux/amd64
			expectedMetadata: "testdata/metadata/alpine-3-21-3-manifest.json",
		},
	}

	var (
		mockCache    = mockblobcache.MockClient{}
		ingestClient = &mockIngestClient{}
	)

	tr := setupTestRegistry(t)
	defer tr.Close()
	registryAddr := tr.Listener.Addr().String()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			c := New(
				log,
				config.Config{
					ImageID:           tt.image,
					ImageName:         fmt.Sprintf("%s/%s", registryAddr, tt.image),
					Timeout:           1 * time.Minute,
					Mode:              config.ModeRemote,
					Runtime:           config.RuntimeDocker,
					Parallel:          1,
					DisabledAnalyzers: []string{"secret"},
				},
				ingestClient,
				mockCache,
				nil,
			)

			r.NoError(c.Collect(ctx))

			receivedMetadataJson, err := protojson.Marshal(ingestClient.receivedMeta)
			r.NoError(err)
			var receivedMetadata castaipb.ImageMetadata
			r.NoError(protojson.Unmarshal(receivedMetadataJson, &receivedMetadata))

			var expectedMetadata castaipb.ImageMetadata
			b, err := os.ReadFile(tt.expectedMetadata)
			r.NoError(err)
			r.NoError(protojson.Unmarshal(b, &expectedMetadata))

			// ignore image name and id as the registry port is dynamic per test run
			r.Equal(tt.image, receivedMetadata.ImageId)
			expectedMetadata.ImageId = receivedMetadata.ImageId
			r.Contains(receivedMetadata.ImageName, tt.image)
			expectedMetadata.ImageName = receivedMetadata.ImageName
			r.Equal(&expectedMetadata, &receivedMetadata)
		})
	}
}

func TestCollectorPackageAnalyzers(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name  string
		image string
	}{
		{
			name:  "analyze apk packages",
			image: "alpine:3.21.3",
		},
		{
			name:  "analyze deb packages",
			image: "debian:trixie-slim",
		},
		{
			name:  "analyze rpm packages",
			image: "ubi-micro:8.10",
		},
	}

	var (
		mockCache    = mockblobcache.MockClient{}
		ingestClient = &mockIngestClient{}
	)

	tr := setupTestRegistry(t)
	defer tr.Close()
	registryAddr := tr.Listener.Addr().String()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			c := New(
				log,
				config.Config{
					ImageID:           test.image,
					ImageName:         fmt.Sprintf("%s/%s", registryAddr, test.image),
					Timeout:           5 * time.Minute,
					Mode:              config.ModeRemote,
					Runtime:           config.RuntimeDocker,
					Parallel:          1,
					DisabledAnalyzers: []string{"secret"},
				},
				ingestClient,
				mockCache,
				nil,
			)

			r.NoError(c.Collect(ctx))

			receivedMetadataJson, err := protojson.Marshal(ingestClient.receivedMeta)
			r.NoError(err)
			var actual castaipb.ImageMetadata
			r.NoError(protojson.Unmarshal(receivedMetadataJson, &actual))

			var actualPackages []types.BlobInfo
			r.NoError(json.Unmarshal(actual.Packages, &actualPackages))

			// verify that files installed per package are included in the scan result
			r.Len(actualPackages, 1)
			r.Len(actualPackages[0].PackageInfos, 1)
			r.True(hasPackageWithInstalledFiles(actualPackages[0].PackageInfos[0].Packages))
		})
	}
}

func TestCollectorRuntimeAnalyzers(t *testing.T) {
	if testing.Short() {
		t.Skip("slow test, skipping in short mode")
	}

	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	tests := []struct {
		runtime  string
		image    string
		filePath string
	}{
		{
			runtime:  "jar",
			image:    "ghcr.io/open-telemetry/demo:1.8.0-adservice", // 359MB
			filePath: "usr/src/app/opentelemetry-javaagent.jar",
		},
	}

	var (
		mockCache    = mockblobcache.MockClient{}
		ingestClient = &mockIngestClient{}
	)

	for _, test := range tests {
		t.Run(fmt.Sprintf("analyze %s runtime", test.runtime), func(t *testing.T) {
			r := require.New(t)
			c := New(
				log,
				config.Config{
					ImageID:           test.image,
					ImageName:         test.image,
					Timeout:           5 * time.Minute,
					Mode:              config.ModeRemote,
					Runtime:           config.RuntimeDocker,
					Parallel:          1,
					DisabledAnalyzers: []string{"secret"},
				},
				ingestClient,
				mockCache,
				nil,
			)

			err := c.Collect(ctx)
			r.NoError(err)

			receivedMetadataJson, err := protojson.Marshal(ingestClient.receivedMeta)
			r.NoError(err)
			var actual castaipb.ImageMetadata
			r.NoError(protojson.Unmarshal(receivedMetadataJson, &actual))

			var blobsInfo []types.BlobInfo
			err = json.Unmarshal(actual.Packages, &blobsInfo)
			r.NoError(err)

			found := hasDependenciesByTypeAndPath(blobsInfo, types.LangType(test.runtime), test.filePath)
			r.True(found, "no dependencies found for %s in %s", test.runtime, test.filePath)
		})
	}
}

func hasPackageWithInstalledFiles(packages []types.Package) bool {
	for _, pkg := range packages {
		if len(pkg.InstalledFiles) > 0 {
			return true
		}
	}
	return false
}

func hasDependenciesByTypeAndPath(blobsInfo []types.BlobInfo, appType types.LangType, filePath string) bool {
	for _, blob := range blobsInfo {
		for _, app := range blob.Applications {
			if app.Type == appType && app.FilePath == filePath {
				return len(app.Packages) > 0
			}
		}
	}
	return false
}

func TestCollectorLargeImageDockerTar(t *testing.T) {
	// Skip this test by default. Uncomment to run locally.
	if os.Getenv("LOCAL_IMAGE") == "" {
		t.Skip()
	}

	// You will spend a lot of time on macOS to fetch image into temp file from daemon.
	// Instead, export image once to local tar file.
	// docker save ghcr.io/castai/egressd:am1 -o egressd.tar
	imgName := "kvisor:local"
	imgID := imgName

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	//debug.SetGCPercent(-1)
	mockCache := mockblobcache.MockClient{}

	var receivedMetaBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data, err := io.ReadAll(req.Body)
		r.NoError(err)
		receivedMetaBytes = data
	}))
	defer srv.Close()

	ingestClient := &mockIngestClient{}

	c := New(log, config.Config{
		ImageID:           imgID,
		ImageName:         imgName,
		Timeout:           5 * time.Minute,
		Mode:              config.ModeTarArchive,
		Runtime:           config.RuntimeDocker,
		Parallel:          1,
		ImageLocalTarPath: "egressd.tar",
	}, ingestClient, mockCache, nil)

	go func() {
		for {
			printMemStats()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	r.NoError(c.Collect(ctx))
	writeMemProfile("heap.pprof")
	r.NoError(os.WriteFile("metadata.json", receivedMetaBytes, 0600))
}

func TestCollectorLargeImageDockerRemote(t *testing.T) {
	// Skip this test by default. Set LOCAL_IMAGE to run locally.
	imgName := os.Getenv("LOCAL_IMAGE")
	if imgName == "" {
		t.Skip()
	}
	imgID := imgName

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	//debug.SetGCPercent(-1)
	mockCache := mockblobcache.MockClient{}

	ingestClient := &mockIngestClient{}

	c := New(log, config.Config{
		ImageID:           imgID,
		ImageName:         imgName,
		Timeout:           5 * time.Minute,
		Mode:              config.ModeRemote,
		Runtime:           config.RuntimeDocker,
		Parallel:          5,
		DisabledAnalyzers: []string{"secret"},
	}, ingestClient, mockCache, nil)

	startCPUProfile("cpu.pprof")
	r.NoError(c.Collect(ctx))
	pprof.StopCPUProfile()
	writeMemProfile("heap.pprof")
}

func printMemStats() {
	runtime.GC() // Get up-to-date statistics.
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("allocs=%d MB, total_allocs=%d MB, sys=%d MB\n", stats.Alloc/1024/1024, stats.TotalAlloc/1024/1024, stats.Sys/1024/1024)
}

func writeMemProfile(name string) {
	f, err := os.Create(name)
	if err != nil {
		logrus.Fatalf("could not create memory profile: %v", err)
	}
	defer f.Close() // error handling omitted for example
	if err := pprof.WriteHeapProfile(f); err != nil {
		logrus.Fatalf("could not write memory profile: %v", err)
	}
}

func startCPUProfile(name string) {
	f, err := os.Create(name)
	if err != nil {
		logrus.Fatalf("could not create CPU profile: %v", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		logrus.Fatalf("could not start CPU profile: %v", err)
	}
}

func TestFindRegistryAuth(t *testing.T) {
	registryAuth := authn.AuthConfig{
		Username:      "u",
		Password:      "p",
		RegistryToken: "t",
	}

	tests := []struct {
		name          string
		cfg           image.DockerConfig
		imageRef      name.Reference
		expectedFound bool
		expectedKey   string
		expectedAuth  authn.AuthConfig
	}{
		{
			name: "find auth for image",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a":                       registryAuth,
					"gitlab.com":              registryAuth,
					"us-east4-docker.pkg.dev": registryAuth,
					"x":                       {},
				},
			},
			imageRef:      name.MustParseReference("us-east4-docker.pkg.dev/project/repo/name:tag"),
			expectedFound: true,
			expectedKey:   "us-east4-docker.pkg.dev",
			expectedAuth:  registryAuth,
		},
		{
			name: "find auth for image with trailing slash",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a":                        registryAuth,
					"gitlab.com":               registryAuth,
					"us-east4-docker.pkg.dev/": registryAuth,
					"x":                        {},
				},
			},
			imageRef:      name.MustParseReference("us-east4-docker.pkg.dev/project/repo/name:tag"),
			expectedFound: true,
			expectedKey:   "us-east4-docker.pkg.dev/",
			expectedAuth:  registryAuth,
		},
		{
			name: "find auth scoped by repository",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a":                                    registryAuth,
					"us-east4-docker.pkg.dev":              registryAuth,
					"us-east4-docker.pkg.dev/project/repo": registryAuth,
					"x":                                    {},
				},
			},
			imageRef:      name.MustParseReference("us-east4-docker.pkg.dev/project/repo/name:tag"),
			expectedFound: true,
			expectedKey:   "us-east4-docker.pkg.dev/project/repo",
			expectedAuth:  registryAuth,
		},
		{
			name: "find auth scoped by repository with trailing slash",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a":                                     registryAuth,
					"us-east4-docker.pkg.dev/":              registryAuth,
					"us-east4-docker.pkg.dev/project/repo/": registryAuth,
					"x":                                     {},
				},
			},
			imageRef:      name.MustParseReference("us-east4-docker.pkg.dev/project/repo/name:tag"),
			expectedFound: true,
			expectedKey:   "us-east4-docker.pkg.dev/project/repo/",
			expectedAuth:  registryAuth,
		},
		{
			name: "find auth for http or https prefixed auths",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a": registryAuth,
					"https://us-east4-docker.pkg.dev/project/repo": registryAuth,
					"x": {},
				},
			},
			imageRef:      name.MustParseReference("us-east4-docker.pkg.dev/project/repo/name:tag"),
			expectedFound: true,
			expectedKey:   "https://us-east4-docker.pkg.dev/project/repo",
			expectedAuth:  registryAuth,
		},
		{
			name: "no auth for unmatched auths",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"a": registryAuth,
					"https://us-east4-docker.pkg.dev/project/repo": registryAuth,
					"x": {},
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: false,
			expectedKey:   "",
			expectedAuth:  authn.AuthConfig{},
		},
		{
			name: "default docker registry",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"docker.io": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "docker.io",
			expectedAuth:  registryAuth,
		},
		{
			name: "default docker registry with version",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"docker.io/v2": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "docker.io/v2",
			expectedAuth:  registryAuth,
		},
		{
			name: "default docker registry with index",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"index.docker.io": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "index.docker.io",
			expectedAuth:  registryAuth,
		},
		{
			name: "default docker registry with index and version v1",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"index.docker.io/v1": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "index.docker.io/v1",
			expectedAuth:  registryAuth,
		},
		{
			name: "default docker registry with index and version",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"index.docker.io/v2": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "index.docker.io/v2",
			expectedAuth:  registryAuth,
		},
		{
			name: "default docker registry with protocol, index and version",
			cfg: image.DockerConfig{
				Auths: map[string]authn.AuthConfig{
					"https://index.docker.io/v2/": registryAuth,
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: true,
			expectedKey:   "https://index.docker.io/v2/",
			expectedAuth:  registryAuth,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			actualKey, actualAuth, found := findRegistryAuth(test.cfg, test.imageRef, logrus.New())
			r.Equal(test.expectedFound, found)
			r.Equal(test.expectedKey, actualKey)
			r.Equal(test.expectedAuth, actualAuth)
		})
	}
}

type mockIngestClient struct {
	receivedMeta *castaipb.ImageMetadata
}

func (m *mockIngestClient) ImageMetadataIngest(ctx context.Context, in *castaipb.ImageMetadata, opts ...grpc.CallOption) (*castaipb.ImageMetadataIngestResponse, error) {
	m.receivedMeta = in
	return &castaipb.ImageMetadataIngestResponse{}, nil
}

func setupTestRegistry(t *testing.T) *httptest.Server {
	t.Helper()

	tr := httptest.NewServer(registry.New())
	u, err := url.Parse(tr.URL)
	require.NoError(t, err)

	// crane pull ${image} --format oci ${path}/${image}
	//
	// To reduce the size of the test data the images have been trimmed
	// to include only the linux/amd64 architecture while keeping the index manifest
	imageIndexes := map[string]v1.ImageIndex{
		"alpine:3.21.3":      mustImageIndexFromPath(t, "testdata/images/alpine-3-21-3"),
		"debian:trixie-slim": mustImageIndexFromPath(t, "testdata/images/debian-13-trixie"),
		"ubi-micro:8.10":     mustImageIndexFromPath(t, "testdata/images/ubi-micro-8-10"),
	}

	for tag, index := range imageIndexes {
		mustWriteImageIndex(t, u.Host, tag, index)
	}

	return tr
}

func mustImageIndexFromPath(t *testing.T, path string) v1.ImageIndex {
	t.Helper()

	layout, err := layout.ImageIndexFromPath(path)
	require.NoError(t, err)

	layoutIndex, err := layout.IndexManifest()
	require.NoError(t, err)

	index, err := layout.ImageIndex(layoutIndex.Manifests[0].Digest)
	require.NoError(t, err)

	return index
}

func mustWriteImageIndex(t *testing.T, host string, tag string, index v1.ImageIndex) {
	t.Helper()

	repoTag := fmt.Sprintf("%s/%s", host, tag)
	ref, err := name.ParseReference(repoTag)
	require.NoError(t, err)

	err = remote.WriteIndex(ref, index)
	require.NoError(t, err)
}
