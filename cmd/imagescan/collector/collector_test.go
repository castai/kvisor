package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/castai/image-analyzer/image"
	"github.com/castai/image-analyzer/image/hostfs"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/imagescan/config"
	mockblobcache "github.com/castai/kvisor/pkg/blobscache/mock"
)

func TestCollector(t *testing.T) {
	t.Run("collect and sends metadata", func(t *testing.T) {
		imgName := "notused"
		imgID := "gke.gcr.io/phpmyadmin@sha256:b0d9c54760b35edd1854e5710c1a62a28ad2d2b070c801da3e30a3e59c19e7e3" //nolint:gosec

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		mockCache := mockblobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "testdata/amd64-linux/io.containerd.content.v1.content")

		ingestClient := &mockIngestClient{}

		c := New(
			log,
			config.Config{
				ImageID:           imgID,
				ImageName:         imgName,
				Timeout:           5 * time.Minute,
				Mode:              config.ModeHostFS,
				Runtime:           config.RuntimeContainerd,
				ImageArchitecture: "amd64",
				ImageOS:           "linux",
				Parallel:          1,
				DisabledAnalyzers: []string{"secret"},
			},
			ingestClient,
			mockCache,
			&hostfs.ContainerdHostFSConfig{
				Platform: v1.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
				ContentDir: p,
			},
		)

		r.NoError(c.Collect(ctx))

		// Read expect metadata.
		var expected castaipb.ImageMetadata
		b, err := os.ReadFile("./testdata/expected_image_scan_meta1.json")
		r.NoError(err)
		r.NoError(protojson.Unmarshal(b, &expected))

		receivedMetadataJson, err := protojson.Marshal(ingestClient.receivedMeta)
		r.NoError(err)
		var actual castaipb.ImageMetadata
		r.NoError(protojson.Unmarshal(receivedMetadataJson, &actual))

		var expectedPackages []types.BlobInfo
		var actualPackages []types.BlobInfo
		r.NoError(json.Unmarshal(expected.Packages, &expectedPackages))
		r.NoError(json.Unmarshal(actual.Packages, &actualPackages))
		expected.Packages = nil
		actual.Packages = nil

		r.Equal(&expected, &actual)
		r.ElementsMatch(expectedPackages, actualPackages)
	})
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
		CastaiAPIGrpcAddr: srv.URL,
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
	registryAuth := image.RegistryAuth{Username: "u", Password: "p", Token: "t"}

	tests := []struct {
		name     string
		cfg      image.DockerConfig
		imageRef name.Reference

		expectedFound bool
		expectedKey   string
		expectedAuth  image.RegistryAuth
	}{
		{
			name: "find auth for image",
			cfg: image.DockerConfig{
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
					"a": registryAuth,
					"https://us-east4-docker.pkg.dev/project/repo": registryAuth,
					"x": {},
				},
			},
			imageRef:      name.MustParseReference("nginx:latest"),
			expectedFound: false,
			expectedKey:   "",
			expectedAuth:  image.RegistryAuth{},
		},
		{
			name: "default docker registry",
			cfg: image.DockerConfig{
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
				Auths: map[string]image.RegistryAuth{
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
