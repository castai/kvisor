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
	"path"
	"runtime"
	"runtime/pprof"
	"slices"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
		// This test was matching the concrete packages before, but this was incredibly brittle and breaking with
		// every upgrade of trivy. Hence we now only test if the len of the packages match.
		r.Len(actualPackages, len(expectedPackages))
	})
}

func TestCollectorImageManifestIngestEndpoint(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name  string
		image string

		expectedManifest string
	}{
		{
			name:             "scan by tag",
			image:            "alpine:3.21.3",
			expectedManifest: "testdata/manifests/alpine-3-21-3-index.json",
		},
		{
			name:             "scan by index digest",
			image:            "alpine@sha256:2c62ccfd5af3cacd327127a22a2f80277c5f6acbec9e5b1cbc18a1b435336b40",
			expectedManifest: "testdata/manifests/alpine-3-21-3-index.json",
		},
		{
			name:             "scan by manifest digest",
			image:            "alpine@sha256:1c4eef651f65e2f7daee7ee785882ac164b02b78fb74503052a26dc061c90474", // linux/amd64
			expectedManifest: "testdata/manifests/alpine-3-21-3-manifest.json",
		},
	}

	mockCache := mockblobcache.MockClient{}

	ingestClient := &mockIngestClient{}

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

			req, err := protojson.Marshal(ingestClient.receivedManifestRequest)
			r.NoError(err)
			var actual castaipb.ImageManifestIngestRequest
			r.NoError(protojson.Unmarshal(req, &actual))

			var expected castaipb.ImageManifestIngestRequest
			b, err := os.ReadFile(tt.expectedManifest)
			r.NoError(err)
			r.NoError(protojson.Unmarshal(b, &expected))

			// ignore image name as the registry port is dynamic per test run
			r.Contains(actual.ImageName, tt.image)
			actual.ImageName = expected.ImageName

			r.Equal(&expected, &actual)
		})
	}
}

func TestCollectorPackageAnalyzers(t *testing.T) {

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

	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	mockCache := mockblobcache.MockClient{}

	ingestClient := &mockIngestClient{}

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

func hasPackageWithInstalledFiles(packages []types.Package) bool {
	for _, pkg := range packages {
		if len(pkg.InstalledFiles) > 0 {
			return true
		}
	}
	return false
}

func TestCollectorWithIngressNginx(t *testing.T) {
	t.Run("collects right ingress nginx version", func(t *testing.T) {
		// This is for local testing only. The whole underlying logic is a huge hack.
		t.Skip()

		imgID := "registry.k8s.io/ingress-nginx/controller:v1.11.0@sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39" //nolint:gosec
		imgName := imgID

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		mockCache := mockblobcache.MockClient{}

		ingestClient := &mockIngestClient{}

		c := New(
			log,
			config.Config{
				ImageID:           imgID,
				ImageName:         imgName,
				Timeout:           5 * time.Minute,
				Mode:              config.ModeRemote,
				Runtime:           config.RuntimeContainerd,
				Parallel:          1,
				ImageLocalTarPath: "ingress-controller.tar",
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

		var ingressVersion string

		for _, bi := range slices.Backward(actualPackages) {
			for _, a := range bi.Applications {
				for _, p := range a.Packages {
					if p.Name == "k8s.io/ingress-nginx" {
						ingressVersion = p.Version
						goto out
					}
				}
			}
		}

	out:
		r.Equal("v1.11.0", ingressVersion)
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
	receivedMeta            *castaipb.ImageMetadata
	receivedManifestRequest *castaipb.ImageManifestIngestRequest
}

func (m *mockIngestClient) ImageMetadataIngest(ctx context.Context, in *castaipb.ImageMetadata, opts ...grpc.CallOption) (*castaipb.ImageMetadataIngestResponse, error) {
	m.receivedMeta = in
	return &castaipb.ImageMetadataIngestResponse{}, nil
}

func (m *mockIngestClient) ImageManifestIngest(ctx context.Context, in *castaipb.ImageManifestIngestRequest, opts ...grpc.CallOption) (*castaipb.ImageManifestIngestResponse, error) {
	m.receivedManifestRequest = in
	return &castaipb.ImageManifestIngestResponse{}, nil
}

func setupTestRegistry(t *testing.T) *httptest.Server {
	t.Helper()

	tr := httptest.NewServer(registry.New())
	u, err := url.Parse(tr.URL)
	require.NoError(t, err)

	// crane pull ${image} --format oci ${path}/${image}
	// in order to reduce the size of the test data the images have been trimmed
	// to only contain the linux/amd64 architecture but keeping the index manifest
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
