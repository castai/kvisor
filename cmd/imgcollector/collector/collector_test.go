package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	mock_blobcache "github.com/castai/kvisor/blobscache/mock"
	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/cmd/imgcollector/image/hostfs"
)

func TestCollector(t *testing.T) {
	t.Run("collect and sends metadata", func(t *testing.T) {
		imgName := "notused"
		imgID := "gke.gcr.io/phpmyadmin@sha256:b0d9c54760b35edd1854e5710c1a62a28ad2d2b070c801da3e30a3e59c19e7e3"

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		client := &mockClient{}
		mockCache := mock_blobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

		c := New(log, config.Config{
			ImageID:   imgID,
			ImageName: imgName,
			Timeout:   5 * time.Minute,
			Mode:      config.ModeHostFS,
			Runtime:   config.RuntimeContainerd,
		}, client, mockCache, &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: p,
		})

		r.NoError(c.Collect(ctx))

		// Read expect metadata.
		var expected castai.ImageMetadata
		b, err := os.ReadFile("./testdata/expected_image_scan_meta1.json")
		r.NoError(err)
		r.NoError(json.Unmarshal(b, &expected))

		// Convert actual metadata to json and back to have identical types.
		// Some fields are dynamic of type interface{}
		actualB, err := json.Marshal(client.meta)
		r.NoError(err)
		var actual castai.ImageMetadata
		r.NoError(json.Unmarshal(actualB, &actual))

		r.Equal(expected, actual)
	})
}

func TestCollectorLargeImageDocker(t *testing.T) {
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
	client := &mockClient{}
	mockCache := mock_blobcache.MockClient{}

	c := New(log, config.Config{
		ImageID:           imgID,
		ImageName:         imgName,
		Timeout:           5 * time.Minute,
		Mode:              config.ModeTarArchive,
		Runtime:           config.RuntimeDocker,
		SlowMode:          true,
		ImageLocalTarPath: "egressd.tar",
	}, client, mockCache, nil)

	go func() {
		for {
			printMemStats()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	r.NoError(c.Collect(ctx))
	writeMemProfile("heap.prof")
	md, err := json.Marshal(client.meta)
	r.NoError(err)
	r.NoError(os.WriteFile("metadata.json", md, 0600))
}

type mockClient struct {
	meta *castai.ImageMetadata
}

func (m *mockClient) SendLogs(ctx context.Context, req *castai.LogEvent) error {
	return nil
}

func (m *mockClient) SendCISReport(ctx context.Context, report *castai.KubeBenchReport) error {
	return nil
}

func (m *mockClient) SendDeltaReport(ctx context.Context, report *castai.Delta) error {
	return nil
}

func (m *mockClient) SendLinterChecks(ctx context.Context, checks []castai.LinterCheck) error {
	return nil
}

func (m *mockClient) SendImageMetadata(ctx context.Context, meta *castai.ImageMetadata) error {
	m.meta = meta
	return nil
}

func (m *mockClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error {
	return nil
}

func (m *mockClient) PostTelemetry(ctx context.Context, initial bool) (*castai.TelemetryResponse, error) {
	return nil, nil
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
