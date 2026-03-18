package gpu

import (
	"context"
	"testing"

	"github.com/castai/kvisor/cmd/agent/daemon/pipeline/gpu/pb"
	"github.com/castai/logging"
	"github.com/stretchr/testify/require"
)

type mockScraper struct {
	scrapeFunc func(ctx context.Context, urls []string) ([]MetricFamilyMap, error)
}

func (m *mockScraper) Scrape(ctx context.Context, urls []string) ([]MetricFamilyMap, error) {
	return m.scrapeFunc(ctx, urls)
}

type mockMapper struct {
	mapFunc       func([]MetricFamilyMap) *pb.MetricsBatch
	mapToAvroFunc func(context.Context, []MetricFamilyMap) []GPUMetric
}

func (m *mockMapper) Map(metrics []MetricFamilyMap) *pb.MetricsBatch {
	if m.mapFunc != nil {
		return m.mapFunc(metrics)
	}
	return &pb.MetricsBatch{}
}

func (m *mockMapper) MapToAvro(ctx context.Context, metrics []MetricFamilyMap) []GPUMetric {
	if m.mapToAvroFunc != nil {
		return m.mapToAvroFunc(ctx, metrics)
	}
	return nil
}

type mockCastAIClient struct {
	uploaded bool
}

func (m *mockCastAIClient) UploadBatch(_ context.Context, _ *pb.MetricsBatch) error {
	m.uploaded = true
	return nil
}

func TestPipeline_export(t *testing.T) {
	log := logging.New()

	t.Run("exports with fixed host", func(t *testing.T) {
		var scrapedURLs []string
		scraper := &mockScraper{
			scrapeFunc: func(_ context.Context, urls []string) ([]MetricFamilyMap, error) {
				scrapedURLs = urls
				return []MetricFamilyMap{{"m": nil}}, nil
			},
		}
		client := &mockCastAIClient{}

		p := &Pipeline{
			cfg: Config{
				DCGMExporterHost: "localhost",
				DCGMExporterPort: 9400,
				DCGMExporterPath: "/metrics",
			},
			log:          log,
			scraper:      scraper,
			mapper:       &mockMapper{mapFunc: func(_ []MetricFamilyMap) *pb.MetricsBatch { return &pb.MetricsBatch{} }},
			castaiClient: client,
		}

		err := p.export(context.Background())

		r := require.New(t)
		r.NoError(err)
		r.Equal([]string{"http://localhost:9400/metrics"}, scrapedURLs)
	})

	t.Run("skips upload when scraper returns empty", func(t *testing.T) {
		scraper := &mockScraper{
			scrapeFunc: func(_ context.Context, _ []string) ([]MetricFamilyMap, error) {
				return nil, nil
			},
		}
		client := &mockCastAIClient{}

		p := &Pipeline{
			cfg: Config{
				DCGMExporterHost: "localhost",
				DCGMExporterPort: 9400,
				DCGMExporterPath: "/metrics",
			},
			log:          log,
			scraper:      scraper,
			mapper:       &mockMapper{},
			castaiClient: client,
		}

		err := p.export(context.Background())

		r := require.New(t)
		r.NoError(err)
		r.False(client.uploaded)
	})
}
