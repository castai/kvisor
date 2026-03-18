package gpu

import (
	"context"
	"fmt"
	"net/http"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/logging"
	custommetrics "github.com/castai/metrics"
)

// Config holds all parameters needed to run the GPU metrics pipeline.
type Config struct {
	// ExportInterval controls how often metrics are collected and exported.
	ExportInterval time.Duration

	// DCGMExporterPort is the port DCGM exporter listens on (default 9400).
	DCGMExporterPort int

	// DCGMExporterPath is the HTTP path for metrics (default /metrics).
	DCGMExporterPath string

	// DCGMExporterHost, when set, bypasses pod discovery and scrapes a fixed host.
	// Set to "localhost" when running alongside DCGM as a sidecar.
	DCGMExporterHost string

	// Selector is the Kubernetes label selector used to find DCGM exporter pods.
	// Used only when DCGMExporterHost is empty.
	Selector string

	// NodeName is injected from the Kubernetes Downward API (spec.nodeName).
	// It is used to scope pod discovery to the local node, preventing double-counting.
	NodeName string

	// WorkloadLabelKeys are pod label keys checked first for a custom workload name override.
	WorkloadLabelKeys []string
}

// Pipeline scrapes DCGM exporter metrics on the local node and exports them
// via both the CAST AI REST API and the castai/metrics telemetry API.
type Pipeline struct {
	cfg          Config
	log          *logging.Logger
	scraper      Scraper
	mapper       MetricMapper
	castaiClient CastAIClient
	metricWriter custommetrics.Metric[GPUMetric]
	kubeClient   kubepb.KubeAPIClient
}

// NewPipeline creates a new GPU metrics pipeline. metricsClient and castaiClient
// may be nil if the respective export path is not configured.
func NewPipeline(
	cfg Config,
	kubeClient kubepb.KubeAPIClient,
	metricsClient custommetrics.MetricClient,
	castaiClient CastAIClient,
	log *logging.Logger,
) (*Pipeline, error) {
	logger := log.WithField("component", "gpu_pipeline")

	scraper := newScraper(&http.Client{}, logger)

	workloadLookup, err := newWorkloadLookup(kubeClient, cfg.WorkloadLabelKeys, 512)
	if err != nil {
		return nil, fmt.Errorf("creating workload lookup: %w", err)
	}
	mapper := newMapper(cfg.NodeName, workloadLookup, logger)

	var metricWriter custommetrics.Metric[GPUMetric]
	if metricsClient != nil {
		metricWriter, err = custommetrics.NewMetric[GPUMetric](
			metricsClient,
			custommetrics.WithCollectionName[GPUMetric]("gpu_metrics"),
			custommetrics.WithSkipTimestamp[GPUMetric](),
		)
		if err != nil {
			logger.WithField("error", err.Error()).Warn("failed to create gpu metric writer")
		}
	}

	return &Pipeline{
		cfg:          cfg,
		log:          logger,
		scraper:      scraper,
		mapper:       mapper,
		castaiClient: castaiClient,
		metricWriter: metricWriter,
		kubeClient:   kubeClient,
	}, nil
}

// Run starts the GPU metrics collection loop. It blocks until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context) error {
	p.log.Info("running gpu metrics pipeline")
	defer p.log.Info("gpu metrics pipeline done")

	ticker := time.NewTicker(p.cfg.ExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.export(ctx); err != nil {
				p.log.WithField("error", err.Error()).Error("error exporting gpu metrics")
			}
		}
	}
}

func (p *Pipeline) export(ctx context.Context) error {
	urls, err := p.getDCGMURLs(ctx)
	if err != nil {
		return fmt.Errorf("getting dcgm urls: %w", err)
	}

	if len(urls) == 0 {
		p.log.Info("no dcgm-exporter instances to scrape")
		return nil
	}

	metricFamilies, err := p.scraper.Scrape(ctx, urls)
	if err != nil {
		return fmt.Errorf("scraping dcgm exporters: %w", err)
	}
	if len(metricFamilies) == 0 {
		p.log.Warnf("no metrics collected from %d dcgm-exporters", len(urls))
		return nil
	}

	now := time.Now()

	// Export path A: protobuf batch to CAST AI REST API.
	if p.castaiClient != nil {
		batch := p.mapper.Map(metricFamilies)
		if len(batch.Metrics) == 0 {
			p.log.Warn("no enabled metrics found in scraped data")
		} else {
			if err := p.castaiClient.UploadBatch(ctx, batch); err != nil {
				p.log.WithField("error", err.Error()).Error("error uploading gpu metrics batch to cast ai")
			} else {
				p.log.Infof("successfully exported %d gpu metric families to cast ai", len(batch.Metrics))
			}
		}
	}

	// Export path B: Avro/custom metrics API.
	if p.metricWriter != nil {
		gpuMetrics := p.mapper.MapToAvro(ctx, metricFamilies)
		for _, m := range gpuMetrics {
			m.Timestamp = now
			if err := p.metricWriter.Write(m); err != nil {
				p.log.WithField("error", err.Error()).Warn("error writing gpu metric to telemetry api")
				break
			}
		}
	}

	return nil
}

// getDCGMURLs returns the list of DCGM exporter scrape endpoints for this node.
// When DCGMExporterHost is set, a single fixed URL is returned.
// Otherwise, running DCGM pods on the local node are discovered via the controller gRPC API.
func (p *Pipeline) getDCGMURLs(ctx context.Context) ([]string, error) {
	if p.cfg.DCGMExporterHost != "" {
		return []string{
			fmt.Sprintf("http://%s:%d%s", p.cfg.DCGMExporterHost, p.cfg.DCGMExporterPort, p.cfg.DCGMExporterPath),
		}, nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := p.kubeClient.GetPodsOnNode(reqCtx, &kubepb.GetPodsOnNodeRequest{
		NodeName:      p.cfg.NodeName,
		LabelSelector: p.cfg.Selector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing dcgm exporter pods via controller: %w", err)
	}

	urls := make([]string, 0, len(resp.Pods))
	for _, pod := range resp.Pods {
		if pod.PodIp == "" {
			continue
		}
		urls = append(urls, fmt.Sprintf("http://%s:%d%s", pod.PodIp, p.cfg.DCGMExporterPort, p.cfg.DCGMExporterPath))
	}

	return urls, nil
}
