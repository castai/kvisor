package gpu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"golang.org/x/sync/errgroup"

	"github.com/castai/logging"
)

const maxConcurrentScrapes = 15

// Scraper fetches Prometheus metrics from one or more DCGM exporter endpoints.
type Scraper interface {
	Scrape(ctx context.Context, urls []string) ([]MetricFamilyMap, error)
}

// HTTPClient is satisfied by *http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type scrapeResult struct {
	metricFamilyMap MetricFamilyMap
	err             error
}

type scraper struct {
	httpClient HTTPClient
	log        *logging.Logger
}

func newScraper(httpClient HTTPClient, log *logging.Logger) Scraper {
	return &scraper{
		httpClient: httpClient,
		log:        log,
	}
}

func (s *scraper) Scrape(ctx context.Context, urls []string) ([]MetricFamilyMap, error) {
	var g errgroup.Group
	g.SetLimit(maxConcurrentScrapes)

	resultsChan := make(chan scrapeResult, maxConcurrentScrapes)

	for i := range urls {
		url := urls[i]
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				families, err := s.scrapeURL(ctx, url)
				if err != nil {
					err = fmt.Errorf("error while fetching metrics from '%s': %w", url, err)
				}
				resultsChan <- scrapeResult{metricFamilyMap: families, err: err}
			}
			return nil
		})
	}

	go func() {
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Errorf("error while scraping metrics: %v", err)
		}
		close(resultsChan)
	}()

	metrics := make([]MetricFamilyMap, 0, len(urls))
	for result := range resultsChan {
		if result.err != nil {
			s.log.WithField("error", result.err.Error()).Error("failed to scrape metrics")
			continue
		}
		metrics = append(metrics, result.metricFamilyMap)
	}

	return metrics, nil
}

func (s *scraper) scrapeURL(ctx context.Context, url string) (map[string]*dto.MetricFamily, error) {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxWithTimeout, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while making http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	var parser expfmt.TextParser
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot parse metrics: %w", err)
	}

	return families, nil
}
