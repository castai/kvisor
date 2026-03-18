package gpu

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/castai/logging"
	"github.com/stretchr/testify/require"
)

const testMetricsText = `# HELP DCGM_FI_DEV_GPU_TEMP Current temperature readings for the device in degrees C.
# TYPE DCGM_FI_DEV_GPU_TEMP gauge
DCGM_FI_DEV_GPU_TEMP{gpu="0",UUID="GPU-abc",device="nvidia0",modelName="Tesla T4",Hostname="node-1",container="",namespace="",pod=""} 40
`

func TestScraper_Scrape(t *testing.T) {
	log := logging.New()

	t.Run("scrapes metrics from multiple URLs", func(t *testing.T) {
		srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testMetricsText))
		}))
		defer srv1.Close()

		srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testMetricsText))
		}))
		defer srv2.Close()

		s := newScraper(srv1.Client(), log)

		results, err := s.Scrape(context.Background(), []string{srv1.URL, srv2.URL})

		r := require.New(t)
		r.NoError(err)
		r.Len(results, 2)
		for _, fam := range results {
			r.Contains(fam, "DCGM_FI_DEV_GPU_TEMP")
		}
	})

	t.Run("partial success on HTTP error", func(t *testing.T) {
		good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testMetricsText))
		}))
		defer good.Close()

		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer bad.Close()

		s := newScraper(good.Client(), log)

		results, err := s.Scrape(context.Background(), []string{good.URL, bad.URL})

		r := require.New(t)
		r.NoError(err)
		r.Len(results, 1)
	})

	t.Run("partial success on unreachable URL", func(t *testing.T) {
		good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testMetricsText))
		}))
		defer good.Close()

		s := newScraper(good.Client(), log)

		results, err := s.Scrape(context.Background(), []string{good.URL, "http://127.0.0.1:1/metrics"})

		r := require.New(t)
		r.NoError(err)
		r.Len(results, 1)
	})
}
