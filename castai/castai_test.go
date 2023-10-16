package castai

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/config"
)

func TestClient_SendCISReport(t *testing.T) {
	r := require.New(t)

	clusterID := os.Getenv("CLUSTER_ID")
	apiKey := os.Getenv("API_KEY")
	apiURL := os.Getenv("API_URL")

	if clusterID == "" || apiURL == "" || apiKey == "" {
		t.Skip("no api key provided")
	}

	cl := NewClient(apiURL, apiKey, nil, clusterID, false, "castai-kvisor", config.SecurityAgentVersion{
		Version: "69",
	})

	report, err := readReport()
	r.NoError(err)

	err = cl.SendCISReport(context.Background(), report)
	r.NoError(err)
}

func readReport() (*KubeBenchReport, error) {
	file, err := os.OpenFile("./kube-bench-gke.json", os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}

	reportBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var report KubeBenchReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return nil, err
	}

	return &report, nil
}
