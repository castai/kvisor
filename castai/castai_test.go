package castai

import (
	"io"
	"os"
)

//func TestClient_SendCISReport(t *testing.T) {
//	r := require.New(t)
//
//	clusterID := os.Getenv("CLUSTER_ID")
//	apiKey := os.Getenv("API_KEY")
//	apiURL := os.Getenv("API_URL")
//
//	if clusterID == "" || apiURL == "" || apiKey == "" {
//		t.Skip("no api key provided")
//	}
//
//	cl := NewDefaultClient(apiURL, apiKey, logrus.DebugLevel, &config.SecurityAgentVersion{
//		Version: "69",
//	})
//	c := NewClient(logrus.New(), cl, clusterID)
//
//	report := readReport()
//
//	err := c.SendCISReport(context.Background(), report)
//	r.NoError(err)
//}

func readReport() []byte {
	file, _ := os.OpenFile("./kube-bench-gke.json", os.O_RDONLY, 0666)
	reportBytes, _ := io.ReadAll(file)

	return reportBytes
}
