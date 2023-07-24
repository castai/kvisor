package imagescan

import (
	"context"
	"io"
	"net/http"
	"time"

	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"

	"github.com/castai/kvisor/castai"
)

func NewScanHttpHandler(log logrus.FieldLogger, client castai.Client) *ScanHTTPHandler {
	return &ScanHTTPHandler{
		log:    log.WithField("component", "scan_http_handler"),
		client: client,
	}
}

// ScanHTTPHandler receives image metadata from scan job and sends it to CAST AI platform.
type ScanHTTPHandler struct {
	log    logrus.FieldLogger
	client castai.Client
}

func (h *ScanHTTPHandler) Handle(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var md castai.ImageMetadata
	if err := json.Unmarshal(data, &md); err != nil {
		h.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.client.SendImageMetadata(ctx, &md); err != nil {
		h.log.Errorf("sending image report: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
