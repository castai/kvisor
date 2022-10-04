package imagescan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

type BlobsCacheServerConfig struct {
	ServePort int
}

func NewBlobsCacheServer(log logrus.FieldLogger, cfg BlobsCacheServerConfig) *BlobsCacheServer {
	return &BlobsCacheServer{
		log:        log,
		cfg:        cfg,
		blobsStore: &fsBlobsStore{dataDir: "/tmp"},
	}
}

type BlobsCacheServer struct {
	log        logrus.FieldLogger
	cfg        BlobsCacheServerConfig
	blobsStore blobsStore
}

func (s *BlobsCacheServer) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/PutBlob", s.putBlob)
	mux.HandleFunc("/GetBlob", s.getBlob)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.cfg.ServePort),
		Handler:      mux,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			s.log.Errorf("blobs cache server shutdown: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
		s.log.Errorf("blobs cache server listen: %v", err)
	}
}

type pubBlobRequest struct {
	ImageID string          `json:"image_id"`
	Blob    json.RawMessage `json:"blob"`
}

func (s *BlobsCacheServer) putBlob(w http.ResponseWriter, r *http.Request) {

}

func (s *BlobsCacheServer) getBlob(w http.ResponseWriter, r *http.Request) {

}

type blobsStore interface {
	putBlob(key string, blob []byte) error
}

type fsBlobsStore struct {
	dataDir string
}

func (f *fsBlobsStore) putBlob(key string, blob []byte) error {
	return os.WriteFile(key, blob, 0600)
}
