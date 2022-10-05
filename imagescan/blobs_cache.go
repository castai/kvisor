package imagescan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	lru "github.com/hashicorp/golang-lru"
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
		blobsStore: newMemoryBlobsStore(log),
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
	ID   string          `json:"id"`
	Blob json.RawMessage `json:"blob"`
}

type getBlobRequest struct {
	ID string `json:"id"`
}

type getBlobResponse struct {
	Blob json.RawMessage `json:"blob"`
}

func (s *BlobsCacheServer) putBlob(w http.ResponseWriter, r *http.Request) {
	var req pubBlobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Errorf("decoding pub blob request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.blobsStore.putBlob(req.ID, req.Blob)

	w.WriteHeader(http.StatusOK)
}

func (s *BlobsCacheServer) getBlob(w http.ResponseWriter, r *http.Request) {
	var req getBlobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Errorf("decoding get blob request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	blob, found := s.blobsStore.getBlob(req.ID)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := getBlobResponse{Blob: blob}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Errorf("encoding get blob response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type blobsStore interface {
	putBlob(key string, blob []byte)
	getBlob(key string) ([]byte, bool)
}

func newMemoryBlobsStore(log logrus.FieldLogger) blobsStore {
	// One large blob json size is around 16KB, so we should use max 32MB of extra memory.
	cache, _ := lru.New(2000)
	return &memoryBlobsStore{
		log:   log,
		cache: cache,
	}
}

type memoryBlobsStore struct {
	log   logrus.FieldLogger
	cache *lru.Cache
}

func (s *memoryBlobsStore) putBlob(key string, blob []byte) {
	s.log.Debugf("adding image blob to cache, current cache size=%d", s.cache.Len())
	evicted := s.cache.Add(key, blob)
	if evicted {
		s.log.Info("evicted old image blob cache entry")
	}
}

func (s *memoryBlobsStore) getBlob(key string) ([]byte, bool) {
	val, ok := s.cache.Get(key)
	if !ok {
		return nil, false
	}
	return val.([]byte), true
}
