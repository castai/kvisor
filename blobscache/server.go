package blobscache

import (
	"net/http"

	lru "github.com/hashicorp/golang-lru"
	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
)

type ServerConfig struct {
}

func NewServer(log logrus.FieldLogger, cfg ServerConfig) *Server {
	return &Server{
		log:        log.WithField("component", "blobscache"),
		cfg:        cfg,
		blobsCache: newMemoryBlobsCacheStore(log),
	}
}

type Server struct {
	log        logrus.FieldLogger
	cfg        ServerConfig
	blobsCache blobsCacheStore
}

func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v1/blobscache/PutBlob", s.putBlob)
	mux.HandleFunc("/v1/blobscache/GetBlob", s.getBlob)
}

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request) {
	var req PubBlobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Errorf("decoding put blob request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.blobsCache.putBlob(req.Key, req.Blob)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	var req GetBlobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.log.Errorf("decoding get blob request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	blob, found := s.blobsCache.getBlob(req.Key)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := GetBlobResponse{Blob: blob}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Errorf("encoding get blob response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type blobsCacheStore interface {
	putBlob(key string, blob []byte)
	getBlob(key string) ([]byte, bool)
}

func newMemoryBlobsCacheStore(log logrus.FieldLogger) blobsCacheStore {
	// One large blob json size is around 16KB, so we should use max 32MB of extra memory.
	cache, _ := lru.New(2000)
	return &memoryBlobsCacheStore{
		log:   log,
		cache: cache,
	}
}

type memoryBlobsCacheStore struct {
	log   logrus.FieldLogger
	cache *lru.Cache
}

func (c *memoryBlobsCacheStore) putBlob(key string, blob []byte) {
	c.log.Debugf("adding image blob to cache, current cache size=%d", c.cache.Len())
	evicted := c.cache.Add(key, blob)
	if evicted {
		c.log.Info("evicted old image blob cache entry")
	}
}

func (c *memoryBlobsCacheStore) getBlob(key string) ([]byte, bool) {
	val, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}
	return val.([]byte), true
}
