package blobscache

import (
	"fmt"
	"net/http"

	"github.com/castai/logging"
	"github.com/cespare/xxhash/v2"
	lru "github.com/elastic/go-freelru"
	"github.com/labstack/echo/v4"
)

func NewServer(log *logging.Logger) *Server {
	return &Server{
		log:        log.WithField("component", "blobscache"),
		blobsCache: newMemoryBlobsCacheStore(log),
	}
}

type Server struct {
	log        *logging.Logger
	blobsCache blobsCacheStore
}

func (s *Server) RegisterHandlers(e *echo.Echo) {
	e.POST("/blobscache/PutBlob", s.putBlob)
	e.POST("/blobscache/GetBlob", s.getBlob)
}

func (s *Server) putBlob(c echo.Context) error {
	var req PubBlobRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	s.blobsCache.putBlob(req.Key, req.Blob)
	return c.NoContent(http.StatusOK)
}

func (s *Server) getBlob(c echo.Context) error {
	var req GetBlobRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	blob, found := s.blobsCache.getBlob(req.Key)
	if !found {
		return c.NoContent(http.StatusNotFound)
	}

	resp := GetBlobResponse{Blob: blob}
	return c.JSON(http.StatusOK, resp)
}

type blobsCacheStore interface {
	putBlob(key string, blob []byte)
	getBlob(key string) ([]byte, bool)
}

func newMemoryBlobsCacheStore(log *logging.Logger) blobsCacheStore {
	// One large blob json size is around 16KB, so we should use max 32MB of extra memory.
	cache, err := lru.NewSynced[string, []byte](2000, func(s string) uint32 {
		return uint32(xxhash.Sum64String(s)) //nolint:gosec
	})
	if err != nil {
		panic(fmt.Sprintf("creating blobs cache lru: %v", err))
	}
	return &memoryBlobsCacheStore{
		log:   log,
		cache: cache,
	}
}

type memoryBlobsCacheStore struct {
	log   *logging.Logger
	cache lru.Cache[string, []byte]
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
	return val, true
}
