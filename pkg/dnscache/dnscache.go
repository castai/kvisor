package dnscache

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
)

func New(size uint32, ttl time.Duration) *Cache {
	cache, err := freelru.NewSharded[uint64, string](size, func(k uint64) uint32 {
		return uint32(k) //nolint:gosec
	})
	if err != nil {
		panic(err)
	}
	cache.SetLifetime(ttl)

	return &Cache{
		cache:       cache,
		digest:      xxhash.New(),
		cgroupIDBuf: make([]byte, 8),
	}
}

type Cache struct {
	keyMu       sync.Mutex
	digest      *xxhash.Digest
	cgroupIDBuf []byte

	cache *freelru.ShardedLRU[uint64, string]
}

func (c *Cache) Get(key uint64) (string, bool) {
	return c.cache.Get(key)
}

func (c *Cache) Add(key uint64, value string) {
	c.cache.Add(key, value)
}

func (c *Cache) CalcKey(cgroupID uint64, addr netip.Addr) uint64 {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()

	c.digest.Reset()
	binary.LittleEndian.PutUint64(c.cgroupIDBuf, cgroupID)
	_, _ = c.digest.Write(c.cgroupIDBuf)
	addrBytes, _ := addr.MarshalBinary()
	_, _ = c.digest.Write(addrBytes)
	return c.digest.Sum64()
}
