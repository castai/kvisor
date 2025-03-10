package bucketcache

import (
	"slices"
	"sync"

	"github.com/elastic/go-freelru"
)

type BucketCache[K comparable, V comparable] struct {
	cache         freelru.Cache[K, []V]
	maxBucketSize int
	mu            sync.RWMutex
}

func New[K comparable, V comparable](cacheSize uint32, maxBucketSize uint32, hash freelru.HashKeyCallback[K]) (*BucketCache[K, V], error) {
	cache, err := freelru.NewSynced[K, []V](cacheSize, hash)
	if err != nil {
		return nil, err
	}

	return &BucketCache[K, V]{
		cache:         cache,
		maxBucketSize: int(maxBucketSize),
	}, nil
}

func (b *BucketCache[K, V]) AddToBucket(k K, val V) bool {
	return b.addToCache(k, val, false)
}

func (b *BucketCache[K, V]) RemoveFromBucket(k K, val V) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, found := b.cache.Get(k)
	if !found {
		return false
	}

	newBucket := slices.DeleteFunc(bucket, func(v V) bool {
		return v == val
	})

	if len(newBucket) == 0 {
		return b.cache.Remove(k)
	} else if len(bucket) == len(newBucket) {
		return false
	}

	b.cache.Add(k, newBucket)
	return true
}

func (b *BucketCache[K, V]) ForceAddToBucket(k K, val V) {
	b.addToCache(k, val, true)
}

func (b *BucketCache[K, V]) addToCache(k K, val V, force bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, found := b.cache.Get(k)
	if !found {
		b.cache.Add(k, []V{val})
		return true
	}

	if len(bucket) >= b.maxBucketSize {
		if force {
			bucket[0] = val
			b.cache.Add(k, bucket)
			return true
		}

		return false
	}

	b.cache.Add(k, append(bucket, val))

	return true
}

func (b *BucketCache[K, V]) GetBucket(k K) []V {
	res, _ := b.cache.Get(k)
	return res
}

func (b *BucketCache[K, V]) RemoveBucket(k K) bool {
	return b.cache.Remove(k)
}
