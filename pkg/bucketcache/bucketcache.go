package bucketcache

import (
	"github.com/elastic/go-freelru"
)

type BucketCache[K comparable, V any] struct {
	cache         freelru.Cache[K, []V]
	maxBucketSize int
}

func New[K comparable, V any](cacheSize uint32, maxBucketSize uint32, hash freelru.HashKeyCallback[K]) (*BucketCache[K, V], error) {
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

func (b *BucketCache[K, V]) ForceAddToBucket(k K, val V) {
	b.addToCache(k, val, true)
}

func (b *BucketCache[K, V]) addToCache(k K, val V, force bool) bool {
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
