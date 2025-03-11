package bucketcache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func intHash(n int) uint32 {
	return uint32(n)
}

func TestBucketCache(t *testing.T) {
	t.Run("add single value", func(t *testing.T) {
		r := require.New(t)

		key := 10
		val := 20

		cache, err := New[int, int](10, 5, intHash)
		r.NoError(err)

		added := cache.AddToBucket(key, val)
		r.True(added)

		vals := cache.GetBucket(key)
		r.Equal([]int{val}, vals)
	})

	t.Run("add multiple values", func(t *testing.T) {
		r := require.New(t)

		key := 10
		vals := []int{20, 30, 40}

		cache, err := New[int, int](10, 5, intHash)
		r.NoError(err)

		for _, v := range vals {
			added := cache.AddToBucket(key, v)
			r.True(added)
		}

		result := cache.GetBucket(key)
		r.Equal(vals, result)
	})

	t.Run("add multiple buckets", func(t *testing.T) {
		r := require.New(t)

		key1 := 10
		val1 := 20

		key2 := 90
		val2 := 99

		cache, err := New[int, int](10, 5, intHash)
		r.NoError(err)

		added := cache.AddToBucket(key1, val1)
		r.True(added)

		added = cache.AddToBucket(key2, val2)
		r.True(added)

		vals := cache.GetBucket(key1)
		r.Equal([]int{val1}, vals)

		vals = cache.GetBucket(key2)
		r.Equal([]int{val2}, vals)
	})

	t.Run("should not add more values than max bucket size", func(t *testing.T) {
		r := require.New(t)

		key := 10
		vals := []int{1, 2, 3, 4, 5, 6, 7, 8}

		cache, err := New[int, int](2, 2, intHash)
		r.NoError(err)

		for i, val := range vals {
			added := cache.AddToBucket(key, val)
			if i < 2 {
				r.True(added)
			} else {
				r.False(added)
			}
		}

		result := cache.GetBucket(key)
		r.Equal([]int{1, 2}, result)
	})

	t.Run("should drop oldest bucket when going over cache size", func(t *testing.T) {
		r := require.New(t)

		key1 := 11
		key2 := 12
		key3 := 13

		cache, err := New[int, int](2, 2, intHash)
		r.NoError(err)

		cache.AddToBucket(key1, 1)
		cache.AddToBucket(key2, 2)
		cache.AddToBucket(key3, 3)

		result := cache.GetBucket(key1)
		r.Nil(result)

		result = cache.GetBucket(key2)
		r.Equal([]int{2}, result)

		result = cache.GetBucket(key3)
		r.Equal([]int{3}, result)
	})

	t.Run("remove values from bucket", func(t *testing.T) {
		r := require.New(t)

		key := 10
		vals := []int{1, 2, 3, 4, 5}

		cache, err := New[int, int](1, 5, intHash)
		r.NoError(err)

		for _, val := range vals {
			added := cache.AddToBucket(key, val)
			r.True(added)
		}

		result := cache.GetBucket(key)
		r.Equal(vals, result)

		t.Run("remove value", func(t *testing.T) {
			removed := cache.RemoveFromBucket(key, 3)
			r.True(removed)
			result = cache.GetBucket(key)
			r.Equal([]int{1, 2, 4, 5}, result)
		})

		t.Run("remove non-existing value", func(t *testing.T) {
			removed := cache.RemoveFromBucket(key, 6)
			r.False(removed)
			result = cache.GetBucket(key)
			r.Equal([]int{1, 2, 4, 5}, result)
		})

		t.Run("remove bucket", func(t *testing.T) {
			removed := cache.RemoveBucket(key)
			r.True(removed)
			result = cache.GetBucket(key)
			r.Empty(result)
		})
	})

	t.Run("should add and remove values concurrently", func(t *testing.T) {
		r := require.New(t)

		var (
			key     = 1
			workers = 10
			size    = 100
		)

		cache, err := New[int, int](1, uint32(workers*size), intHash)
		r.NoError(err)

		t.Run("add values", func(t *testing.T) {
			for i := range workers {
				go func() {
					for j := range size {
						added := cache.AddToBucket(key, i*size+j)
						r.True(added)
					}
				}()
			}
			r.Eventually(func() bool {
				return len(cache.GetBucket(key)) == workers*size
			}, 2*time.Second, 10*time.Millisecond,
				"expected %d values in the bucket, got %d", workers*size, len(cache.GetBucket(key)))
		})

		t.Run("remove values", func(t *testing.T) {
			for i := range workers {
				go func() {
					for j := range size {
						removed := cache.RemoveFromBucket(key, i*size+j)
						r.True(removed)
					}
				}()
			}
			r.Eventually(func() bool {
				return len(cache.GetBucket(key)) == 0
			}, 2*time.Second, 10*time.Millisecond,
				"expected 0 values in the bucket, got %d", len(cache.GetBucket(key)))
		})
	})
}
