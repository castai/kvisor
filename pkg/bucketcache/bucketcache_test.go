package bucketcache

import (
	"testing"

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
}
