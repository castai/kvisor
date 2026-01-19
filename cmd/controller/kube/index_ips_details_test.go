package kube

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestIPsDetails(t *testing.T) {
	t.Run("find single record", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
			region:     "us-east-1",
		}

		m.set(ip, info)

		result, found := m.find(ip)
		r.True(found)
		r.Equal("us-east-1a", result.zone)
		r.Equal("us-east-1", result.region)
		r.Equal(types.UID("pod-1"), result.resourceID)
	})

	t.Run("find not found", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		result, found := m.find(ip)
		r.False(found)
		r.Equal(IPInfo{}, result)
	})

	t.Run("find multiple records with same zone", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		// Add first record
		info1 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
			region:     "us-east-1",
		}
		m.set(ip, info1)

		// Add second record with same zone (e.g., hostNetwork pods)
		info2 := IPInfo{
			resourceID: "pod-2",
			zone:       "us-east-1a",
			region:     "us-east-1",
		}
		m.set(ip, info2)

		result, found := m.find(ip)
		r.True(found)
		r.Equal("us-east-1a", result.zone)
		r.Equal("us-east-1", result.region)
	})

	t.Run("find multiple records with different zones", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		// Add first record
		info1 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
			region:     "us-east-1",
		}
		m.set(ip, info1)

		// Add second record with different zone (GCP regional subnets)
		info2 := IPInfo{
			resourceID: "pod-2",
			zone:       "us-east-1b",
			region:     "us-east-1",
		}
		m.set(ip, info2)

		result, found := m.find(ip)
		r.True(found)
		r.Equal("", result.zone) // Zone is empty when multiple different zones
		r.Equal("us-east-1", result.region)
	})

	t.Run("set new record", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
			region:     "us-east-1",
		}

		m.set(ip, info)

		r.Len(m[ip], 1)
		r.Equal(types.UID("pod-1"), m[ip][0].resourceID)
		r.False(m[ip][0].setAt.IsZero())
		r.Equal(ip, m[ip][0].ip)
	})

	t.Run("set updates existing record", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID:  "pod-1",
				Name: "old-name",
			},
		}

		info1 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
			PodInfo: &PodInfo{
				Pod: pod,
			},
		}
		m.set(ip, info1)

		// Update the same pod (same resourceID)
		pod2 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID:  "pod-1",
				Name: "new-name",
			},
		}

		info2 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1b", // Zone changed
			PodInfo: &PodInfo{
				Pod: pod2,
			},
		}
		m.set(ip, info2)

		// Should have only one record (updated)
		r.Len(m[ip], 1)
		r.Equal("us-east-1b", m[ip][0].zone)
		r.Equal("new-name", m[ip][0].PodInfo.Pod.Name)
	})

	t.Run("set multiple records for same IP", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		// Add first pod
		info1 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info1)

		// Add second pod with same IP (e.g., hostNetwork: true)
		info2 := IPInfo{
			resourceID: "pod-2",
			zone:       "us-east-1a",
		}
		m.set(ip, info2)

		// Should have two records
		r.Len(m[ip], 2)
		r.Equal(types.UID("pod-1"), m[ip][0].resourceID)
		r.Equal(types.UID("pod-2"), m[ip][1].resourceID)
	})

	t.Run("delete marks record as deleted", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info)

		m.delete(ip, "pod-1")

		r.Len(m[ip], 1)
		r.NotNil(m[ip][0].deleteAt)
		r.False(m[ip][0].deleteAt.IsZero())
	})

	t.Run("delete when IP not found does nothing", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		// Should not panic
		m.delete(ip, "pod-1")

		r.Empty(m)
	})

	t.Run("delete when resourceID not found does nothing", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info)

		m.delete(ip, "pod-2") // Different resourceID

		r.Len(m[ip], 1)
		r.Nil(m[ip][0].deleteAt) // Should not be deleted
	})

	t.Run("delete only marks matching record in list", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")

		info1 := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info1)

		info2 := IPInfo{
			resourceID: "pod-2",
			zone:       "us-east-1a",
		}
		m.set(ip, info2)

		m.delete(ip, "pod-1")

		r.Len(m[ip], 2)
		r.NotNil(m[ip][0].deleteAt) // pod-1 is deleted
		r.Nil(m[ip][1].deleteAt)    // pod-2 is not deleted
	})

	t.Run("cleanup removes old deleted records", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info)

		// Mark as deleted
		m.delete(ip, "pod-1")

		// Wait a bit
		time.Sleep(10 * time.Millisecond)

		// Cleanup with short TTL
		deleted := m.cleanup(5 * time.Millisecond)

		r.Equal(1, deleted)
		r.Empty(m) // IP should be removed completely
	})

	t.Run("cleanup keeps recent deleted records", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info)

		// Mark as deleted
		m.delete(ip, "pod-1")

		// Cleanup with long TTL
		deleted := m.cleanup(1 * time.Hour)

		r.Equal(0, deleted)
		r.Len(m[ip], 1)             // Record still exists
		r.NotNil(m[ip][0].deleteAt) // But is marked as deleted
	})

	t.Run("cleanup keeps non-deleted records", func(t *testing.T) {
		r := require.New(t)
		m := make(ipsDetails)

		ip := netip.MustParseAddr("10.0.1.50")
		info := IPInfo{
			resourceID: "pod-1",
			zone:       "us-east-1a",
		}
		m.set(ip, info)

		// Don't delete, just cleanup
		deleted := m.cleanup(1 * time.Millisecond)

		r.Equal(0, deleted)
		r.Len(m[ip], 1)
		r.Nil(m[ip][0].deleteAt)
	})
}
