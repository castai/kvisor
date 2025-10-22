package kube

import (
	"net/netip"
	"time"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/types"
)

type ipsDetails map[netip.Addr][]IPInfo

func (m ipsDetails) find(ip netip.Addr) (IPInfo, bool) {
	list, found := m[ip]
	if !found {
		return IPInfo{}, false
	}
	// We can use ip info only if there is a single record.
	// If we have multiple records here then we have a collision. Since we do not track destination container startup time
	// we can't pick latest valid record by timestamp.
	if len(list) == 1 {
		return list[0], true
	}
	return IPInfo{}, false
}

func (m ipsDetails) set(ip netip.Addr, info IPInfo) {
	list := m[ip]

	info.setAt = time.Now()
	info.ip = ip

	// Update existing non deleted record if any.
	for i := range list {
		v := list[i]
		if v.resourceID == info.resourceID && v.deleteAt == nil {
			list[i] = info
			return
		}
	}

	// Add new record.
	list = append(list, info)
	m[ip] = list
}

func (m ipsDetails) delete(ip netip.Addr, resourceID types.UID) {
	list := m[ip]
	if len(list) == 0 {
		return
	}

	now := time.Now()
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].resourceID == resourceID && list[i].deleteAt == nil {
			list[i].deleteAt = &now
			break
		}
	}
	m[ip] = list
	spew.Dump(m)
}

func (m ipsDetails) cleanup(ttl time.Duration) int {
	if len(m) == 0 {
		return 0
	}

	cutoff := time.Now().Add(-ttl)
	var deleted int
	for ip, list := range m {
		var kept []IPInfo
		for _, info := range list {
			if info.deleteAt == nil || info.deleteAt.After(cutoff) {
				kept = append(kept, info)
			} else {
				deleted++
			}
		}

		if len(kept) == 0 {
			delete(m, ip)
		} else {
			m[ip] = kept
		}
	}
	return deleted
}
