package ebpftracer

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

func (t *Tracer) addDNSResponseToCache(cgroupID uint64, answers []*castaipb.DNSAnswers) error {
	cacheVal, found := t.dnsCache.Get(cgroupID)
	if !found {
		var err error

		cacheSize := uint32(1024)
		if t.cfg.CgroupDNSCacheMaxEntries > 0 {
			cacheSize = t.cfg.CgroupDNSCacheMaxEntries
		}

		cacheVal, err = freelru.NewSynced[netip.Addr, string](cacheSize, func(k netip.Addr) uint32 {
			return uint32(xxhash.Sum64(k.AsSlice())) // nolint:gosec
		})
		if err != nil {
			return fmt.Errorf("creating dns cache: %w", err)
		}
		t.dnsCache.Add(cgroupID, cacheVal)
	}
	for _, answer := range answers {
		if len(answer.Ip) == 0 {
			continue
		}
		addr, ok := netip.AddrFromSlice(answer.Ip)
		if !ok {
			continue
		}

		name := strings.ToValidUTF8(answer.Name, "")
		cacheVal.Add(addr.Unmap(), name)
	}
	return nil
}

func (t *Tracer) GetDNSNameFromCache(cgroupID uint64, addr netip.Addr) string {
	if cache, found := t.dnsCache.Get(cgroupID); found {
		if name, found := cache.Get(addr.Unmap()); found {
			return name
		}
	}
	return ""
}

func (t *Tracer) RemoveCgroupFromDNSCache(cgroup uint64) {
	t.dnsCache.Remove(cgroup)
	t.log.Debugf("removed cgroup: %d", cgroup)
}
