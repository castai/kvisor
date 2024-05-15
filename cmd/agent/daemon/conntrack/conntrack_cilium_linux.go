//go:build linux

package conntrack

import (
	"net/netip"
	"path/filepath"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	ciliumCt4    *bpf.Map
	ciliumCt6    *bpf.Map
	backends4Map *bpf.Map
	backends6Map *bpf.Map
)

// TODO(anjmao): Rewrite this with simple cilium/ebpf map lookups to not depend on cilium packages.
func iniCiliumMaps(log *logging.Logger) bool {
	var err error

	ciliumCt4, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, ctmap.MapNameTCP4Global)), &ctmap.CtKey4Global{}, &ctmap.CtEntry{})
	if err != nil {
		log.Info(err.Error())
		// We always expect v4 map. If it doesn't exist assume that cilium is not used.
		return false
	} else {
		log.Infof("found cilium ebpf-map %s", ctmap.MapNameTCP4Global)
	}

	ciliumCt6, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, ctmap.MapNameTCP6Global)), &ctmap.CtKey6Global{}, &ctmap.CtEntry{})
	if err != nil {
		log.Warn(err.Error())
	} else {
		log.Infof("found cilium ebpf-map %s", ctmap.MapNameTCP6Global)
	}
	backends4Map, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, lbmap.Backend4MapV3Name)), &lbmap.Backend4KeyV3{}, &lbmap.Backend4ValueV3{})
	if err != nil {
		log.Warn(err.Error())
	} else {
		log.Infof("found cilium ebpf-map %s", lbmap.Backend4MapV3Name)
	}

	backends6Map, err = bpf.OpenMap(proc.HostPath(filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath, lbmap.Backend6MapV3Name)), &lbmap.Backend6KeyV3{}, &lbmap.Backend6ValueV3{})
	if err != nil {
		log.Warn(err.Error())
	} else {
		log.Infof("found cilium ebpf-map %s", lbmap.Backend6MapV3Name)
	}

	return true
}

func closeCilium() {
	if ciliumCt4 != nil {
		_ = ciliumCt4.Close()
	}
	if ciliumCt6 != nil {
		_ = ciliumCt6.Close()
	}
	if backends4Map != nil {
		_ = backends4Map.Close()
	}
	if backends6Map != nil {
		_ = backends6Map.Close()
	}
}

func lookupCiliumConntrackTable(src, dst netip.AddrPort) *netip.AddrPort {
	if src.Addr().Is4() {
		return lookupCilium4(src, dst)
	}
	if src.Addr().Is6() {
		return lookupCilium6(src, dst)
	}
	return nil
}

func lookupCilium4(src, dst netip.AddrPort) *netip.AddrPort {
	if ciliumCt4 == nil || backends4Map == nil {
		return nil
	}
	key := &ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourcePort: dst.Port(),
				SourceAddr: src.Addr().As4(),
				DestPort:   src.Port(),
				DestAddr:   dst.Addr().As4(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt4.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	e := v.(*ctmap.CtEntry)

	// https://github.com/cilium/cilium/blob/v1.13.0/bpf/lib/common.h#L819
	// CtEntity.RxBytes stores `backend_id` if `e.Flags & TUPLE_F_SERVICE`
	backendId := e.RxBytes
	backendKey := lbmap.NewBackend4KeyV3(loadbalancer.BackendID(backendId))
	b, err := backends4Map.Lookup(backendKey)
	if err != nil || b == nil {
		return nil
	}
	var backend lbmap.BackendValue
	switch bv := b.(type) {
	case *lbmap.Backend4Value:
		backend = bv.ToHost()
	case *lbmap.Backend4ValueV3:
		backend = bv.ToHost()
	default:
		return nil
	}
	backendIP, _ := netip.AddrFromSlice(backend.GetAddress())
	res := netip.AddrPortFrom(backendIP, backend.GetPort())
	return &res
}

func lookupCilium6(src, dst netip.AddrPort) *netip.AddrPort {
	if ciliumCt6 == nil || backends6Map == nil {
		return nil
	}
	key := &ctmap.CtKey6Global{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourcePort: dst.Port(),
				SourceAddr: src.Addr().As16(),
				DestPort:   src.Port(),
				DestAddr:   dst.Addr().As16(),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	v, err := ciliumCt6.Lookup(key.ToNetwork())
	if err != nil || v == nil {
		return nil
	}
	e := v.(*ctmap.CtEntry)
	backendId := e.RxBytes
	backendKey := lbmap.NewBackend6KeyV3(loadbalancer.BackendID(backendId))
	b, err := backends6Map.Lookup(backendKey)
	if err != nil || b == nil {
		return nil
	}
	var backend lbmap.BackendValue
	switch bv := b.(type) {
	case *lbmap.Backend6Value:
		backend = bv.ToHost()
	case *lbmap.Backend6ValueV3:
		backend = bv.ToHost()
	default:
		return nil
	}
	backendIP, _ := netip.AddrFromSlice(backend.GetAddress())
	res := netip.AddrPortFrom(backendIP, backend.GetPort())
	return &res
}
