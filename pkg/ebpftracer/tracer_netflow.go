package ebpftracer

import (
	"fmt"
	"strings"
)

type NetflowGrouping uint64

func (n *NetflowGrouping) String() string {
	return fmt.Sprintf("%d", *n)
}

func (n *NetflowGrouping) Set(s string) error {
	v, err := parseNetflowGrouping(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

func (n *NetflowGrouping) Type() string {
	return "NetflowGrouping"
}

const (
	NetflowGroupingDropSrcPort NetflowGrouping = (1 << iota)
)

var netflowGroupingStrings = map[string]NetflowGrouping{
	"drop_src_port": NetflowGroupingDropSrcPort,
}

func parseNetflowGrouping(s string) (NetflowGrouping, error) {
	if s == "" {
		return 0, nil
	}
	var res NetflowGrouping
	for _, flagStr := range strings.Split(s, "|") {
		flag, found := netflowGroupingStrings[flagStr]
		if !found {
			return 0, fmt.Errorf("unknown grouping flag %q", flagStr)
		}
		res |= flag
	}
	return res, nil
}
