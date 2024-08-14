package ebpftracer

import (
	"fmt"
	"strings"

	"github.com/castai/kvisor/pkg/ebpftracer/events"
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

type EventsPolicyConfig struct {
	EnabledEvents []events.ID `json:"enabledEvents"`
}

func (n *EventsPolicyConfig) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *EventsPolicyConfig) Set(s string) error {
	n.EnabledEvents = []events.ID{}
	parts := strings.Split(s, ",")
	defs := newEventsDefinitionSet(&tracerObjects{})
	defsByName := map[string]events.ID{}
	for id, def := range defs {
		defsByName[def.name] = id
	}
	for _, eventName := range parts {
		eventName = strings.TrimSpace(eventName)
		eventID, found := defsByName[eventName]
		if !found {
			return fmt.Errorf("unknown event name %q", eventName)
		}
		n.EnabledEvents = append(n.EnabledEvents, eventID)
	}
	return nil
}

func (n *EventsPolicyConfig) Type() string {
	return "EventsPolicyConfig"
}
