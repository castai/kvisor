package controllers

import (
	"context"
	"time"
)

type PodsStats struct {
	ContainerStatuses []ContainerStatusStats `json:"containerStatuses"`
	Phases            []PodPhaseStats        `json:"phases"`
	TrafficTypes      []TrafficTypeStats     `json:"trafficTypes"`
}

type PodPhaseStats struct {
	Value string `json:"value"`
	Text  string `json:"text"`
	Count int    `json:"count"`
}

type TrafficTypeStats struct {
	Value string `json:"value"`
	Text  string `json:"text"`
	Count int    `json:"count"`
}

type ContainerStatusStats struct {
	Value string `json:"value"`
	Text  string `json:"text"`
	Count int    `json:"count"`
}

type TrafficType string

const (
	TrafficTypeInternet     TrafficType = "internet"
	TrafficTypePrivate      TrafficType = "private"
	TrafficTypeControlPlane TrafficType = "control_plane"
	TrafficTypeCrossZone    TrafficType = "cross_zone"
	TrafficTypeWorkload     TrafficType = "workload"
	TrafficTypeService      TrafficType = "service"
)

type FlowsFilter struct {
	Namespaces []string `json:"namespaces"`
	IDs        []string `json:"ids"`
	// If set to true filtering by IDs will try to filter by WorkloadKey or ID.
	TryWorkloadIDs bool `json:"-"`
}

type Namespace struct {
	Name string `json:"name"`
}

func sleep(ctx context.Context, d time.Duration) {
	timeout := time.NewTimer(d)
	defer timeout.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timeout.C:
		return
	}
}
