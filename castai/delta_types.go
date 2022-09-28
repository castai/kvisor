package castai

import (
	"time"
)

type EventType string

const (
	EventAdd    EventType = "add"
	EventUpdate EventType = "update"
	EventDelete EventType = "delete"
)

type Delta struct {
	FullSnapshot bool        `json:"full_snapshot,omitempty"`
	Items        []DeltaItem `json:"items"`
}

type DeltaItem struct {
	Event            EventType `json:"event"`
	ObjectUID        string    `json:"object_uid"`
	ObjectName       string    `json:"object_name,omitempty"`
	ObjectNamespace  string    `json:"object_namespace,omitempty"`
	ObjectKind       string    `json:"object_kind,omitempty"`
	ObjectAPIVersion string    `json:"object_api_version,omitempty"`
	ObjectCreatedAt  time.Time `json:"object_created_at,omitempty"`
}
