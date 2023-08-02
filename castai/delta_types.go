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
	Event            EventType         `json:"event"`
	ObjectUID        string            `json:"object_uid"`
	ObjectName       string            `json:"object_name,omitempty"`
	ObjectNamespace  string            `json:"object_namespace,omitempty"`
	ObjectKind       string            `json:"object_kind,omitempty"`
	ObjectAPIVersion string            `json:"object_api_version,omitempty"`
	ObjectCreatedAt  time.Time         `json:"object_created_at,omitempty"`
	ObjectOwnerUID   string            `json:"object_owner_uid,omitempty"`
	ObjectLabels     map[string]string `json:"object_labels,omitempty"`

	// ObjectContainers and ObjectStatus are set only for objects which could contain containers.
	ObjectContainers []Container `json:"object_containers,omitempty"`
	ObjectStatus     interface{} `json:"object_status,omitempty"`
	// ObjectImagesChanged is set to true when previous container status contained different image set.
	ObjectImagesChanged bool `json:"object_images_changed,omitempty"`
}

type Container struct {
	Name      string `json:"name"`
	ImageName string `json:"image_name,omitempty"`
}
