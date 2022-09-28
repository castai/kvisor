package castai

import (
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type EventType string
type State string
type NodeType string

const (
	EventAdd    EventType = "add"
	EventUpdate EventType = "update"
	EventDelete EventType = "delete"
)

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL State = "FAIL"
	// WARN could not carry out check.
	WARN State = "WARN"
	// INFO informational message
	INFO State = "INFO"
)

type LogEvent struct {
	Level   string        `json:"level"`
	Time    time.Time     `json:"time"`
	Message string        `json:"message"`
	Fields  logrus.Fields `json:"fields"`
}

type Node struct {
	NodeName   string    `json:"node_name"`
	ResourceID uuid.UUID `json:"resource_id"`
}

type CustomReport struct {
	OverallControls
	Node
}

type OverallControls struct {
	Controls []*Controls `json:"Controls"`
}

type Controls struct {
	Groups []*Group `json:"tests"`
}

// Group is a collection of similar checks.
type Group struct {
	Checks []*Check `json:"results"`
}

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID       string   `yaml:"id" json:"test_number"`
	Text     string   `json:"test_desc"`
	TestInfo []string `json:"test_info"`
	State    `json:"status"`
}

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
