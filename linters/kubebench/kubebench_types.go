package kubebench

import "github.com/google/uuid"

// https://github.com/aquasecurity/kube-bench/blob/main/check/controls.go

type NodeType string
type State string

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

type Node struct {
	NodeName   string    `json:"node_name"`
	ResourceID uuid.UUID `json:"resource_id"`
}

type CustomReport struct {
	OverallControls
	Node
}

type OverallControls struct {
	Controls []*Controls
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
