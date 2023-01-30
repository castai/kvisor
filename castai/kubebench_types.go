package castai

import "github.com/google/uuid"

type State string

type Node struct {
	NodeName   string    `json:"node_name"`
	ResourceID uuid.UUID `json:"resource_id"`
}

type KubeBenchReport struct {
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
