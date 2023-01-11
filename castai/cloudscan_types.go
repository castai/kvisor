package castai

import json "github.com/json-iterator/go"

type CloudScanReport struct {
	Checks []CloudScanCheck `json:"checks"`
}

type CloudScanCheck struct {
	ID        string          `json:"id"`
	Automated bool            `json:"automated,omitempty"`
	Passed    bool            `json:"passed,omitempty"`
	Context   json.RawMessage `json:"context,omitempty"`
}
