package castai

import json "github.com/json-iterator/go"

type CloudScanReport struct {
	Checks []CloudScanCheck
}

type CloudScanCheck struct {
	ID      string          `json:"id"`
	Manual  bool            `json:"manual,omitempty"`
	Failed  bool            `json:"failed,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
}
