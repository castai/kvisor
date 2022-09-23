package contract

import "time"

type LinterCheck struct {
	ResourceID string    `json:"resourceID"`
	RuleID     string    `json:"ruleID"`
	Failed     bool      `json:"failed"`
	Timestamp  time.Time `json:"timestamp"`
}
