package enrichment

import (
	"context"
	"regexp"
	"strings"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
)

type SensitiveValueRedactor struct {
	log *logging.Logger

	redactSensitiveValuesRegex *regexp.Regexp
}

// NewSensitiveValueRedactor creates a new SensitiveValueRedactor.
func NewSensitiveValueRedactor(sensitiveValueRegex *regexp.Regexp) *SensitiveValueRedactor {
	return &SensitiveValueRedactor{
		redactSensitiveValuesRegex: sensitiveValueRegex,
	}
}

// Enrich will add additional data to the provided Event.
func (r *SensitiveValueRedactor) Enrich(ctx context.Context, req *EnrichRequest) {
	r.redactArgs(req.Event.GetExec().GetArgs())
}

// EventsTypes returns a slice of event types, this enricher reacts to.
func (r *SensitiveValueRedactor) EventTypes() []castpb.EventType {
	return []castpb.EventType{
		castpb.EventType_EVENT_EXEC,
	}
}

// redactArgs redacts the arguments that we consider sensitive, e.g. password, token, etc.
//
// It transforms this
//
//	["cmd", "--password", "abc123"]
//
// to this:
//
//	["cmd", "--password", "<redacted>"]
//
// provided that the regex matches the sensitive value.
func (r *SensitiveValueRedactor) redactArgs(args []string) {
	if len(args) == 0 {
		return
	}

	for i, arg := range args {
		matches := r.redactSensitiveValuesRegex.FindStringSubmatch(arg)

		if matches == nil {
			continue
		}

		args[i] = strings.Replace(arg, matches[0], "<redacted>", -1)
	}
}
