package enrichment

import (
	"context"
	"regexp"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
)

var sensitiveValuePattern = regexp.MustCompile(`(?i).*(password|passwd|pass|pwd|secret|token|key|creds|credential)(=?)`)

type SensitiveValueRedactor struct {
	log *logging.Logger

	redactSensitiveValuesRegex *regexp.Regexp
}

// NewSensitiveValueRedactor creates a new SensitiveValueRedactor.
func NewSensitiveValueRedactor(log *logging.Logger, redactSensitiveValuesRegex *regexp.Regexp) *SensitiveValueRedactor {
	return &SensitiveValueRedactor{
		log:                        log,
		redactSensitiveValuesRegex: redactSensitiveValuesRegex,
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
func (r *SensitiveValueRedactor) redactArgs(args []string) {
	if len(args)==0 {
		return
	}

	if r.redactSensitiveValuesRegex == nil {
		// if the redactSensitiveValuesRegex is not set, we use the default sensitive value pattern.
		// This uses our custom logic that detects sensitive values based on the key, taking into account
		// whether the sensitive value is in the same arg (e.g. ["password=abc123"]) or the next one (e.g. ["password", "abc123"]).

		var redactArg = false
		for i, arg := range args {
			// we have detected that this arg is a sensitive value, because of the previous arg, e.g.
			// "password abc123" or "--password abc123"
			// so redact it.
			if redactArg {
				args[i] = "<redacted>"
				redactArg = false

				continue
			}

			matches := sensitiveValuePattern.FindStringSubmatch(arg)
			if matches == nil {
				// arg does not contain sensitive value, continue
				continue
			}

			hasEqualSign := matches[len(matches)-1] == "="
			if hasEqualSign {
				// if the arg matches the sensitive value regex AND contains an equal sign that means it looks like this:
				// "password=abc123" or "--password=abc123"
				// so keep the first part of the arg and redact the value.
				args[i] = matches[0] + "<redacted>"
				continue
			}

			// if the arg matches the sensitive value regex but does not contain an equal sign that means that the sensitive value is actually the next args, e.g.
			// "password abc123" or "--password abc123"
			// so keep the current arg as is and redact the next one.
			redactArg = true
		}

		if redactArg {
			r.log.Warn("detected sensitive keyword at the end of the args array, but no value following it to redact")
		}
	} else {
		// if the redactSensitiveValuesRegex value is set, we use the user defined regex to redact sensitive values.
		// This matches the values as-is, and redacts the whole value, without taking into account any keywords.

		for i, arg := range args {
			if r.redactSensitiveValuesRegex.MatchString(arg) {
				args[i] = "<redacted>"
			}
		}
	}
}
