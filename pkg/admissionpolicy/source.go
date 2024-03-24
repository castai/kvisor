package admissionpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/castai/kvisor/pkg/logging"

	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

// EventSource receives audit events from the Kubernetes API server.
// Different implementations may use different mechanisms to receive events.
type EventSource interface {
	// Start starts the event source.
	Start(ctx context.Context) error
	// Events returns a channel that receives audit events.
	Events() <-chan []ValidationEvent
}

// WebhookSource is an EventSource that receives via a webhook.
type WebhookSource struct {
	srv    *http.Server
	log    *logging.Logger
	events chan []ValidationEvent
}

// NewWebhookSource returns a new WebhookSource.
func NewWebhookSource(log *logging.Logger, laddr string) *WebhookSource {
	src := &WebhookSource{
		events: make(chan []ValidationEvent, 100),
		log:    log,
	}
	src.srv = &http.Server{
		Addr:    laddr,
		Handler: http.HandlerFunc(src.handle),
	}
	return src
}

// Start starts the event source.
func (s *WebhookSource) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.srv.Shutdown(context.Background())
	}()
	s.log.Infof("listening for audit events on %s", s.srv.Addr)
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Events returns a channel that receives audit events.
func (s *WebhookSource) Events() <-chan []ValidationEvent {
	return s.events
}

type eventMetadata struct {
	Message           string   `json:"message"`
	Policy            string   `json:"policy"`
	Bindng            string   `json:"binding"`
	ExpressionIndex   int      `json:"expressionIndex"`
	ValidationActions []string `json:"validationActions"`
}

func (s *WebhookSource) handle(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var evlist auditv1.EventList
	err := json.NewDecoder(r.Body).Decode(&evlist)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// filter down events to only include items related to validating admission
	// and extract relevant details
	var items []ValidationEvent
	for _, ev := range evlist.Items {
		rawmeta, ok := ev.Annotations["validation.policy.admission.k8s.io/validation_failure"]
		if !ok {
			continue
		}
		var mdslc []eventMetadata
		err := json.Unmarshal([]byte(rawmeta), &mdslc)
		if err != nil {
			s.log.Warnf("failed to unmarshal event metadata: %v", err)
			continue
		}
		if len(mdslc) == 0 {
			continue
		}
		md := mdslc[0]
		kind := fmt.Sprintf("%s/%s/%s", ev.ObjectRef.APIGroup, ev.ObjectRef.APIVersion, ev.ObjectRef.Resource)
		items = append(items, ValidationEvent{
			Policy:          md.Policy,
			Binding:         md.Bindng,
			ObjectKind:      kind,
			ObjectName:      ev.ObjectRef.Name,
			ObjectNamespace: ev.ObjectRef.Namespace,
		})
	}
	go func() {
		select {
		case s.events <- items:
		default:
			s.log.Warn("dropping audit event batch due to full channel")
		}
	}()
	fmt.Fprintln(w, "OK")
}
