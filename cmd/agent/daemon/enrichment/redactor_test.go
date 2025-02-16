package enrichment

import (
	"context"
	"regexp"
	"testing"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
)

func TestSensitiveValueRedactor(t *testing.T) {
	ctx := context.Background()

	redactor := NewSensitiveValueRedactor(regexp.MustCompile("abc123"))

	testCases := []struct {
		name         string
		args         []string
		expectedArgs []string
	}{
		{
			name:         "key and value are different args",
			args:         []string{"cmd", "--password", "abc123"},
			expectedArgs: []string{"cmd", "--password", "<redacted>"},
		},
		{
			name:         "key and value are same arg",
			args:         []string{"cmd", "--password=abc123"},
			expectedArgs: []string{"cmd", "--password=<redacted>"},
		},
		{
			name:         "key and value are different args with other args",
			args:         []string{"cmd", "--username", "uuu", "--password", "abc123"},
			expectedArgs: []string{"cmd", "--username", "uuu", "--password", "<redacted>"},
		},
		{
			name:         "key and value are same arg with other args",
			args:         []string{"cmd", "--username", "uuu", "--password=abc123"},
			expectedArgs: []string{"cmd", "--username", "uuu", "--password=<redacted>"},
		},
		{
			name:         "nil args",
			args:         nil,
			expectedArgs: nil,
		},
		{
			name:         "no args",
			args:         []string{},
			expectedArgs: []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req := &EnrichedContainerEvent{
				Event: &castpb.ContainerEvent{
					EventType: castpb.EventType_EVENT_EXEC,
					Data: &castpb.ContainerEvent_Exec{
						Exec: &castpb.Exec{
							Args: testCase.args,
						},
					},
				},
			}

			redactor.Enrich(ctx, req)

			require.Equal(t, testCase.expectedArgs, req.Event.GetExec().GetArgs())
		})
	}
}

func TestSensitiveValueRedactorEventTypes(t *testing.T) {
	redactor := NewSensitiveValueRedactor(nil)

	require.Equal(t, []castpb.EventType{castpb.EventType_EVENT_EXEC}, redactor.EventTypes())
}
