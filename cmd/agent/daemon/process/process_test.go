package process

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestFindContainerID(t *testing.T) {
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})
	client := NewClient(log, "./testdata")

	tests := []struct {
		procID              int
		expectedContainerID string
		expectedError       error
	}{
		{procID: 1, expectedContainerID: "3010305da5e9ea6603f01878e99baf14c0a9af276b7b2002ae19e58027e74ab7", expectedError: nil},
		{procID: 2, expectedContainerID: "2c912ceba34be6ea2d15f93f69603542211aaaa6b7a4220e0c8f7cd9aa3b574b", expectedError: nil},
		{procID: 3, expectedContainerID: "d3867876cf98ca70deef61cbec048701ca5a016968582b932fdb2bbf016d3a36", expectedError: nil},
		{procID: 4, expectedError: ErrContainerNotFound},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("proc_%d", test.procID), func(t *testing.T) {
			r := require.New(t)

			containerID, err := client.GetContainerID(test.procID)
			if test.expectedError != nil {
				r.ErrorIs(err, test.expectedError)
			} else {
				r.NoError(err)
				r.Equal(test.expectedContainerID, containerID)
			}
		})
	}
}
