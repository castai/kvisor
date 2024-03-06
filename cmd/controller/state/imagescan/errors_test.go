package imagescan

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPrivateImageErr(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedPrivate bool
	}{
		{name: "unauthorized upper case", err: errors.New("can't get image: UNAUTHORIZED image"), expectedPrivate: true},
		{name: "unauthorized pascal case", err: errors.New("can't get image: Unauthorized image"), expectedPrivate: true},
		{name: "manifest_unknown", err: errors.New("can't get image: MANIFEST_UNKNOWN image"), expectedPrivate: true},
		{name: "denied", err: errors.New("can't get image: DENIED image"), expectedPrivate: true},
		{name: "connection refused", err: errors.New("can't get image: connection refused image"), expectedPrivate: true},
		{name: "context canceled", err: errors.New("can't get image: context canceled"), expectedPrivate: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(test.expectedPrivate, isPrivateImageError(test.err))
		})
	}
}

func TestParseErrorFromLog(t *testing.T) {
	t.Run("PrivateImageError", func(t *testing.T) {
		rawErr := errors.New(`time="2023-11-03T12:34:56Z" level=error msg="unauthorized: authentication required" component=image-scan`)
		result := parseErrorFromLog(rawErr)
		if !errors.Is(result, errPrivateImage) {
			t.Errorf("Expected %v, but got %v", errPrivateImage, result)
		}
	})

	t.Run("HostFSError", func(t *testing.T) {
		rawErr := errors.New(`time="2023-11-03T12:34:56Z" level=error msg="no such file or directory" component=image-scan`)
		result := parseErrorFromLog(rawErr)
		if !errors.Is(result, errImageScanLayerNotFound) {
			t.Errorf("Expected %v, but got %v", errImageScanLayerNotFound, result)
		}
	})

	t.Run("LogsWithErrors", func(t *testing.T) {
		expectedErr := errors.New(`An error occurred`)
		rawErr := errors.New(`time="2023-11-03T12:34:56Z" level=error msg="An error occurred" component=image-scan`)
		result := parseErrorFromLog(rawErr)
		require.EqualError(t, expectedErr, result.Error())
	})

	t.Run("LogsWithoutErrors", func(t *testing.T) {
		rawErr := errors.New(`time="2023-11-03T12:34:56Z" level=info msg="No error occurred" component=image-scan`)
		result := parseErrorFromLog(rawErr)
		if !errors.Is(result, rawErr) {
			t.Errorf("Expected the original error, but got %v", result)
		}
	})

	t.Run("LogWithUnknownError", func(t *testing.T) {
		expectedErr := errors.New(`who knows which error`)
		rawErr := errors.New(`scan job failed: time="2023-11-01T10:17:27Z" level=info msg="running image scan job, version=local, commit=undefined" component=imagescan_job
            time="2023-11-01T10:17:27Z" level=info msg="collecting artifacts for image 'test/service:todoapp-3(docker.io/test/service@sha256:a56d1aba98ea532b3031b09d118f420a03a2e3f09eb2d5d6a81d906435e864d2)', mode=remote" component=imagescan_job
            time="2023-11-01T10:17:27Z" level=fatal msg="who knows which error" component=imagescan_job`)
		result := parseErrorFromLog(rawErr)
		require.EqualError(t, expectedErr, result.Error())
	})
}
