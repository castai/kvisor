package imagescan

import (
	"errors"
	"regexp"
	"strings"
)

const (
	logrusErrorPattern = `time="(?P<Timestamp>.*?)" level=(?P<Level>.*?) msg="(?P<Message>.*?)" component=(?P<Component>.*)`
)

var (
	re = regexp.MustCompile(logrusErrorPattern)

	errImageScanLayerNotFound = errors.New("image layer not found")
	errPrivateImage           = errors.New("private image")
)

type Log struct {
	Timestamp string
	Level     string
	Message   string
	Component string
}

func isPrivateImageError(rawErr error) bool {
	errStr := strings.ToLower(rawErr.Error())

	// Error codes from https://github.com/google/go-containerregistry/blob/190ad0e4d556f199a07951d55124f8a394ebccd9/pkg/v1/remote/transport/error.go#L115
	// Connection refused error can happen for localhost image.
	for _, errPart := range []string{"unauthorized", "manifest_unknown", "denied", "connection refused"} {
		if strings.Contains(errStr, errPart) {
			return true
		}
	}
	return false
}

func isHostFSError(rawErr error) bool {
	return strings.Contains(rawErr.Error(), "no such file or directory") || strings.Contains(rawErr.Error(), "failed to get the layer")
}

func parseErrorFromLog(rawErr error) error {
	if isPrivateImageError(rawErr) {
		return errPrivateImage
	}
	if isHostFSError(rawErr) {
		return errImageScanLayerNotFound
	}
	logs := parseLogrusLog(rawErr.Error())
	var errs []error
	for _, log := range logs {
		if log.Level == "error" || log.Level == "fatal" {
			errs = append(errs, errors.New(log.Message))
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return rawErr
}

func parseLogrusLog(logMessage string) []Log {
	var logs []Log
	lines := strings.Split(logMessage, "\n")
	for _, line := range lines {
		match := re.FindStringSubmatch(line)
		if match != nil {
			result := make(map[string]string)
			for i, name := range re.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}
			logs = append(logs, Log{
				Timestamp: result["Timestamp"],
				Level:     result["Level"],
				Message:   result["Message"],
				Component: result["Component"],
			})
		}
	}
	return logs
}
