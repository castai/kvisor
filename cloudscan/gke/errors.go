package gke

import (
	"errors"
	"net/http"

	"google.golang.org/api/googleapi"
)

func IsNotFound(err error) bool {
	return isError(err, http.StatusNotFound)
}

func isError(err error, expectedCode int) bool {
	out := &googleapi.Error{}
	if ok := errors.As(err, &out); ok && out.Code == expectedCode {
		return true
	}

	return false
}
