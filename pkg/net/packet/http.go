package packet

import (
	"bytes"
	"errors"
	"strconv"
)

// HTTPMessageType identifies the type of HTTP message
type HTTPMessageType uint8

const (
	HTTPMessageUnknown HTTPMessageType = iota
	HTTPMessageRequest
	HTTPMessageResponse
)

var httpMessageTypeNames = map[HTTPMessageType]string{
	HTTPMessageUnknown:  "Unknown",
	HTTPMessageRequest:  "Request",
	HTTPMessageResponse: "Response",
}

func (m HTTPMessageType) String() string {
	if name, found := httpMessageTypeNames[m]; found {
		return name
	}
	return "Unknown"
}

// HTTPMessage represents a parsed HTTP message (request or response)
type HTTPMessage interface {
	internal()
	MessageType() HTTPMessageType
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method   string
	Path     string
	Protocol string
	Host     string
}

func (HTTPRequest) internal() {}
func (HTTPRequest) MessageType() HTTPMessageType {
	return HTTPMessageRequest
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	Protocol   string
	StatusCode int
	Status     string
}

func (HTTPResponse) internal() {}
func (HTTPResponse) MessageType() HTTPMessageType {
	return HTTPMessageResponse
}

var (
	ErrHTTPInvalidMessage  = errors.New("invalid HTTP message")
	ErrHTTPTooShort        = errors.New("HTTP payload too short")
	ErrHTTPInvalidMethod   = errors.New("invalid HTTP method")
	ErrHTTPInvalidResponse = errors.New("invalid HTTP response")
)

// Known HTTP methods
var httpMethods = [][]byte{
	[]byte("GET"),
	[]byte("POST"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("PATCH"),
	[]byte("HEAD"),
	[]byte("OPTIONS"),
	[]byte("CONNECT"),
	[]byte("TRACE"),
}

// ParseHTTP tries to parse the given data as an HTTP/1.x message
func ParseHTTP(data []byte) (HTTPMessage, error) {
	if len(data) < 10 {
		return nil, ErrHTTPTooShort
	}

	// Check if this is an HTTP response
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		return parseHTTPResponse(data)
	}

	// Check if this is an HTTP request
	return parseHTTPRequest(data)
}

func parseHTTPRequest(data []byte) (*HTTPRequest, error) {
	// Find the end of the request line
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd == -1 {
		// Try just newline (non-standard but sometimes seen)
		lineEnd = bytes.Index(data, []byte("\n"))
		if lineEnd == -1 {
			// No line ending found, use the whole data
			lineEnd = len(data)
		}
	}

	requestLine := data[:lineEnd]

	// Parse: METHOD PATH PROTOCOL
	// e.g., "GET /api/users HTTP/1.1"
	parts := bytes.SplitN(requestLine, []byte(" "), 3)
	if len(parts) < 2 {
		return nil, ErrHTTPInvalidMessage
	}

	method := string(parts[0])
	path := string(parts[1])
	protocol := ""
	if len(parts) >= 3 {
		protocol = string(parts[2])
	}

	// Validate the method
	validMethod := false
	for _, m := range httpMethods {
		if bytes.Equal(parts[0], m) {
			validMethod = true
			break
		}
	}
	if !validMethod {
		return nil, ErrHTTPInvalidMethod
	}

	// Try to extract Host header
	host := ""
	hostPrefix := []byte("\r\nHost: ")
	hostIdx := bytes.Index(data, hostPrefix)
	if hostIdx == -1 {
		// Try case-insensitive search
		hostPrefix = []byte("\r\nhost: ")
		hostIdx = bytes.Index(bytes.ToLower(data), hostPrefix)
	}
	if hostIdx != -1 {
		hostStart := hostIdx + len(hostPrefix)
		hostEnd := bytes.Index(data[hostStart:], []byte("\r\n"))
		if hostEnd == -1 {
			hostEnd = len(data[hostStart:])
		}
		host = string(bytes.TrimSpace(data[hostStart : hostStart+hostEnd]))
	}

	return &HTTPRequest{
		Method:   method,
		Path:     path,
		Protocol: protocol,
		Host:     host,
	}, nil
}

func parseHTTPResponse(data []byte) (*HTTPResponse, error) {
	// Find the end of the status line
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd == -1 {
		lineEnd = bytes.Index(data, []byte("\n"))
		if lineEnd == -1 {
			lineEnd = len(data)
		}
	}

	statusLine := data[:lineEnd]

	// Parse: PROTOCOL STATUS_CODE STATUS_TEXT
	// e.g., "HTTP/1.1 200 OK"
	parts := bytes.SplitN(statusLine, []byte(" "), 3)
	if len(parts) < 2 {
		return nil, ErrHTTPInvalidResponse
	}

	protocol := string(parts[0])
	if !bytes.HasPrefix(parts[0], []byte("HTTP/")) {
		return nil, ErrHTTPInvalidResponse
	}

	statusCode, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return nil, ErrHTTPInvalidResponse
	}

	status := ""
	if len(parts) >= 3 {
		status = string(parts[2])
	}

	return &HTTPResponse{
		Protocol:   protocol,
		StatusCode: statusCode,
		Status:     status,
	}, nil
}

// IsHTTPRequest checks if the data starts with an HTTP request method
func IsHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	for _, m := range httpMethods {
		if len(data) >= len(m)+1 && bytes.HasPrefix(data, m) && data[len(m)] == ' ' {
			return true
		}
	}
	return false
}

// IsHTTPResponse checks if the data starts with an HTTP response
func IsHTTPResponse(data []byte) bool {
	return len(data) >= 5 && bytes.HasPrefix(data, []byte("HTTP/"))
}
