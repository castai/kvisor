package http

import (
	"regexp"
	"strings"
)

// MaxPathTemplates is the maximum number of unique path templates to track
// before grouping remaining paths under /{overflow}
const MaxPathTemplates = 1000

var (
	// UUID pattern: 8-4-4-4-12 hex digits
	uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

	// Numeric ID pattern: segment that is purely numeric
	numericPattern = regexp.MustCompile(`^[0-9]+$`)

	// Long hex hash pattern: 32+ hex characters (MD5, SHA1, SHA256, etc.)
	hexHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
)

// NormalizePath normalizes an HTTP path to reduce cardinality.
// It replaces:
// - UUIDs with {uuid}
// - Numeric IDs with {id}
// - Long hex hashes with {hash}
// - Query strings are removed
func NormalizePath(path string) string {
	// Remove query string
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Remove fragment
	if idx := strings.Index(path, "#"); idx != -1 {
		path = path[:idx]
	}

	// Handle empty path
	if path == "" {
		return "/"
	}

	// Replace UUIDs first (before splitting)
	path = uuidPattern.ReplaceAllString(path, "{uuid}")

	// Split path into segments and normalize each
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}

		// Skip already normalized segments
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			continue
		}

		// Check for numeric ID
		if numericPattern.MatchString(seg) {
			segments[i] = "{id}"
			continue
		}

		// Check for hex hash (32+ chars)
		if hexHashPattern.MatchString(seg) {
			segments[i] = "{hash}"
			continue
		}
	}

	result := strings.Join(segments, "/")

	// Ensure path starts with /
	if !strings.HasPrefix(result, "/") {
		result = "/" + result
	}

	return result
}

// PathTemplateTracker tracks unique path templates and enforces cardinality limits
type PathTemplateTracker struct {
	templates map[string]bool
	maxSize   int
}

// NewPathTemplateTracker creates a new path template tracker
func NewPathTemplateTracker(maxSize int) *PathTemplateTracker {
	if maxSize <= 0 {
		maxSize = MaxPathTemplates
	}
	return &PathTemplateTracker{
		templates: make(map[string]bool),
		maxSize:   maxSize,
	}
}

// Track normalizes the path and returns the template to use.
// If the max number of templates is reached, returns "/{overflow}" for new paths.
func (t *PathTemplateTracker) Track(path string) string {
	normalized := NormalizePath(path)

	// Check if we already know this template
	if t.templates[normalized] {
		return normalized
	}

	// Check if we're at capacity
	if len(t.templates) >= t.maxSize {
		return "/{overflow}"
	}

	// Track the new template
	t.templates[normalized] = true
	return normalized
}

// Reset clears all tracked templates
func (t *PathTemplateTracker) Reset() {
	t.templates = make(map[string]bool)
}

// Count returns the number of tracked templates
func (t *PathTemplateTracker) Count() int {
	return len(t.templates)
}
