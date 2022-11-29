package analyzer

import (
	"path/filepath"
)

func Split(input string, separator uint8) (string, string) {
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == separator {
			return input[:i], input[i+1:]
		}
	}

	return input, ""
}

func BinariesPathFilter(input string, _ int) bool {
	dir := filepath.Base(filepath.Dir(filepath.Clean(input)))
	return dir == "bin" || dir == "sbin"
}
