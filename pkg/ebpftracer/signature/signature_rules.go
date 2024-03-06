package signature

import "github.com/castai/kvisor/pkg/logging"

func DefaultSignatures(log *logging.Logger) []Signature {
	return []Signature{
		NewStdViaSocketSignature(log),
	}
}
