package signature

import "github.com/castai/kvisor/pkg/logging"

type DefaultSignatureConfig struct {
	TTYDetectedSignatureEnabled bool
}

func DefaultSignatures(log *logging.Logger, cfg DefaultSignatureConfig) []Signature {
	result := []Signature{
		NewStdViaSocketSignature(log),
	}

	if cfg.TTYDetectedSignatureEnabled {
		result = append(result, NewTTYDetectedSignature())
	}

	return result
}
