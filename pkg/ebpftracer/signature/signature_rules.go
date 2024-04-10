package signature

import "github.com/castai/kvisor/pkg/logging"

type DefaultSignatureConfig struct {
	TTYDetectedSignatureEnabled    bool
	SOCKS5DetectedSignatureEnabled bool
	SOCKS5DetectedSignatureConfig  SOCKS5DetectionSignatureConfig
}

func DefaultSignatures(log *logging.Logger, cfg DefaultSignatureConfig) ([]Signature, error) {
	result := []Signature{
		NewStdViaSocketSignature(log),
	}

	if cfg.TTYDetectedSignatureEnabled {
		result = append(result, NewTTYDetectedSignature())
	}

	if cfg.SOCKS5DetectedSignatureEnabled {
		if s, err := NewSOCKS5DetectedSignature(cfg.SOCKS5DetectedSignatureConfig); err != nil {
			return nil, err
		} else {
			result = append(result, s)
		}
	}

	return result, nil
}
