package signature

import "github.com/castai/kvisor/pkg/logging"

type DefaultSignatureConfig struct {
	TTYDetectedSignatureEnabled    bool
	SockViaStdioSignatureEnabled   bool
	SOCKS5DetectedSignatureEnabled bool
	SOCKS5DetectedSignatureConfig  SOCKS5DetectionSignatureConfig
}

func DefaultSignatures(log *logging.Logger, cfg SignatureEngineConfig) ([]Signature, error) {
	var result []Signature

	if cfg.DefaultSignatureConfig.SockViaStdioSignatureEnabled {
		result = append(result, NewStdViaSocketSignature(log))
	}

	if cfg.DefaultSignatureConfig.TTYDetectedSignatureEnabled {
		result = append(result, NewTTYDetectedSignature())
	}

	if cfg.DefaultSignatureConfig.SOCKS5DetectedSignatureEnabled {
		if s, err := NewSOCKS5DetectedSignature(log, cfg.DefaultSignatureConfig.SOCKS5DetectedSignatureConfig); err != nil {
			return nil, err
		} else {
			result = append(result, s)
		}
	}

	return result, nil
}
