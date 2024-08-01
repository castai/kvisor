package signature

import "github.com/castai/kvisor/pkg/logging"

type DefaultSignatureConfig struct {
	SOCKS5DetectedSignatureEnabled bool
	SOCKS5DetectedSignatureConfig  SOCKS5DetectionSignatureConfig
}

func DefaultSignatures(log *logging.Logger, cfg SignatureEngineConfig) ([]Signature, error) {
	var result []Signature
	if cfg.DefaultSignatureConfig.SOCKS5DetectedSignatureEnabled {
		if s, err := NewSOCKS5DetectedSignature(log, cfg.DefaultSignatureConfig.SOCKS5DetectedSignatureConfig); err != nil {
			return nil, err
		} else {
			result = append(result, s)
		}
	}

	return result, nil
}
