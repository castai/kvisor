package blobscache

import "encoding/json"

type PubBlobRequest struct {
	Key  string          `json:"key"`
	Blob json.RawMessage `json:"blob"`
}

type GetBlobRequest struct {
	Key string `json:"key"`
}

type GetBlobResponse struct {
	Blob json.RawMessage `json:"blob"`
}
