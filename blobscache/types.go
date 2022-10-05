package blobscache

import json "github.com/json-iterator/go"

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
