package types

import (
	"testing"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     Type
		wantErr  bool
	}{
		{
			name:     "gcp returns TypeGCP",
			provider: "gcp",
			want:     TypeGCP,
			wantErr:  false,
		},
		{
			name:     "gke returns TypeGCP",
			provider: "gke",
			want:     TypeGCP,
			wantErr:  false,
		},
		{
			name:     "aws returns TypeAWS",
			provider: "aws",
			want:     TypeAWS,
			wantErr:  false,
		},
		{
			name:     "eks returns TypeAWS",
			provider: "eks",
			want:     TypeAWS,
			wantErr:  false,
		},
		{
			name:     "azure returns TypeAzure",
			provider: "azure",
			want:     TypeAzure,
			wantErr:  false,
		},
		{
			name:     "aks returns TypeAzure",
			provider: "aks",
			want:     TypeAzure,
			wantErr:  false,
		},
		{
			name:     "unknown provider returns error",
			provider: "unknown",
			want:     "",
			wantErr:  true,
		},
		{
			name:     "empty string returns error",
			provider: "",
			want:     "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProviderType(tt.provider)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestType_KubernetesType(t *testing.T) {
	tests := []struct {
		name string
		t    Type
		want string
	}{
		{
			name: "TypeGCP returns gke",
			t:    TypeGCP,
			want: "gke",
		},
		{
			name: "TypeAWS returns eks",
			t:    TypeAWS,
			want: "eks",
		},
		{
			name: "TypeAzure returns aks",
			t:    TypeAzure,
			want: "aks",
		},
		{
			name: "unknown type returns empty string",
			t:    Type("unknown"),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.KubernetesType(); got != tt.want {
				t.Errorf("Type.KubernetesType() = %v, want %v", got, tt.want)
			}
		})
	}
}
