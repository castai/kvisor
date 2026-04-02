package types_test

import (
	"testing"

	// Import CSP packages so their init() functions register the specs.
	_ "github.com/castai/kvisor/pkg/cloudprovider/aws"
	_ "github.com/castai/kvisor/pkg/cloudprovider/gcp"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/stretchr/testify/require"
)

func TestFillMissingPerformanceParams(t *testing.T) {
	gib := int64(1024 * 1024 * 1024)
	mib := int64(1024 * 1024)

	tests := []struct {
		name           string
		input          types.Volume
		wantIOPS       int32
		wantThroughput int32
	}{
		// ── GCP ──────────────────────────────────────────────────────────────────
		{
			name:           "gcp pd-standard: fills IOPS and throughput from size",
			input:          types.Volume{VolumeType: "pd-standard", SizeBytes: 500 * gib},
			wantIOPS:       750,                      // 500 * 3/2
			wantThroughput: int32(500 * 120 * 1024),  // 500 * 120 KiB/s
		},
		{
			name:           "gcp pd-balanced: fills IOPS and throughput from size",
			input:          types.Volume{VolumeType: "pd-balanced", SizeBytes: 100 * gib},
			wantIOPS:       3600,                           // 3000 + 100*6
			wantThroughput: int32((140 + 28) * mib),        // (140 + 0.28*100) MiB/s
		},
		{
			name:           "gcp pd-ssd: fills IOPS and throughput from size",
			input:          types.Volume{VolumeType: "pd-ssd", SizeBytes: 100 * gib},
			wantIOPS:       9000,                           // 6000 + 100*30
			wantThroughput: int32((240 + 48) * mib),        // (240 + 0.48*100) MiB/s
		},
		{
			name:           "gcp pd-extreme: fills throughput from provisioned IOPS",
			input:          types.Volume{VolumeType: "pd-extreme", SizeBytes: 500 * gib, IOPS: 10000},
			wantIOPS:       10000,
			wantThroughput: types.SafeInt64ToInt32(10000 / 4 * mib), // 2500 MiB/s
		},
		{
			name:           "gcp pd-extreme: no throughput when IOPS is zero",
			input:          types.Volume{VolumeType: "pd-extreme", SizeBytes: 500 * gib},
			wantIOPS:       0,
			wantThroughput: 0,
		},
		// ── AWS ──────────────────────────────────────────────────────────────────
		{
			name:           "aws gp2: fills IOPS and throughput from size",
			input:          types.Volume{VolumeType: "gp2", SizeBytes: 100 * gib},
			wantIOPS:       300,                                       // 100 * 3
			wantThroughput: types.SafeInt64ToInt32(300 * (mib / 4)),   // IOPS * 0.25 MiB/s
		},
		{
			name:           "aws st1: fills throughput from size (no IOPS)",
			input:          types.Volume{VolumeType: "st1", SizeBytes: 2 * 1024 * gib}, // 2 TiB
			wantIOPS:       0,
			wantThroughput: int32(80 * mib), // 40 MiB/s per TiB * 2 TiB
		},
		{
			name:           "aws sc1: fills throughput from size (no IOPS)",
			input:          types.Volume{VolumeType: "sc1", SizeBytes: 2 * 1024 * gib}, // 2 TiB
			wantIOPS:       0,
			wantThroughput: int32(24 * mib), // 12 MiB/s per TiB * 2 TiB
		},
		{
			name:           "aws standard: fills IOPS and baseline throughput",
			input:          types.Volume{VolumeType: "standard", SizeBytes: 100 * gib},
			wantIOPS:       100,             // 1 IOPS/GiB
			wantThroughput: int32(65 * mib), // 65 MiB/s baseline
		},
		// ── shared edge cases ────────────────────────────────────────────────────
		{
			name:           "does not overwrite existing IOPS",
			input:          types.Volume{VolumeType: "pd-ssd", SizeBytes: 100 * gib, IOPS: 5000},
			wantIOPS:       5000,
			wantThroughput: int32((240 + 48) * mib),
		},
		{
			name:           "does not overwrite existing throughput",
			input:          types.Volume{VolumeType: "pd-ssd", SizeBytes: 100 * gib, ThroughputBytes: 999},
			wantIOPS:       9000,
			wantThroughput: 999,
		},
		{
			name:           "unknown volume type: no values filled",
			input:          types.Volume{VolumeType: "mystery-disk", SizeBytes: 100 * gib},
			wantIOPS:       0,
			wantThroughput: 0,
		},
		{
			// pd-ssd has a baseline throughput of 240 MiB/s regardless of size;
			// IOPS remains 0 because the size-based formula yields 0 at sizeGiB=0.
			name:           "zero size: baseline throughput still applied, IOPS stays 0",
			input:          types.Volume{VolumeType: "pd-ssd", SizeBytes: 0},
			wantIOPS:       0,
			wantThroughput: int32(240 * mib),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.input
			v.FillMissingPerformanceParams()
			require.Equal(t, tt.wantIOPS, v.IOPS)
			require.Equal(t, tt.wantThroughput, v.ThroughputBytes)
		})
	}
}
