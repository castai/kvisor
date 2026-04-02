package aws

import "github.com/castai/kvisor/pkg/cloudprovider/types"

// AWS EBS volume performance specs for types where the API does not return
// IOPS / throughput because they are implicitly derived from disk size.
// Source: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html
//
// gp2:      3 IOPS/GiB (min 100, burst to 3000 for <1 TiB) — we store 3/GiB.
//           Throughput: 128–250 MiB/s depending on IOPS; 0.25 MiB/s per IOPS (up to 250 MiB/s).
// st1:      40 MiB/s per TiB baseline (0.039 MiB/s per GiB), burst 250 MiB/s per TiB.
// sc1:      12 MiB/s per TiB baseline (0.012 MiB/s per GiB), burst 80 MiB/s per TiB.
// standard: ~1 IOPS/GiB, 40–90 MiB/s (we use midpoint 65 MiB/s flat — no per-GiB spec).
//
// io1, io2, gp3: IOPS and throughput are returned directly by the AWS API.
func init() {
	mib := int64(1024 * 1024)

	types.VolumePerformanceSpecs["gp2"] = types.VolumePerformanceSpec{
		// 3 IOPS per GiB (min 100 effectively, but we don't model the minimum here)
		IOPSNumerator:   3,
		IOPSDenominator: 1,
		// Throughput = IOPS * 0.25 MiB/s (capped at 250 MiB/s by the engine's int32 overflow guard)
		ThroughputIOPSNumerator:   mib / 4,
		ThroughputIOPSDenominator: 1,
	}

	types.VolumePerformanceSpecs["st1"] = types.VolumePerformanceSpec{
		// No IOPS spec for HDD volumes.
		// Baseline throughput: 40 MiB/s per TiB = 40/1024 MiB/s per GiB
		ThroughputNumerator:   40 * mib,
		ThroughputDenominator: 1024,
	}

	types.VolumePerformanceSpecs["sc1"] = types.VolumePerformanceSpec{
		// No IOPS spec for HDD volumes.
		// Baseline throughput: 12 MiB/s per TiB = 12/1024 MiB/s per GiB
		ThroughputNumerator:   12 * mib,
		ThroughputDenominator: 1024,
	}

	types.VolumePerformanceSpecs["standard"] = types.VolumePerformanceSpec{
		// ~1 IOPS per GiB
		IOPSNumerator:   1,
		IOPSDenominator: 1,
		// AWS docs quote 40–90 MiB/s; use 65 MiB/s flat (no per-GiB scaling documented).
		BaselineThroughputBytes: 65 * mib,
	}
}
