package gcp

import "github.com/castai/kvisor/pkg/cloudprovider/types"

// GCP persistent disk performance specs.
// Source: https://cloud.google.com/compute/docs/disks/performance
//
// Formula: IOPS = BaselineIOPS + IOPSPerGiB * sizeGiB
//          Throughput (bytes/s) = BaselineThroughputBytes + ThroughputBytesPerGiB * sizeGiB
//
// pd-extreme: IOPS are user-provisioned (returned by API).
//             Throughput = IOPS / 4 MiB/s (1 MiB/s per 4 IOPS).
func init() {
	mib := int64(1024 * 1024)

	types.VolumePerformanceSpecs["pd-standard"] = types.VolumePerformanceSpec{
		// Read: 0.75 IOPS/GiB, Write: 1.5 IOPS/GiB — we store write (higher bound).
		IOPSNumerator:   3,
		IOPSDenominator: 2,
		// 0.12 MiB/s per GiB = 120 KiB/s per GiB
		ThroughputNumerator:   120 * 1024,
		ThroughputDenominator: 1,
	}

	types.VolumePerformanceSpecs["pd-balanced"] = types.VolumePerformanceSpec{
		BaselineIOPS:    3000,
		IOPSNumerator:   6,
		IOPSDenominator: 1,
		// 140 MiB/s baseline + 0.28 MiB/s per GiB
		BaselineThroughputBytes: 140 * mib,
		ThroughputNumerator:     28 * mib,
		ThroughputDenominator:   100,
	}

	types.VolumePerformanceSpecs["pd-ssd"] = types.VolumePerformanceSpec{
		BaselineIOPS:    6000,
		IOPSNumerator:   30,
		IOPSDenominator: 1,
		// 240 MiB/s baseline + 0.48 MiB/s per GiB
		BaselineThroughputBytes: 240 * mib,
		ThroughputNumerator:     48 * mib,
		ThroughputDenominator:   100,
	}

	types.VolumePerformanceSpecs["pd-extreme"] = types.VolumePerformanceSpec{
		// IOPS are provisioned by the user and returned by the API — no size-based formula.
		// Throughput = IOPS * 1 MiB/s / 4 IOPS = IOPS/4 MiB/s.
		ThroughputIOPSNumerator:   mib,
		ThroughputIOPSDenominator: 4,
	}
}
