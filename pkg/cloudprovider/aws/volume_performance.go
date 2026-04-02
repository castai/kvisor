package aws

import "github.com/castai/kvisor/pkg/cloudprovider/types"

// AWS EBS volume performance specs for types where the API does not return
// IOPS / throughput.
// Source: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html
//
// The AWS API returns:
//   - IOPS      for io1, io2, gp3
//   - Throughput for gp3 only
//
// Types handled here (values not in API response):
//
//	io1/io2:  throughput = 0.256 MiB/s per provisioned IOPS (source: https://docs.aws.amazon.com/ebs/latest/userguide/provisioned-iops.html)
//	gp2:      3 IOPS/GiB; throughput = 0.25 MiB/s per IOPS
//	st1:      40 MiB/s per TiB baseline throughput
//	sc1:      12 MiB/s per TiB baseline throughput
//	standard: ~1 IOPS/GiB, ~65 MiB/s flat
func init() {
	mib := int64(1024 * 1024)

	// io1/io2: IOPS returned by API; throughput = IOPS * 0.256 MiB/s = IOPS * 256/1000 MiB/s
	ioSpec := types.VolumePerformanceSpec{
		ThroughputIOPSNumerator:   256 * mib,
		ThroughputIOPSDenominator: 1000,
	}
	types.VolumePerformanceSpecs["io1"] = ioSpec
	types.VolumePerformanceSpecs["io2"] = ioSpec

	types.VolumePerformanceSpecs["gp2"] = types.VolumePerformanceSpec{
		// 3 IOPS per GiB
		IOPSNumerator:   3,
		IOPSDenominator: 1,
		// Throughput = IOPS * 0.25 MiB/s
		ThroughputIOPSNumerator:   mib / 4,
		ThroughputIOPSDenominator: 1,
	}

	types.VolumePerformanceSpecs["st1"] = types.VolumePerformanceSpec{
		// 40 MiB/s per TiB = 40/1024 MiB/s per GiB
		ThroughputNumerator:   40 * mib,
		ThroughputDenominator: 1024,
	}

	types.VolumePerformanceSpecs["sc1"] = types.VolumePerformanceSpec{
		// 12 MiB/s per TiB = 12/1024 MiB/s per GiB
		ThroughputNumerator:   12 * mib,
		ThroughputDenominator: 1024,
	}

	types.VolumePerformanceSpecs["standard"] = types.VolumePerformanceSpec{
		// ~1 IOPS per GiB; ~65 MiB/s flat (AWS docs quote 40–90 MiB/s, no per-GiB formula)
		IOPSNumerator:           1,
		IOPSDenominator:         1,
		BaselineThroughputBytes: 65 * mib,
	}
}
