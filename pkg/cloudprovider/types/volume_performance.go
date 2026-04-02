package types

// VolumePerformanceSpec describes how to derive IOPS and throughput when the
// cloud API does not return them.
//
// Size-based:    IOPS = BaselineIOPS + sizeGiB * IOPSNumerator/IOPSDenominator
//                Tput = BaselineThroughputBytes + sizeGiB * ThroughputNumerator/ThroughputDenominator
// IOPS-based:    Tput = IOPS * ThroughputIOPSNumerator/ThroughputIOPSDenominator  (e.g. pd-extreme)
type VolumePerformanceSpec struct {
	// BaselineIOPS is the fixed IOPS floor (0 if none).
	BaselineIOPS    int64
	IOPSNumerator   int64 // additional IOPS per GiB = Numerator/Denominator
	IOPSDenominator int64

	// BaselineThroughputBytes is the fixed throughput floor in bytes/s (0 if none).
	BaselineThroughputBytes int64
	ThroughputNumerator     int64 // additional bytes/s per GiB = Numerator/Denominator
	ThroughputDenominator   int64

	// Set when throughput is proportional to IOPS: bytes/s = IOPS * Numerator/Denominator.
	ThroughputIOPSNumerator   int64
	ThroughputIOPSDenominator int64
}

// VolumePerformanceSpecs maps volume type strings to their specs.
// Each cloud provider package populates this at init() time.
var VolumePerformanceSpecs = map[string]VolumePerformanceSpec{}

// FillMissingPerformanceParams fills IOPS/ThroughputBytes when they are zero
// and a spec is registered for v.VolumeType. No-op otherwise.
func (v *Volume) FillMissingPerformanceParams() {
	spec, ok := VolumePerformanceSpecs[v.VolumeType]
	if !ok {
		return
	}

	sizeGiB := v.SizeBytes / (1024 * 1024 * 1024)

	if v.IOPS == 0 && sizeGiB > 0 && spec.IOPSDenominator > 0 {
		v.IOPS = SafeInt64ToInt32(spec.BaselineIOPS + sizeGiB*spec.IOPSNumerator/spec.IOPSDenominator)
	}

	if v.ThroughputBytes == 0 {
		if spec.ThroughputIOPSDenominator > 0 && v.IOPS > 0 {
			v.ThroughputBytes = SafeInt64ToInt32(int64(v.IOPS) * spec.ThroughputIOPSNumerator / spec.ThroughputIOPSDenominator)
		} else {
			perGiB := int64(0)
			if sizeGiB > 0 && spec.ThroughputDenominator > 0 {
				perGiB = sizeGiB * spec.ThroughputNumerator / spec.ThroughputDenominator
			}
			if tput := spec.BaselineThroughputBytes + perGiB; tput > 0 {
				v.ThroughputBytes = SafeInt64ToInt32(tput)
			}
		}
	}
}

// SafeInt64ToInt32 clamps val to math.MaxInt32 before converting.
func SafeInt64ToInt32(val int64) int32 {
	const maxInt32 = 1<<31 - 1
	if val > maxInt32 {
		return maxInt32
	}
	return int32(val) //nolint:gosec
}
