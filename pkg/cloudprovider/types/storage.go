package types

type StorageState struct {
	Provider        Type
	Domain          string              // Cloud domain (e.g., googleapis.com, amazonaws.com)
	InstanceVolumes map[string][]Volume // Instance id -> volumes
}

// Volume represents a cloud storage volume with metrics data
type Volume struct {
	VolumeID         string
	VolumeType       string
	VolumeState      string
	SizeBytes        uint64
	IOPS             *uint32
	ThroughputBytes  *uint32
	Encrypted        bool
	AvailabilityZone string
}
