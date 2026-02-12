package types

type StorageState struct {
	Provider        Type
	Domain          string              // Cloud domain (e.g., googleapis.com, amazonaws.com)
	InstanceVolumes map[string][]Volume // Instance id -> volumes
}

type AWSVolumeDetails struct {
	Device string
}

type GCPVolumeDetails struct {
	DeviceName string
}

// Volume represents a cloud storage volume with metrics data
type Volume struct {
	VolumeID        string
	VolumeType      string
	VolumeState     string
	SizeBytes       int64
	IOPS            int32
	ThroughputBytes int32
	Encrypted       bool
	Zone            string
	AwsDetails      *AWSVolumeDetails
	GCPDetails      *GCPVolumeDetails
}
