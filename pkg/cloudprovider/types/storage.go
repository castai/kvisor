package types

type StorageState struct {
	Provider        Type
	Domain          string              // Cloud domain (e.g., googleapis.com, amazonaws.com)
	InstanceVolumes map[string][]Volume // Instance id -> volumes
}

type AWSDiskAttachment struct {
	InstanceID string
	Device     string
}

type AWSDetails struct {
	Attachments []AWSDiskAttachment
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
	AwsDetails      *AWSDetails
}
