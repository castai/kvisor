package k8s

// Standard Kubernetes topology labels.
const (
	LabelTopologyZone   = "topology.kubernetes.io/zone"
	LabelTopologyRegion = "topology.kubernetes.io/region"
	LabelAWSZoneID      = "topology.k8s.aws/zone-id"
)

// NodeZone returns the zone from a node's labels map.
// Reading from a nil map is safe in Go and returns "".
func NodeZone(labels map[string]string) string {
	return labels[LabelTopologyZone]
}

// NodeRegion returns the region from a node's labels map.
func NodeRegion(labels map[string]string) string {
	return labels[LabelTopologyRegion]
}

// NodeZoneID returns the AWS zone ID from a node's labels map.
func NodeZoneID(labels map[string]string) string {
	return labels[LabelAWSZoneID]
}

func NodeZoneOrID(labels map[string]string, useZoneID bool) string {
	if useZoneID {
		return labels[LabelAWSZoneID]
	}
	return labels[LabelTopologyZone]
}
