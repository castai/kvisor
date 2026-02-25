package k8s

// Standard Kubernetes topology labels.
const (
	LabelTopologyZone   = "topology.kubernetes.io/zone"
	LabelTopologyRegion = "topology.kubernetes.io/region"
	LabelAWSZoneID      = "topology.k8s.aws/zone-id"
)

func NodeZone(labels map[string]string) string {
	return labels[LabelTopologyZone]
}

func NodeRegion(labels map[string]string) string {
	return labels[LabelTopologyRegion]
}

func NodeZoneID(labels map[string]string) string {
	return labels[LabelAWSZoneID]
}

func NodeZoneOrID(labels map[string]string, useZoneID bool) string {
	if useZoneID {
		return labels[LabelAWSZoneID]
	}
	return labels[LabelTopologyZone]
}
