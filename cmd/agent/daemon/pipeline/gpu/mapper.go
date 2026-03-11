package gpu

import (
	"context"
	"strings"

	client_model "github.com/prometheus/client_model/go"

	"github.com/castai/kvisor/cmd/agent/daemon/pipeline/gpu/pb"
	"github.com/castai/logging"
)

const (
	nodeNameLabel  = "Hostname"
	modelNameLabel = "modelName"
	deviceLabel    = "device"
	podLabel       = "pod"
	containerLabel = "container"
	namespaceLabel = "namespace"
	gpuIDLabel     = "gpu"
	gpuUUIDLabel   = "UUID"
	gpuMIGProfile  = "GPU_I_PROFILE"
	gpuInstanceID  = "GPU_I_ID"
)

// WorkloadLookup resolves a pod name+namespace to its top-level workload name and kind.
type WorkloadLookup interface {
	FindWorkloadForPod(ctx context.Context, podName, namespace string) (workloadName, workloadKind string, err error)
}

// MetricMapper transforms raw DCGM Prometheus metric families into exportable forms.
type MetricMapper interface {
	Map(metrics []MetricFamilyMap) *pb.MetricsBatch
	MapToAvro(ctx context.Context, metrics []MetricFamilyMap) []GPUMetric
}

type metricMapper struct {
	nodeName       string
	workloadLookup WorkloadLookup
	log            *logging.Logger
}

type gpuMetricKey struct {
	device        string
	pod           string
	namespace     string
	container     string
	deviceID      string
	deviceUUID    string
	MIGProfile    string
	MIGInstanceID string
}

func newMapper(nodeName string, lookup WorkloadLookup, log *logging.Logger) MetricMapper {
	return &metricMapper{
		nodeName:       nodeName,
		workloadLookup: lookup,
		log:            log,
	}
}

func (p metricMapper) Map(metricFamilyMaps []MetricFamilyMap) *pb.MetricsBatch {
	batch := &pb.MetricsBatch{}
	metricsMap := make(map[string]*pb.Metric)

	for _, familyMap := range metricFamilyMaps {
		for name, family := range familyMap {
			if _, found := EnabledMetrics[name]; !found {
				continue
			}

			metric, found := metricsMap[name]
			if !found {
				metric = &pb.Metric{
					Name: name,
				}
				metricsMap[name] = metric
				batch.Metrics = append(batch.Metrics, metric)
			}

			t := family.Type.String()

			for _, m := range family.Metric {
				labels := p.mapLabels(m.Label)
				var newValue float64
				switch t {
				case "COUNTER":
					newValue = m.GetCounter().GetValue()
				case "GAUGE":
					newValue = m.GetGauge().GetValue()
				}

				metric.Measurements = append(metric.Measurements, &pb.Metric_Measurement{
					Value:  newValue,
					Labels: labels,
				})
			}
		}
	}

	return batch
}

func getLabelValue(labels []*client_model.LabelPair, name string) string {
	for _, lp := range labels {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func (p metricMapper) MapToAvro(ctx context.Context, metricFamilyMaps []MetricFamilyMap) []GPUMetric {
	gpuMetrics := make(map[gpuMetricKey]*GPUMetric)

	for _, familyMap := range metricFamilyMaps {
		for name, family := range familyMap {
			if _, found := EnabledMetrics[name]; !found {
				continue
			}

			for _, m := range family.Metric {
				key := gpuMetricKey{
					device:        getLabelValue(m.Label, deviceLabel),
					pod:           getLabelValue(m.Label, podLabel),
					namespace:     getLabelValue(m.Label, namespaceLabel),
					container:     getLabelValue(m.Label, containerLabel),
					deviceID:      getLabelValue(m.Label, gpuIDLabel),
					deviceUUID:    getLabelValue(m.Label, gpuUUIDLabel),
					MIGProfile:    getLabelValue(m.Label, gpuMIGProfile),
					MIGInstanceID: getLabelValue(m.Label, gpuInstanceID),
				}

				gm, exists := gpuMetrics[key]
				if !exists {
					nodeName := getLabelValue(m.Label, nodeNameLabel)
					if p.nodeName != "" {
						nodeName = p.nodeName
					}

					gm = &GPUMetric{
						NodeName:      nodeName,
						ModelName:     getLabelValue(m.Label, modelNameLabel),
						Device:        key.device,
						DeviceID:      key.deviceID,
						DeviceUUID:    key.deviceUUID,
						MIGProfile:    key.MIGProfile,
						MIGInstanceID: key.MIGInstanceID,
						Pod:           key.pod,
						Container:     key.container,
						Namespace:     key.namespace,
					}

					if key.pod != "" {
						wName, wKind, err := p.workloadLookup.FindWorkloadForPod(ctx, key.pod, key.namespace)
						if err != nil {
							p.log.With(
								"pod", key.pod,
								"namespace", key.namespace,
								"error", err.Error(),
							).Error("failed to resolve workload")
						} else {
							gm.WorkloadName = wName
							gm.WorkloadKind = wKind
						}
					}

					gpuMetrics[key] = gm
				}

				var value float64
				switch family.Type.String() {
				case "COUNTER":
					value = m.GetCounter().GetValue()
				case "GAUGE":
					value = m.GetGauge().GetValue()
				}

				switch name {
				case MetricStreamingMultiProcessorActive:
					gm.SMActive = value
				case MetricStreamingMultiProcessorOccupancy:
					gm.SMOccupancy = value
				case MetricStreamingMultiProcessorTensorActive:
					gm.TensorActive = value
				case MetricDRAMActive:
					gm.DRAMActive = value
				case MetricPCIeTXBytes:
					gm.PCIeTXBytes = value
				case MetricPCIeRXBytes:
					gm.PCIeRXBytes = value
				case MetricNVLinkTXBytes:
					gm.NVLinkTXBytes = value
				case MetricNVLinkRXBytes:
					gm.NVLinkRXBytes = value
				case MetricGraphicsEngineActive:
					gm.GraphicsEngineActive = value
				case MetricFrameBufferTotal:
					gm.FramebufferTotal = value
				case MetricFrameBufferFree:
					gm.FramebufferFree = value
				case MetricFrameBufferUsed:
					gm.FramebufferUsed = value
				case MetricPCIeLinkGen:
					gm.PCIeLinkGen = value
				case MetricPCIeLinkWidth:
					gm.PCIeLinkWidth = value
				case MetricGPUTemperature:
					gm.Temperature = value
				case MetricMemoryTemperature:
					gm.MemoryTemperature = value
				case MetricPowerUsage:
					gm.PowerUsage = value
				case MetricGPUUtilization:
					gm.GPUUtilization = value
				case MetricIntPipeActive:
					gm.IntPipeActive = value
				case MetricFloat16PipeActive:
					gm.FP16PipeActive = value
				case MetricFloat32PipeActive:
					gm.FP32PipeActive = value
				case MetricFloat64PipeActive:
					gm.FP64PipeActive = value
				case MetricClocksEventReasons:
					gm.ClocksEventReasons = value
				case MetricXIDErrors:
					gm.XIDErrors = value
				case MetricPowerViolation:
					gm.PowerViolation = value
				case MetricThermalViolation:
					gm.ThermalViolation = value
				}
			}
		}
	}

	metrics := make([]GPUMetric, 0, len(gpuMetrics))
	for _, gm := range gpuMetrics {
		metrics = append(metrics, *gm)
	}

	return metrics
}

func (p metricMapper) mapLabels(labelPairs []*client_model.LabelPair) []*pb.Metric_Label {
	labels := make([]*pb.Metric_Label, len(labelPairs))
	for i, label := range labelPairs {
		value := label.GetValue()
		if p.nodeName != "" && strings.EqualFold(label.GetName(), nodeNameLabel) {
			value = p.nodeName
		}
		labels[i] = &pb.Metric_Label{
			Name:  label.GetName(),
			Value: value,
		}
	}

	return labels
}
