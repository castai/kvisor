package gpu

import (
	"time"

	dto "github.com/prometheus/client_model/go"
)

type MetricName = string

const (
	MetricStreamingMultiProcessorActive       = MetricName("DCGM_FI_PROF_SM_ACTIVE")
	MetricStreamingMultiProcessorOccupancy    = MetricName("DCGM_FI_PROF_SM_OCCUPANCY")
	MetricStreamingMultiProcessorTensorActive = MetricName("DCGM_FI_PROF_PIPE_TENSOR_ACTIVE")
	MetricDRAMActive                          = MetricName("DCGM_FI_PROF_DRAM_ACTIVE")
	MetricPCIeTXBytes                         = MetricName("DCGM_FI_PROF_PCIE_TX_BYTES")
	MetricPCIeRXBytes                         = MetricName("DCGM_FI_PROF_PCIE_RX_BYTES")
	MetricNVLinkTXBytes                       = MetricName("DCGM_FI_PROF_NVLINK_TX_BYTES")
	MetricNVLinkRXBytes                       = MetricName("DCGM_FI_PROF_NVLINK_RX_BYTES")
	MetricGraphicsEngineActive                = MetricName("DCGM_FI_PROF_GR_ENGINE_ACTIVE")
	MetricFrameBufferTotal                    = MetricName("DCGM_FI_DEV_FB_TOTAL")
	MetricFrameBufferFree                     = MetricName("DCGM_FI_DEV_FB_FREE")
	MetricFrameBufferUsed                     = MetricName("DCGM_FI_DEV_FB_USED")
	MetricPCIeLinkGen                         = MetricName("DCGM_FI_DEV_PCIE_LINK_GEN")
	MetricPCIeLinkWidth                       = MetricName("DCGM_FI_DEV_PCIE_LINK_WIDTH")
	MetricGPUTemperature                      = MetricName("DCGM_FI_DEV_GPU_TEMP")
	MetricMemoryTemperature                   = MetricName("DCGM_FI_DEV_MEMORY_TEMP")
	MetricPowerUsage                          = MetricName("DCGM_FI_DEV_POWER_USAGE")
	MetricGPUUtilization                      = MetricName("DCGM_FI_DEV_GPU_UTIL")
	MetricIntPipeActive                       = MetricName("DCGM_FI_PROF_PIPE_INT_ACTIVE")
	MetricFloat16PipeActive                   = MetricName("DCGM_FI_PROF_PIPE_FP16_ACTIVE")
	MetricFloat32PipeActive                   = MetricName("DCGM_FI_PROF_PIPE_FP32_ACTIVE")
	MetricFloat64PipeActive                   = MetricName("DCGM_FI_PROF_PIPE_FP64_ACTIVE")
	MetricClocksEventReasons                  = MetricName("DCGM_FI_DEV_CLOCKS_EVENT_REASONS")
	MetricXIDErrors                           = MetricName("DCGM_FI_DEV_XID_ERRORS")
	MetricPowerViolation                      = MetricName("DCGM_FI_DEV_POWER_VIOLATION")
	MetricThermalViolation                    = MetricName("DCGM_FI_DEV_THERMAL_VIOLATION")
)

var EnabledMetrics = map[MetricName]struct{}{
	MetricStreamingMultiProcessorActive:       {},
	MetricStreamingMultiProcessorOccupancy:    {},
	MetricStreamingMultiProcessorTensorActive: {},
	MetricDRAMActive:                          {},
	MetricPCIeTXBytes:                         {},
	MetricPCIeRXBytes:                         {},
	MetricNVLinkTXBytes:                       {},
	MetricNVLinkRXBytes:                       {},
	MetricGraphicsEngineActive:                {},
	MetricFrameBufferTotal:                    {},
	MetricFrameBufferFree:                     {},
	MetricFrameBufferUsed:                     {},
	MetricPCIeLinkGen:                         {},
	MetricPCIeLinkWidth:                       {},
	MetricGPUTemperature:                      {},
	MetricMemoryTemperature:                   {},
	MetricPowerUsage:                          {},
	MetricGPUUtilization:                      {},
	MetricIntPipeActive:                       {},
	MetricFloat16PipeActive:                   {},
	MetricFloat32PipeActive:                   {},
	MetricFloat64PipeActive:                   {},
	MetricClocksEventReasons:                  {},
	MetricXIDErrors:                           {},
	MetricPowerViolation:                      {},
	MetricThermalViolation:                    {},
}

// MetricFamilyMap maps metric name to its family of measurements from a single DCGM exporter.
type MetricFamilyMap map[string]*dto.MetricFamily

// GPUMetric holds all collected metrics for a single GPU device at a point in time.
type GPUMetric struct {
	NodeName      string `avro:"node_name"`
	ModelName     string `avro:"model_name"`
	Device        string `avro:"device"`
	DeviceID      string `avro:"device_id"`
	DeviceUUID    string `avro:"device_uuid"`
	MIGProfile    string `avro:"mig_profile"`
	MIGInstanceID string `avro:"mig_instance_id"`

	Pod          string `avro:"pod"`
	Container    string `avro:"container"`
	Namespace    string `avro:"namespace"`
	WorkloadName string `avro:"workload_name"`
	WorkloadKind string `avro:"workload_kind"`

	SMActive             float64 `avro:"sm_active"`
	SMOccupancy          float64 `avro:"sm_occupancy"`
	TensorActive         float64 `avro:"tensor_active"`
	DRAMActive           float64 `avro:"dram_active"`
	PCIeTXBytes          float64 `avro:"pcie_tx_bytes"`
	PCIeRXBytes          float64 `avro:"pcie_rx_bytes"`
	NVLinkTXBytes        float64 `avro:"nvlink_tx_bytes"`
	NVLinkRXBytes        float64 `avro:"nvlink_rx_bytes"`
	GraphicsEngineActive float64 `avro:"graphics_engine_active"`
	FramebufferTotal     float64 `avro:"framebuffer_total"`
	FramebufferUsed      float64 `avro:"framebuffer_used"`
	FramebufferFree      float64 `avro:"framebuffer_free"`
	PCIeLinkGen          float64 `avro:"pcie_link_gen"`
	PCIeLinkWidth        float64 `avro:"pcie_link_width"`
	Temperature          float64 `avro:"temperature"`
	MemoryTemperature    float64 `avro:"memory_temperature"`
	PowerUsage           float64 `avro:"power_usage"`
	GPUUtilization       float64 `avro:"gpu_utilization"`
	IntPipeActive        float64 `avro:"int_pipe_active"`
	FP16PipeActive       float64 `avro:"fp16_pipe_active"`
	FP32PipeActive       float64 `avro:"fp32_pipe_active"`
	FP64PipeActive       float64 `avro:"fp64_pipe_active"`
	ClocksEventReasons   float64 `avro:"clocks_event_reasons"`
	XIDErrors            float64 `avro:"xid_errors"`
	PowerViolation       float64 `avro:"power_violation"`
	ThermalViolation     float64 `avro:"thermal_violation"`

	Timestamp time.Time `avro:"ts"`
}
