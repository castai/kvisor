package gpu

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/cmd/agent/daemon/pipeline/gpu/pb"
	"github.com/castai/logging"
)

func newGauge(value float64) *dto.Gauge {
	return &dto.Gauge{Value: &value}
}

func newLabelPair(name, value string) *dto.LabelPair {
	return &dto.LabelPair{Name: &name, Value: &value}
}

type mockWorkloadLookup struct {
	name string
	kind string
}

func (m *mockWorkloadLookup) FindWorkloadForPod(_ context.Context, _, _ string) (string, string, error) {
	return m.name, m.kind, nil
}

func TestMetricMapper_Map(t *testing.T) {
	log := logging.New()
	mapper := newMapper("", nil, log)

	t.Run("empty input", func(t *testing.T) {
		got := mapper.Map(nil)
		require.Empty(t, got.Metrics)
	})

	t.Run("non-enabled metric is skipped", func(t *testing.T) {
		input := []MetricFamilyMap{
			{
				"not_a_real_metric": {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{Label: []*dto.LabelPair{newLabelPair("k", "v")}, Gauge: newGauge(1)},
					},
				},
			},
		}
		got := mapper.Map(input)
		require.Empty(t, got.Metrics)
	})

	t.Run("enabled metric is included", func(t *testing.T) {
		input := []MetricFamilyMap{
			{
				MetricGraphicsEngineActive: {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{newLabelPair("device", "nvidia0")},
							Gauge: newGauge(0.75),
						},
					},
				},
			},
		}
		got := mapper.Map(input)

		r := require.New(t)
		r.Len(got.Metrics, 1)
		r.Equal(MetricGraphicsEngineActive, got.Metrics[0].Name)
		r.Len(got.Metrics[0].Measurements, 1)
		r.Equal(0.75, got.Metrics[0].Measurements[0].Value)
	})

	t.Run("node name override in labels", func(t *testing.T) {
		m := newMapper("override-node", nil, log)
		input := []MetricFamilyMap{
			{
				MetricGPUTemperature: {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								newLabelPair("Hostname", "original-node"),
								newLabelPair("device", "nvidia0"),
							},
							Gauge: newGauge(55),
						},
					},
				},
			},
		}
		got := m.Map(input)

		r := require.New(t)
		r.Len(got.Metrics, 1)

		var hostnameLabel *pb.Metric_Label
		for _, l := range got.Metrics[0].Measurements[0].Labels {
			if l.Name == "Hostname" {
				hostnameLabel = l
			}
		}
		r.NotNil(hostnameLabel)
		r.Equal("override-node", hostnameLabel.Value)
	})
}

func TestMetricMapper_MapToAvro(t *testing.T) {
	log := logging.New()

	t.Run("maps metric values to correct fields", func(t *testing.T) {
		mapper := newMapper("test-node", &mockWorkloadLookup{}, log)
		input := []MetricFamilyMap{
			{
				MetricGPUTemperature: {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								newLabelPair("device", "nvidia0"),
								newLabelPair("gpu", "0"),
								newLabelPair("UUID", "GPU-abc"),
								newLabelPair("modelName", "Tesla T4"),
								newLabelPair("Hostname", "node-1"),
							},
							Gauge: newGauge(55),
						},
					},
				},
				MetricPowerUsage: {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								newLabelPair("device", "nvidia0"),
								newLabelPair("gpu", "0"),
								newLabelPair("UUID", "GPU-abc"),
								newLabelPair("modelName", "Tesla T4"),
								newLabelPair("Hostname", "node-1"),
							},
							Gauge: newGauge(72.5),
						},
					},
				},
			},
		}

		got := mapper.MapToAvro(context.Background(), input)

		r := require.New(t)
		r.Len(got, 1)
		r.Equal("test-node", got[0].NodeName)
		r.Equal("Tesla T4", got[0].ModelName)
		r.Equal("nvidia0", got[0].Device)
		r.Equal(55.0, got[0].Temperature)
		r.Equal(72.5, got[0].PowerUsage)
	})

	t.Run("resolves workload for pod", func(t *testing.T) {
		lookup := &mockWorkloadLookup{name: "my-deploy", kind: "Deployment"}
		mapper := newMapper("node-1", lookup, log)

		input := []MetricFamilyMap{
			{
				MetricGPUTemperature: {
					Type: dto.MetricType_GAUGE.Enum(),
					Metric: []*dto.Metric{
						{
							Label: []*dto.LabelPair{
								newLabelPair("device", "nvidia0"),
								newLabelPair("pod", "my-pod-abc"),
								newLabelPair("namespace", "default"),
								newLabelPair("container", "main"),
							},
							Gauge: newGauge(40),
						},
					},
				},
			},
		}

		got := mapper.MapToAvro(context.Background(), input)

		r := require.New(t)
		r.Len(got, 1)
		r.Equal("my-deploy", got[0].WorkloadName)
		r.Equal("Deployment", got[0].WorkloadKind)
		r.Equal("my-pod-abc", got[0].Pod)
		r.Equal("default", got[0].Namespace)
	})
}
