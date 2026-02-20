package components

import (
	"context"

	// Standard OTel collector components.
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/debugexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"

	// Contrib components.
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/clickhouseexporter"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/cumulativetodeltaprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"

	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
)

// Build creates all component factories required by the collector pipeline.
func Build(_ context.Context) (otelcol.Factories, error) {
	receiverList := []receiver.Factory{
		otlpreceiver.NewFactory(),
	}
	receiverMap := make(map[component.Type]receiver.Factory, len(receiverList))
	for _, f := range receiverList {
		receiverMap[f.Type()] = f
	}

	processorList := []processor.Factory{
		batchprocessor.NewFactory(),
		memorylimiterprocessor.NewFactory(),
		filterprocessor.NewFactory(),
		cumulativetodeltaprocessor.NewFactory(),
		transformprocessor.NewFactory(),
	}
	processorMap := make(map[component.Type]processor.Factory, len(processorList))
	for _, f := range processorList {
		processorMap[f.Type()] = f
	}

	// TODO: add prometheusexporter.NewFactory() once go.mod replace for
	// prometheus/prometheus is updated past v0.54.0.
	exporterList := []exporter.Factory{
		debugexporter.NewFactory(),
		otlphttpexporter.NewFactory(),
		clickhouseexporter.NewFactory(),
	}
	exporterMap := make(map[component.Type]exporter.Factory, len(exporterList))
	for _, f := range exporterList {
		exporterMap[f.Type()] = f
	}

	extensionList := []extension.Factory{
		healthcheckextension.NewFactory(),
	}
	extensionMap := make(map[component.Type]extension.Factory, len(extensionList))
	for _, f := range extensionList {
		extensionMap[f.Type()] = f
	}

	return otelcol.Factories{
		Receivers:  receiverMap,
		Processors: processorMap,
		Exporters:  exporterMap,
		Extensions: extensionMap,
		Connectors: map[component.Type]connector.Factory{},
		Telemetry:  otelconftelemetry.NewFactory(),
	}, nil
}
