#!/bin/bash

set -e

# Install grafana.
helm upgrade --install --repo https://grafana.github.io/helm-charts \
  kvisord-grafana grafana \
  --create-namespace -n kvisord-trace \
  --version 6.50.7 \
  -f ./tools/localenv/grafana-values.yaml

# Install loki.
helm upgrade --install --repo https://grafana.github.io/helm-charts \
  kvisord-loki loki \
  --create-namespace -n kvisord-trace \
  --version 5.8.2 \
  --set monitoring.serviceMonitor.enabled=false \
  --set monitoring.selfMonitoring.enabled=false \
  --set monitoring.lokiCanary.enabled=false \
  --set loki.commonConfig.replication_factor=1 \
  --set loki.storage.type=filesystem \
  --set loki.auth_enabled=false \
  --set test.enabled=false \
  --set gateway.enabled=true \
  --set singleBinary.replicas=1
helm upgrade --install promtail -n kvisord-trace grafana/promtail

# Install prometheus.
helm upgrade --install --repo https://prometheus-community.github.io/helm-charts \
  kvisord-prometheus prometheus -n kvisord-trace \
  --version 22.5.0 \
  --set alertmanager.enabled=false \
  --set kube-state-metrics.enabled=false \
  --set prometheus-pushgateway.enabled=false \
  --set server.global.scrape_interval=30s \
  --set server.global.scrape_timeout=30s \
  --set server.statefulSet.enabled=true \
  --set server.statefulSet.resources.requests.memory=1Gi \
  --set server.persistentVolume.size=60Gi

# Install pyroscope tracing.
helm upgrade --install --repo https://pyroscope-io.github.io/helm-chart \
  kvisord-pyroscope pyroscope -n kvisord \
  --version 0.2.92

# Install kvisord and kvisord-server.
kubectl create ns kvisord || true
helm template kvisord ./charts/kvisord \
  -n kvisord \
  --set agent.image.tag=next \
  --set agent.image.pullPolicy=Always \
  --set server.image.tag=next \
  --set server.image.pullPolicy=Always \
  --set server.ingress.enabled=false \
  --set eventGenerator.enabled=true \
  --set eventGenerator.image.tag=latest \
  --set eventGenerator.image.pullPolicy=Always \
 | kubectl delete -n kvisord -f -

# Install trivy operator.
#helm upgrade --install --repo https://aquasecurity.github.io/helm-charts trivy-operator trivy-operator \
#  --namespace kvisord \
#  --set="trivy.ignoreUnfixed=true" \
#  --version 0.13.2

# Instal demo eshop services.
helm upgrade --install onlineboutique oci://us-docker.pkg.dev/online-boutique-ci/charts/onlineboutique -n eshop --create-namespace \
  --set adService.resources.requests.cpu=5m \
  --set adService.resources.requests.memory=10Mi \
  --set cartService.resources.requests.cpu=5m \
  --set cartService.resources.requests.memory=10Mi \
  --set cartService.replicas=2 \
  --set checkoutService.resources.requests.cpu=5m \
  --set checkoutService.resources.requests.memory=10Mi \
  --set currencyService.resources.requests.cpu=5m \
  --set currencyService.resources.requests.memory=10Mi \
  --set currencyService.replicas=3 \
  --set emailService.resources.requests.cpu=5m \
  --set emailService.resources.requests.memory=10Mi \
  --set frontend.resources.requests.cpu=5m \
  --set frontend.resources.requests.memory=10Mi \
  --set frontend.replicas=2 \
  --set loadGenerator.resources.requests.cpu=5m \
  --set loadGenerator.resources.requests.memory=10Mi \
  --set paymentService.resources.requests.cpu=5m \
  --set paymentService.resources.requests.memory=10Mi \
  --set productCatalogService.resources.requests.cpu=5m \
  --set productCatalogService.resources.requests.memory=10Mi \
  --set recommendationService.resources.requests.cpu=5m \
  --set recommendationService.resources.requests.memory=10Mi
  #--set cartDatabase.connectionString="redis-storage.tools.svc.cluster.local:6379"

# Install events generator. These events are security related. For now do not install it due to https://github.com/falcosecurity/event-generator/blob/main/events/syscall/change_thread_namespace.go#L21
# breaking network flows. We should detect such events.
#helm upgrade --install event-generator falcosecurity/event-generator \
#  --namespace event-generator \
#  --create-namespace \
#  --set config.actions="" \
#  --set config.sleep="10s"

#helm upgrade --install kvisord oci://us-east4-docker.pkg.dev/kvisor/helm-charts/kvisord \
#  --version 0.4.0 \
#  --namespace kvisord --create-namespace \
#  --set agent.image.tag=next-arm2 \
#  --set server.image.tag=next-arm2
#
#helm template kvisord oci://us-east4-docker.pkg.dev/kvisor/helm-charts/kvisord \
#  --version 0.4.0 \
#  --namespace kvisord --create-namespace \
#  --set agent.debug.ebpf=true \
#  --set agent.image.tag=next-arm2 \
#  --set server.image.tag=next-arm2