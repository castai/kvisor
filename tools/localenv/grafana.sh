helm upgrade --install --repo https://grafana.github.io/helm-charts \
  grafana grafana \
  --create-namespace -n metrics \
  --version 8.9.0 \
  -f ./tools/localenv/grafana-values.yaml
