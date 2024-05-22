helm upgrade --install --repo https://grafana.github.io/helm-charts \
  grafana grafana \
  --create-namespace -n metrics \
  --version 6.50.7 \
  -f ./tools/localenv/grafana-values.yaml
