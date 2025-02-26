helm upgrade --install --repo https://grafana.github.io/helm-charts \
  pyroscope pyroscope \
  --create-namespace -n metrics \
  --version 1.12.0 \
  -f ./tools/localenv/pyroscope-values.yaml \
  --wait
