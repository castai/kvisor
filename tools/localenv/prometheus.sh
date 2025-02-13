helm upgrade --install --repo https://prometheus-community.github.io/helm-charts \
  prometheus prometheus \
  --create-namespace -n metrics \
  --version 27.3.0 \
  -f ./tools/localenv/prometheus-values.yaml
