helm upgrade --install --repo https://prometheus-community.github.io/helm-charts \
  prometheus prometheus -n metrics --create-namespace \
  --version 27.3.0 \
  --set alertmanager.enabled=false \
  --set kube-state-metrics.enabled=false \
  --set prometheus-pushgateway.enabled=false \
  --set server.global.scrape_interval=5s \
  --set server.global.scrape_timeout=5s \
  --set server.statefulSet.enabled=true \
  --set server.persistentVolume.size=5Gi \
  --set server.retention=1h

