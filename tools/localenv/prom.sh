helm upgrade --install --repo https://prometheus-community.github.io/helm-charts \
  prometheus prometheus -n metrics --create-namespace \
  --version 22.5.0 \
  --set alertmanager.enabled=false \
  --set kube-state-metrics.enabled=false \
  --set prometheus-pushgateway.enabled=false \
  --set server.global.scrape_interval=30s \
  --set server.global.scrape_timeout=30s \
  --set server.statefulSet.enabled=true \
  --set server.persistentVolume.size=5Gi
  #--set server.statefulSet.resources.requests.memory=1Gi \
