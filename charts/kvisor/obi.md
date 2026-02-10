Dev-Master Install
Values file created: charts/kvisor/obi-values-dev-master.yaml

The only difference from the test cluster values: no podMonitorLabels. Dev-master's Prometheus uses podMonitorSelector: {} — it scrapes all PodMonitors across all namespaces without label filtering. The test cluster required release: kube-prometheus-stack.

Commands
1. Deploy (requires RBAC permissions — the last upgrade failed on ClusterRole patching):

helm upgrade castai-kvisor charts/kvisor -n castai-agent \
--kube-context dev-master \
--reuse-values \
--history-max 0 \
-f charts/kvisor/obi-values-dev-master.yaml

2. Force DaemonSet rollout (ConfigMap changes don't auto-trigger restarts):

kubectl --context dev-master -n castai-agent rollout restart daemonset castai-kvisor-agent

3. Verify pods come up (38 nodes → 38 pods, each with 3 containers):

kubectl --context dev-master -n castai-agent get pods -l app.kubernetes.io/component=agent -o wide

4. Check OBI is instrumenting processes:

kubectl --context dev-master -n castai-agent logs -l app.kubernetes.io/component=agent -c obi --tail=20

5. Check metrics flowing:

kubectl --context dev-master -n castai-agent logs -l app.kubernetes.io/component=agent -

```shell
helm history castai-kvisor -n castai-agent --kube-context dev-master --max 1
```

```shell
helm upgrade castai-kvisor charts/kvisor \
  -n castai-agent \
  --kube-context dev-master \
  --reuse-values \
  --history-max 0
```

```shell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace \
  --kube-context gke_engineering-test-353509_europe-west3_kvisor-obi-test
```

```shell
helm upgrade castai-kvisor charts/kvisor \
  -n castai-agent \
  --kube-context gke_engineering-test-353509_europe-west3_kvisor-obi-test \
  --reuse-values \
  --history-max 0 \
  -f charts/kvisor/values.yaml \
  --set agent.reliabilityMetrics.enabled=true \
  --set castai.clusterID=e5bb3cab-e0e1-4c5f-8e9d-919741ea5c99

  helm upgrade castai-kvisor charts/kvisor \
  -n castai-agent \
  --kube-context gke_engineering-test-353509_europe-west3_kvisor-obi-test \
  --reuse-values \
  --history-max 0 \
  -f charts/kvisor/obi-values.yaml

```

```shell
helm rollback castai-kvisor 78 \
  -n castai-agent \
  --kube-context dev-master
```

```shell
kube-prometheus-stack has been installed. Check its status by running:
  kubectl --namespace monitoring get pods -l "release=kube-prometheus-stack"

Get Grafana 'admin' user password by running:

  kubectl --namespace monitoring get secrets kube-prometheus-stack-grafana -o jsonpath="{.data.admin-password}" | base64 -d ; echo
ndlRHgFWknylyInDEHgmj88HIgtDdlm1g44kR3o9
Access Grafana local instance:

  export POD_NAME=$(kubectl --namespace monitoring get pod -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=kube-prometheus-stack" -oname)
  kubectl --namespace monitoring port-forward $POD_NAME 3000

Get your grafana admin user password by running:

  kubectl get secret --namespace monitoring -l app.kubernetes.io/component=admin-secret -o jsonpath="{.items[0].data.admin-password}" | base64 --decode ; echo
```
