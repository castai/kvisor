# Usage guide

Normally your would install kvisor via CAST AI platform. Advanced users can configure kvisor to collect various metrics into local Clickhouse instance. This is a nice way to get started quickly and explore the power of eBPF based security observability. 

## Netflows monitoring

Install kvisor with netflows monitoring.

```sh
helm upgrade --install castai-kvisor castai-kvisor --repo https://castai.github.io/helm-charts \
  -n castai-agent --create-namespace \
  --reset-then-reuse-values \
  --set castai.enabled=false \
  --set castai.clusterID=noop \
  --set agent.enabled=true \
  --set agent.extraArgs.netflow-enabled=true \
  --set agent.extraArgs.netflow-export-interval=15s \
  --set clickhouse.enabled=true \
  --set clickhouse.persistentVolume.size=200Gi
```

Once installed netflows will be collected to local Clickhouse cluster.

### Query netflows

1. Open port to Clickhouse running in castai-agent namespace. 
```sh
 kubectl port-forward svc/castai-kvisor-clickhouse 8123:8123 -n castai-kvisor
```

2. Connect to database using your favorite sql client which supports Clickhouse.
```
Host: localhost
Port: 8123
Username: kvisor
Password: kvisor
Schema: kvisor
```

3. Validate data ingestion is working

```sql
select * from kvisor.netflows where ts > now() - interval 5 minute
order by rand()
limit 5;
```

```
+-------------------------+--------+---------------+-----------------------+------------------------------------------+-----------+----+-------------+-------------+---+----------------+----+----------------+--------+----------+--------------------------+-------------+--------+------------------------+-----------------+--------+----------+--------+----------+
|ts                       |protocol|process        |container_name         |pod_name                                  |namespace  |zone|workload_name|workload_kind|pid|addr            |port|dst_addr        |dst_port|dst_domain|dst_pod_name              |dst_namespace|dst_zone|dst_workload_name       |dst_workload_kind|tx_bytes|tx_packets|rx_bytes|rx_packets|
+-------------------------+--------+---------------+-----------------------+------------------------------------------+-----------+----+-------------+-------------+---+----------------+----+----------------+--------+----------+--------------------------+-------------+--------+------------------------+-----------------+--------+----------+--------+----------+
|2025-09-16T12:36:55Z[UTC]|tcp     |kube-controller|kube-controller-manager|kube-controller-manager-tilt-control-plane|kube-system|    |             |             |1  |/127.0.0.1      |0   |/127.0.0.1      |0       |          |                          |             |        |                        |                 |4226    |10        |2404    |12        |
|2025-09-16T12:35:55Z[UTC]|tcp     |kube-controller|kube-controller-manager|kube-controller-manager-tilt-control-plane|kube-system|    |             |             |1  |/172.18.0.2     |0   |/172.18.0.2     |0       |          |                          |             |        |                        |                 |1500    |9         |3906    |12        |
|2025-09-16T12:37Z[UTC]   |tcp     |kube-apiserver |kube-apiserver         |kube-apiserver-tilt-control-plane         |kube-system|    |             |             |1  |/0:0:0:0:0:0:0:1|0   |/0:0:0:0:0:0:0:1|0       |          |                          |             |        |                        |                 |5282    |23        |5282    |23        |
|2025-09-16T12:37:55Z[UTC]|tcp     |kube-scheduler |kube-scheduler         |kube-scheduler-tilt-control-plane         |kube-system|    |             |             |1  |/127.0.0.1      |0   |/127.0.0.1      |0       |          |                          |             |        |                        |                 |25356   |60        |14579   |75        |
|2025-09-16T12:33:05Z[UTC]|tcp     |kubelet        |                       |                                          |           |    |             |             |151|/10.244.0.1     |0   |/10.244.0.26    |0       |          |castai-kvisor-clickhouse-0|kvisor       |        |castai-kvisor-clickhouse|StatefulSet      |1582    |26        |1774    |26        |
+-------------------------+--------+---------------+-----------------------+------------------------------------------+-----------+----+-------------+-------------+---+----------------+----+----------------+--------+----------+--------------------------+-------------+--------+------------------------+-----------------+--------+----------+--------+----------+

```

### Example queries

### Cross namespace traffic
```sql
select namespace, dst_namespace, formatReadableSize(sum(tx_bytes)) tx, formatReadableSize(sum(rx_bytes)) rx from kvisor.netflows
where ts > now() - interval 5 minute
and namespace != '' and dst_namespace != ''
group by namespace, dst_namespace
order by sum(tx_bytes) desc;
```

```
+------------------+-------------+---------+----------+
|namespace         |dst_namespace|tx       |rx        |
+------------------+-------------+---------+----------+
|kvisor            |kvisor       |1.75 MiB |1.47 MiB  |
|kvisor            |default      |21.61 KiB|240.13 KiB|
|kvisor            |kube-system  |4.51 KiB |8.05 KiB  |
|kube-system       |default      |3.78 KiB |6.94 KiB  |
|local-path-storage|default      |3.12 KiB |5.58 KiB  |
+------------------+-------------+---------+----------+
```

### Traffic by resolved dns domain

```sql
select namespace, workload_name, dst_domain, formatReadableSize(sum(tx_bytes)) tx, formatReadableSize(sum(rx_bytes)) rx from kvisor.netflows
where ts > now() - interval 5 minute
and dst_domain!=''
group by namespace, workload_name, dst_domain
order by sum(tx_bytes) desc;
```

```
+---------+-----------------------------------------------+---------------------------------------------------------+----------+----------+
|namespace|workload_name                                  |dst_domain                                               |tx        |rx        |
+---------+-----------------------------------------------+---------------------------------------------------------+----------+----------+
|kvisor   |castai-kvisor-agent                            |castai-kvisor-clickhouse.kvisor.svc.cluster.local        |539.17 KiB|976.79 KiB|
|kvisor   |castai-kvisor-agent                            |castai-kvisor-controller.kvisor.svc.cluster.local        |124.18 KiB|153.31 KiB|
|kvisor   |castai-imgscan-e606f7c4ba9572ebc8bf6bff86d13cd5|castai-kvisor-castai-mock-server.kvisor.svc.cluster.local|38.60 KiB |691.00 B  |
|kvisor   |castai-imgscan-e606f7c4ba9572ebc8bf6bff86d13cd5|castai-kvisor-controller.kvisor.svc.cluster.local        |38.31 KiB |1.08 KiB  |
|kvisor   |castai-imgscan-e606f7c4ba9572ebc8bf6bff86d13cd5|a1663.dscd.akamai.net                                    |37.51 KiB |6.75 MiB  |
|kvisor   |castai-kvisor-controller                       |castai-kvisor-castai-mock-server.kvisor.svc.cluster.local|35.47 KiB |19.36 KiB |
|kvisor   |castai-imgscan-e606f7c4ba9572ebc8bf6bff86d13cd5|raw.githubusercontent.com                                |10.88 KiB |279.14 KiB|
|kvisor   |castai-imgscan-e606f7c4ba9572ebc8bf6bff86d13cd5|quay.io                                                  |4.62 KiB  |15.31 KiB |
|kvisor   |castai-kvisor-clickhouse                       |www.google.com                                           |4.17 KiB  |74.05 KiB |
|kvisor   |castai-kvisor-clickhouse                       |google.com                                               |2.78 KiB  |7.25 KiB  |
|kvisor   |dns-generator                                  |google.com                                               |394.00 B  |989.00 B  |
+---------+-----------------------------------------------+---------------------------------------------------------+----------+----------+
```

### Traffic to internet by destination host and IP address

```sql
select namespace, workload_name, workload_kind, dst_domain, dst_addr, formatReadableSize(sum(tx_bytes)) tx, formatReadableSize(sum(rx_bytes)) rx from kvisor.netflows
where ts > now() - interval 5 minute
and dst_workload_kind='internet'
group by namespace, workload_name, workload_kind, dst_domain, dst_addr
order by sum(tx_bytes) desc;
```

```
+---------+------------------------+-------------+--------------+----------------+--------+---------+
|namespace|workload_name           |workload_kind|dst_domain    |dst_addr        |tx      |rx       |
+---------+------------------------+-------------+--------------+----------------+--------+---------+
|kvisor   |castai-kvisor-clickhouse|StatefulSet  |github.com    |/140.82.121.4   |2.78 KiB|29.28 KiB|
|kvisor   |castai-kvisor-clickhouse|StatefulSet  |www.google.com|/216.58.208.196 |976.00 B|12.23 KiB|
|kvisor   |castai-kvisor-clickhouse|StatefulSet  |google.com    |/142.250.186.206|812.00 B|2.07 KiB |
+---------+------------------------+-------------+--------------+----------------+--------+---------+
```

### Internal cross zone traffic

```sql
select zone, namespace, workload_name, workload_kind, dst_zone, dst_namespace, dst_workload_name, dst_workload_kind, formatReadableSize(sum(tx_bytes)) tx, formatReadableSize(sum(rx_bytes)) rx from kvisor.netflows
where ts > now() - interval 5 minute
and zone!=dst_zone and zone != '' and dst_zone!=''
group by zone, namespace, workload_name, workload_kind, dst_zone, dst_namespace, dst_workload_name, dst_workload_kind
order by sum(tx_bytes) desc;
```

### Traffic to Kubernetes control plane 

```sql
select namespace, workload_name, workload_kind, formatReadableSize(sum(tx_bytes)) tx, formatReadableSize(sum(rx_bytes)) rx from kvisor.netflows
where ts > now() - interval 5 minute
and dst_workload_kind='Service' and dst_workload_name='kubernetes'
group by namespace, workload_name, workload_kind
order by sum(tx_bytes) desc;
```

```
+------------------+------------------------+-------------+--------+---------+
|namespace         |workload_name           |workload_kind|tx      |rx       |
+------------------+------------------------+-------------+--------+---------+
|kvisor            |castai-kvisor-controller|Deployment   |9.79 KiB|30.42 KiB|
|kube-system       |coredns                 |Deployment   |4.12 KiB|7.66 KiB |
|local-path-storage|local-path-provisioner  |Deployment   |2.32 KiB|5.48 KiB |
+------------------+------------------------+-------------+--------+---------+
```

## Uninstall

```sh
helm uninstall castai-kvisor -n castai-agent
```
