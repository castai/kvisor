## Develop ebpf locally

First setup lima. It uses nix and devbox to manage most of the packages.
```sh
ln -s ~/c/kvisor /tmp/kvisor
limactl start ./tools/lima-ebpf.yaml
limactl shell lima-ebpf
cd /tmp/kvisor
devbox install
```

Now inside vm you can run ebpftracer
```sh
cd /tmp/kvisor/pkg/ebpftracer
go generate ./...
go test -v . -run=TestTracer
```

Trigger ebpf events

```sh
limactl shell lima-ebpf
curl google.com
```

## Run E2E tests locally

You can run tests on your local kind cluster.

```
KIND_CONTEXT=tilt IMAGE_TAG=local ./e2e/run.sh
```

## Colima
Colima is a wrapper around Lima for macos and can be used as docker desktop for mac replacement.

```
colima start  --cpu 2 --memory 4 --disk 100 -t vz --mount-type virtiofs
```

Lima is lower level VM which allows to create customizable templates. This is recommended if you need to work with ebpf code.
### Lima
```
ln -s ~/c/kvisor /tmp/kvisor
limactl start ./tools/lima-ebpf.yaml
```

## TILT local development

### 1. Install docker, you need 6+ kernel with btf support.

### 2. Setup local k8s.

You can use kind or any other local k8s cluster. Kind is recommended.

```
kind create cluster
kubectl cluster-info --context kind-kind
```

### 3. Start tilt
```
tilt up
```

### 4. Port-forward server api
```
kubectl port-forward svc/kvisord-server 6060:80 -n kvisord
```

### 5. Run dashboard UI locally

```
cd ui
npm install
PUBLIC_API_BASE_URL=http://localhost:6060 npm run dev
```


## GKE Cluster

Create cluster
```sh
export GCP_PROJECT="my-project"
export CLUSTER_NAME="my-cluster-name"
gcloud beta container --project $GCP_PROJECT \
  clusters create $CLUSTER_NAME \
  --zone "us-central1-c" \
  --cluster-version "1.25.8-gke.500" \
  --machine-type "e2-small" \
  --disk-type "pd-balanced" \
  --disk-size "100" \
  --num-nodes "2" \ 
  --node-locations "us-central1-c"
```

Connect
```sh
gcloud container clusters get-credentials $CLUSTER_NAME --zone us-central1-c --project $GCP_PROJECT
```

## eBPF

### Mount tracepoint events

Mount tracepoints if they are not mounted yet.
```
mount -t debugfs none /sys/kernel/debug
ls /sys/kernel/debug/tracing/events
```


### Print logs in ebpf

```c
bpf_printk("called");
```

```
cat /sys/kernel/debug/tracing/trace_pipe
```


## Clickhouse

Clickhouse show columns data size
```sql
select column, formatReadableSize(sum(column_bytes_on_disk)) bytes_on_disk, formatReadableSize(sum(column_data_uncompressed_bytes)) uncompressed
from system.parts_columns
where active = 1 and table like '%events%'
group by database,table, column
order by sum(column_bytes_on_disk) desc;
```

Query container resource usage stats:
```sql
select toStartOfMinute(ts) t,
       case when group = 'cpu' then toString(avg(value)) else formatReadableSize(avg(value)) end as val,
       group||'_'||subgroup name from container_stats
where container_name='kvisord' and group!='syscall' and t > now() - interval 5 minute
group by t, group, name
order by t;
```

## Push chart to gcp artifact registry

Create package and push chart
```sh
helm package ./charts/kvisord 
helm push kvisord-0.1.6.tgz oci://us-east4-docker.pkg.dev/kvisor/helm-charts
```

Test chart template
```sh
helm template kvisord oci://us-east4-docker.pkg.dev/kvisor/helm-charts/kvisord --version 0.1.6
```

### Public demo

Install kvisord

```sh
helm upgrade --install kvisord oci://us-east4-docker.pkg.dev/kvisor/helm-charts/kvisord \
    --version 0.7.0 \
    --namespace kvisord --create-namespace \
    --set storage.resources.requests.cpu=2 \
    --set storage.resources.requests.memory=8Gi \
    --set agent.resources.requests.cpu=100m \
    --set agent.resources.requests.memory=128Mi \
    --set server.resources.requests.cpu=2 \
    --set server.resources.requests.memory=4Gi \
    --set server.extraArgs.events-batch-size=1000 \
    --set server.extraArgs.events-batch-queue-size=30000 \
    --set-string server.extraArgs.workload-profiles-enabled=false \
```

Open port-forward to local dashboard

```sh
kubectl port-forward svc/kvisord-server 6060:80 -n kvisord
```

Delete kvisord

```sh
helm uninstall kvisord -n kvisord
```

### Integrate with CASTAI
```
helm upgrade --install castai-kvisor oci://us-east4-docker.pkg.dev/kvisor/helm-charts/castai-kvisor \
    --version 0.12.0 \
    --namespace kvisord --create-namespace \
    --set image.tag=0f07db05bbe55f9aba04952337f7023f3a4553e5 \
    --set castai.clusterID=<CLUSTER-ID> \
    --set castai.apiKey=<API-KEY> \
    --set agent.enabled=true \
    --set controller.extraArgs.image-scan-enabled=true \
    --set controller.extraArgs.kube-bench-enabled=true
```

## Misc

List available trace functions for ftrace. 
```
cat /sys/kernel/debug/tracing/available_filter_functions | grep socket_connect
```
