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
go test -v . -exec sudo -run=TestTracer
```

Trigger ebpf events

```sh
limactl shell lima-ebpf
curl google.com
```

## Run E2E tests locally

You can run tests on your local kind cluster.

```sh
KIND_CONTEXT=tilt IMAGE_TAG=local ./e2e/run.sh
```

## Colima
Colima is a wrapper around Lima for macos and can be used as docker desktop for mac replacement.

```sh
colima start  --cpu 2 --memory 4 --disk 100 -t vz --mount-type virtiofs
```

Lima is lower level VM which allows to create customizable templates. This is recommended if you need to work with ebpf code.
### Lima
```sh
ln -s ~/c/kvisor /tmp/kvisor
limactl start ./tools/lima-ebpf.yaml
```

## TILT local development

### 1. Install docker, you need 6+ kernel with btf support.

### 2. Setup local k8s.

You can use kind or any other local k8s cluster. Kind is recommended.

```sh
kind create cluster
kubectl cluster-info --context kind-kind
```

### 3. Start tilt
```sh
tilt up
```

### 4. Port-forward server api
```sh
kubectl port-forward svc/kvisord-server 6060:80 -n kvisord
```

### 5. Run dashboard UI locally

```sh
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
```sh
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

### Downgrade kernel version

```sh
wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
chmod +x ubuntu-mainline-kernel.sh

# search and find your wanted version
ubuntu-mainline-kernel.sh -r | grep 5.10

# install that version kernel
ubuntu-mainline-kernel.sh -i v5.10.5

# get all menuentries
grep 'menuentry \|submenu ' /boot/grub/grub.cfg | cut -f2 -d "'"

# change the grub configuration
vi /etc/default/grub
from: GRUB_DEFAULT=0
to: GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.10.5-051005-generic"

# update grub
update-grub

# reboot
reboot now

# verify
uname -r
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
where container_name='kvisor' and group!='syscall' and t > now() - interval 5 minute
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
```sh
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
```sh
cat /sys/kernel/debug/tracing/available_filter_functions | grep socket_connect
```

## Making new release

1. Go to https://github.com/castai/kvisor/releases
2. Click draw new release (should open https://github.com/castai/kvisor/releases/new)
3. Choose tag. Add new tag. Follow semver. For fixes only bump patch version.
4. Click generate release notes.
5. Publish release.


## Testing netflow

Install kvisor with netflow export to local clickhouse.

```sh
helm repo add castai-helm https://castai.github.io/helm-charts
helm repo update castai-helm

helm upgrade --install castai-kvisor castai-helm/castai-kvisor \
    --namespace castai-agent --create-namespace \
    --set castai.enabled=false \
    --set agent.enabled=true \
    --set agent.extraArgs.netflow-enabled=true \
    --set clickhouse.enabled=true
```

Check pods are running

```sh
kubectl get pods -n castai-agent
```

You should see agent, clickhouse and controller pods

```
NAME                                        READY   STATUS    RESTARTS   AGE
castai-kvisor-agent-djjcq                   1/1     Running   0          67s
castai-kvisor-clickhouse-0                  2/2     Running   0          66s
castai-kvisor-controller-8697bbf8cd-sq6jp   1/1     Running   0          67s
```

### Query flows

Port forward clickhouse connection

```sh
kubectl port-forward -n castai-agent svc/castai-kvisor-clickhouse 8123
```
Connect to clickhouse with your favorite sql client with credentials:
```
Username: kvisor
Password: kvisor
Database: kvisor
```

Example query:

```sql
select toStartOfInterval(ts, INTERVAL 1 HOUR) AS period,
       pod_name,
       namespace,
       workload_name,
       workload_kind,
       zone,
       dst_pod_name,
       dst_namespace,
       dst_domain,
       dst_workload_name,
       dst_workload_kind,
       dst_zone,
       formatReadableSize(sum(tx_bytes)) total_egress,
       formatReadableSize(sum(rx_bytes)) total_ingress
from netflows
group by period,
         pod_name,
         namespace,
         workload_name,
         workload_kind,
         zone,
         dst_pod_name,
         dst_namespace,
         dst_domain,
         dst_workload_name,
         dst_workload_kind,
         dst_zone
order by period;
```

#### Generating connections

Start server
```sh
docker run -it --rm -p 8000:8000 busybox nc -lk -p 8000
```

Send messages

```sh
for i in {1..50}; do echo "hello$i" | nc -q 0 localhost 8000 & done
```

Or send messages from single process
```sh
cd ./pkg/ebpftracer
NC_ADDR=localhost:8000 go test -v -count=1 . -run=TestGenerateConn
```

## Troubleshooting packets

### PWRU
Install pwru
```sh
wget https://github.com/cilium/pwru/releases/download/v1.0.6/pwru-linux-amd64.tar.gz && \
tar -xzvf pwru-linux-amd64.tar.gz && \
mv pwru /usr/bin/ && \
rm pwru-linux-amd64.tar.gz
```

Or with docker
```sh
docker run --privileged --rm -t --pid=host -v /sys/kernel/debug/:/sys/kernel/debug/ cilium/pwru pwru --output-tuple 'host 1.1.1.1'
```

### Tracee

```sh
docker run --name tracee -it --rm   --pid=host --cgroupns=host --privileged   -v /etc/os-release:/etc/os-release-host:ro   -v /var/run:/var/run:ro   aquasec/tracee:latest --events net_packet_tcp
```

## Linux capabilities

Use [inspektor-gadget](https://github.com/inspektor-gadget) CLI tool to get the required linux capabilities for the kvisor agent container:

```sh
KVISOR_AGENT_KUBERNETES_NODE="kvisor-e2e-control-plane" # Replace with the kvisor agent pod name
kubectl debug --profile=sysadmin node/${KVISOR_AGENT_KUBERNETES_NODE} -it --image=ghcr.io/inspektor-gadget/ig -- \
    ig trace capabilities -c kvisor --unique -t 0

RUNTIME.CONTAINERNAME          PID              COMM             SYSCALL            CAP CAPNAME            AUDIT            VERDICT
kvisor                         69801            kvisor-agent     bpf                39  BPF                1                Allow
kvisor                         69801            kvisor-agent     bpf                38  PERFMON            1                Allow
kvisor                         69801            kvisor-agent     openat             19  SYS_PTRACE         1                Allow
kvisor                         69801            kvisor-agent     readlinkat         19  SYS_PTRACE         1                Allow
kvisor                         69801            kvisor-agent     read               19  SYS_PTRACE         1                Allow
kvisor                         69801            kvisor-agent     setns              21  SYS_ADMIN          1                Allow
kvisor                         69801            kvisor-agent     newfstatat         19  SYS_PTRACE         1                Allow
kvisor                         69801            kvisor-agent     bpf                12  NET_ADMIN          1                Allow
kvisor                         69801            kvisor-agent     perf_event_open    38  PERFMON            1                Allow
```

Any `Deny` in the `VERDICT` column should be added to the `containerSecurityContext` of the kvisor agent container in the `charts/kvisor/values.yaml` file to be allowed.
