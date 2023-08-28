### Running locally

To run agent locally you only need to have correct kubernetes contex and KUBECONFIG variable pointing to kubeconfig.
```
go run ./cmd/agent
```

### Creating image pull secrets

To create secrets for specifying in kvisor config's `pullSecret` attribute there are two options:
- From credential file:
```shell
kubectl -n [namespace] create secret docker-registry [secret-name] \
  --from-file=.dockerconfigjson=/absolute/path/to/.docker/config.json
```
- From credential helper:
```shell
kubectl -n [namespace] create secret docker-registry [secret-name] \
  --docker-server=[registry-server] \
  --docker-username=[registry-username] \
  --docker-password=[registry-password]
```
Read [more](https://docs.docker.com/engine/reference/commandline/login/#credential-helper-protocol).

### Running locally on tilt

Start tilt on local kind cluster with mockapi backend which is located in ./tools/mockapi.
```
API_URL=http://mockapi IMAGE_SCAN_ENABLED=true tilt up
```

### Run E2E tests locally

You can run tests on your local kind cluster.

```
KIND_CONTEXT=tilt IMAGE_TAG=local ./e2e/run.sh
```

### Build and run on k8s cluster

Build and push docker image to github registry.
```
IMAGE_TAG=test1 make push-github-docker
```

Install agent from helm chart
```
IMAGE_TAG=test1 CLUSTER_ID=<my-cluster-id> API_KEY=<my-api-token> API_URL=<my-api-url> ./hack/install_agent.sh
```

### Custom image and profiling

Test docker images are pushed to ghcr.io/castai/kvisor/kvisor on each pull request.

```yaml
helm upgrade castai-kvisor castai-helm/castai-kvisor -n castai-agent --reuse-values \
--set image.repository=ghcr.io/castai/kvisor/kvisor \
--set image.tag=153bacb3b8bdb19831a0b46d6f7762155e5a7612 \
--set-string structuredConfig.imageScan.image.name=ghcr.io/castai/kvisor/kvisor-imgcollector:153bacb3b8bdb19831a0b46d6f7762155e5a7612 \
--set structuredConfig.imageScan.profileEnabled=true \
--set structuredConfig.imageScan.phlareEnabled=true
```
