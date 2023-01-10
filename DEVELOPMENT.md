### Running locally

To run agent locally you only need to have correct kubernetes contex and KUBECONFIG variable pointing to kubeconfig.
```
go run ./cmd/agent
```

### Running locally on tilt

Start tilt on local kind cluster with mockapi backend which is located in ./tools/mockapi.
```
API_URL=http://mockapi tilt up
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
