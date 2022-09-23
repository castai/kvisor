### Running locally

To run agent locally you only need to have correct kubernetes contex and KUBECONFIG variable pointing to kubeconfig.
```
go run ./cmd/agent
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
