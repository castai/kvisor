#!/bin/bash

set -e

# Build kvisor.
#CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisord-server ./cmd/server
docker build -t localhost:5000/kvisord . -f Dockerfile.local
kind load docker-image localhost:5000/kvisord:latest --name kind
kubectl rollout restart ds kvisord

# Build kvisor-server.
CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisord-server ./cmd/server
docker build -t localhost:5000/kvisord-server . -f Dockerfile.server.local
kind load docker-image localhost:5000/kvisord-server:latest --name kind

# Deploy to kind local cluster.
kubectl create ns kvisord || true

helm template kvisord ./charts/kvisord \
  -f ./charts/kvisord/values-local.yaml \
  -n kvisord \
  --set collector.image.tag=latest \
  --set server.image.tag=latest \
  --set server.image.pullPolicy=Always \
 | kubectl apply -n kvisord -f -

kubectl rollout restart deployment kvisord-server
kubectl rollout restart ds kvisord
