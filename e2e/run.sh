#!/bin/bash

set -e

KIND_CONTEXT="${KIND_CONTEXT:-kind}"

if [ "$IMAGE_TAG" == "" ]
then
  echo "env variable IMAGE_TAG is required"
  exit 1
fi

# Build e2e docker image.
GOOS=linux GOARCH=amd64 go build -o bin/kvisor-e2e ./e2e
docker build . -t kvisor-e2e:local --build-arg image_tag=$IMAGE_TAG -f Dockerfile.e2e

# Load local image into kind.
kind load docker-image kvisor-e2e:local --name $KIND_CONTEXT

# Deploy e2e resources.
kubectl apply -f ./e2e/e2e.yaml -n castai-kvisor-e2e
kubectl wait --for=condition=complete --timeout=120s job/e2e -n castai-kvisor-e2e
