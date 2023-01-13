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
function printJobLogs() {
  echo "Job logs:"
  kubectl logs -l job-name=e2e
}
trap printJobLogs EXIT

kubectl create ns castai-kvisor-e2e || true
kubectl apply -f ./e2e/e2e.yaml -n castai-kvisor-e2e
echo "Waiting for job to finish"

while true; do
  if kubectl wait --for=condition=complete --timeout=0s job/e2e 2>/dev/null; then
    job_result=0
    break
  fi

  if kubectl wait --for=condition=failed --timeout=0s job/e2e 2>/dev/null; then
    job_result=1
    break
  fi

  sleep 3
done

if [[ $job_result -eq 1 ]]; then
    echo "Job failed!"
    exit 1
fi
echo "Job succeeded!"
