#!/bin/bash

set -e

KIND_CONTEXT="${KIND_CONTEXT:-kind}"
GOARCH="$(go env GOARCH)"

if [ "$IMAGE_TAG" == "" ]
then
  echo "env variable IMAGE_TAG is required"
  exit 1
fi

name=kvisor

# Build e2e docker image.
pushd ./e2e
GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o ../bin/$name-e2e .
popd
docker build . -t $name-e2e:local --build-arg image_tag=$IMAGE_TAG -f Dockerfile.e2e

# Load e2e image into kind.
kind load docker-image $name-e2e:local --name $KIND_CONTEXT

if [ "$IMAGE_TAG" == "local" ]
then
  GOOS=linux CGO_ENABLED=0 make clean-kvisor-agent kvisor-agent
  docker build . -t $name-agent:local -f Dockerfile.agent
  kind load docker-image $name-agent:local --name $KIND_CONTEXT

  GOOS=linux CGO_ENABLED=0 make clean-kvisor-controller kvisor-controller
  docker build . -t $name-controller:local -f Dockerfile.controller
  kind load docker-image $name-controller:local --name $KIND_CONTEXT

  GOOS=linux CGO_ENABLED=0 make clean-kvisor-image-scanner kvisor-image-scanner clean-kvisor-linter kvisor-linter
  docker build . -t $name-scanners:local -f Dockerfile.scanners
  kind load docker-image $name-scanners:local --name $KIND_CONTEXT
fi

ns="$name-e2e"
kubectl delete ns $ns --force || true
kubectl create ns $ns || true
kubectl config set-context --current --namespace=$ns
# Create job pod. It will install kvisor-e2e helm chart inside the k8s.
kubectl apply -f ./e2e/e2e.yaml
# Make sure kvisor agent is running.
for (( i=1; i<=20; i++ ))
do
    if eval kubectl get ds kvisor-e2e-castai-kvisor-agent; then
        break
    fi
    sleep 1
done
# Deploy various k8s resources to generate events.
kubectl apply -f ./e2e/dns-generator.yaml
kubectl apply -f ./e2e/magic-write-generator.yaml
kubectl apply -f ./e2e/oom-generator.yaml
kubectl apply -f ./e2e/socks5-generator.yaml
kubectl apply -f ./e2e/nc-server-client.yaml
kubectl apply -f ./e2e/conn-generator.yaml
kubectl apply -f ./e2e/iperf.yaml

echo "Waiting for job to finish"

i=0
sleep_seconds=5
retry_count=20
while true; do
  if [ "$i" == "$retry_count" ];
  then
    echo "Timeout waiting for job to complete"
    job_result=1
    break
  fi

  if kubectl wait --for=condition=complete --timeout=0s job/e2e 2>/dev/null; then
    job_result=0
    break
  fi

  if kubectl wait --for=condition=failed --timeout=0s job/e2e 2>/dev/null; then
    job_result=1
    break
  fi

  sleep $sleep_seconds
  i=$((i+1))
done

if [[ $job_result -eq 1 ]]; then
    echo "==================================== All pods ===================================="
    kubectl get pods -A
    echo "==================================== Kvisor Controller logs ======================"
    kubectl logs -l app.kubernetes.io/component=controller --tail=-1
    echo "==================================== Kvisor Agent logs ==========================="
    kubectl logs -l app.kubernetes.io/component=agent --tail=-1
    echo "==================================== E2E logs ===================================="
    kubectl logs -l job-name=e2e --tail=-1

    echo "😞 Job failed! Try to run locally and good luck 🤞: KIND_CONTEXT=tilt IMAGE_TAG=local ./e2e/run.sh"
    exit 1
fi
echo "👌 Job succeeded!"
kubectl delete ns $ns --force || true
