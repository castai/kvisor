#!/bin/bash

set -e

helm upgrade --install castai-kvisor ./charts/castai-kvisor \
  -n castai-kvisor-e2e --create-namespace \
  -f ./charts/castai-kvisor/ci/test-values.yaml \
  --set image.repository=ghcr.io/castai/kvisor/kvisor,image.tag=${IMAGE_TAG} \
  --wait --timeout=2m
