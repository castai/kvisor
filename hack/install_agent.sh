#!/bin/bash

set -e

local_charts_path="../gh-helm-charts/charts/castai-kvisor"

default_api_url="https://api.cast.ai"
api_url="${API_URL:-$default_api_url}"

default_image_repo="ghcr.io/castai/kvisor"
image_repo="${IMAGE_REPO:-$default_image_repo}"

default_image_tag="alpha1"
image_tag="${IMAGE_TAG:-$default_image_tag}"

if [ "$API_KEY" == "" ]; then
  echo "CLUSTER_ID is required"
  exit 1
fi

if [ "$CLUSTER_ID" == "" ]; then
  echo "CLUSTER_ID is required"
  exit 1
fi

helm upgrade --install --create-namespace castai-kvisor $local_charts_path --devel \
	--namespace castai-sec \
	--set castai.apiURL=${api_url} \
	--set castai.apiKey=${API_KEY} \
	--set castai.clusterID=${CLUSTER_ID} \
	--set image.repository=${image_repo} \
	--set image.tag=${image_tag}