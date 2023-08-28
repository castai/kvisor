#!/bin/bash
set -e

default_chart_path="../gh-helm-charts/charts/castai-kvisor"
chart_path="${CHART_PATH:-$default_chart_path}"

default_api_url="https://api.cast.ai"
api_url="${API_URL:-$default_api_url}"

default_image_repo="ghcr.io/castai/kvisor/kvisor"
image_repo="${IMAGE_REPO:-$default_image_repo}"

if [ "$API_KEY" == "" ]; then
  echo "API_KEY is required"
  exit 1
fi

if [ "$CLUSTER_ID" == "" ]; then
  echo "CLUSTER_ID is required"
  exit 1
fi

if [ "$SECRET_NAME" == "" ]; then
  echo "SECRET_NAME is required"
  exit 1
fi

if [ "$IMAGE_TAG" == "" ]; then
  echo "IMAGE_TAG is required"
  exit 1
fi

helm upgrade --install --create-namespace castai-kvisor $chart_path --devel \
	--namespace castai-agent \
	--set castai.apiURL=${api_url} \
	--set castai.apiKey=${API_KEY} \
	--set castai.clusterID=${CLUSTER_ID} \
	--set 'castai.imagePullSecrets[0].name=castai-kvisor-github' \
	--set image.repository=${image_repo} \
	--set image.tag=${IMAGE_TAG} \
	--set imageScanSecret=${SECRET_NAME}