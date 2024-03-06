#!/bin/bash

set -e

helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.type=LoadBalancer \
  --set admissionWebhooks.enabled=false

helm upgrade --install \
  cert-manager cert-manager \
  --repo https://charts.jetstack.io \
  --namespace cert-manager \
  --create-namespace \
  --version v1.12.0 \
  --set prometheus.enabled=false \
  --set webhook.timeoutSeconds=4 \
  --set installCRDs=true

kubectl apply -f ./cert-issuer.yaml