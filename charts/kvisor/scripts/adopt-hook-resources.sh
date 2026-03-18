#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# adopt-hook-resources.sh — Run BEFORE helm upgrade to migrate hook-created
# ClickHouse resources into regular Helm-managed resources.
#
# This is needed once when upgrading from chart versions that deployed the
# ClickHouseInstallation CR and credentials Secret as Helm hooks.
# After the first successful upgrade, this script is a no-op.
#
# Usage:
#   ./adopt-hook-resources.sh <release-name> <namespace>
#   ./adopt-hook-resources.sh castai-kvisor castai-agent
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RELEASE="${1:?Usage: $0 <release-name> <namespace>}"
NAMESPACE="${2:?Usage: $0 <release-name> <namespace>}"

# Resource names follow the subchart naming convention
SECRET_NAME="${RELEASE}-clickhouse-install-credentials"
CHI_NAME="${RELEASE}-clickhouse"

adopt_resource() {
  local resource="$1"
  if kubectl get "$resource" -n "$NAMESPACE" >/dev/null 2>&1; then
    existing=$(kubectl get "$resource" -n "$NAMESPACE" \
      -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}' 2>/dev/null || true)
    if [ "$existing" = "$RELEASE" ]; then
      echo "  $resource: already Helm-managed, skipping."
      return
    fi
    echo "  $resource: adopting into release $RELEASE..."
    kubectl annotate "$resource" -n "$NAMESPACE" \
      "meta.helm.sh/release-name=$RELEASE" \
      "meta.helm.sh/release-namespace=$NAMESPACE" \
      --overwrite
    kubectl label "$resource" -n "$NAMESPACE" \
      "app.kubernetes.io/managed-by=Helm" \
      --overwrite
    kubectl annotate "$resource" -n "$NAMESPACE" \
      "helm.sh/hook-" \
      "helm.sh/hook-weight-" \
      "helm.sh/resource-policy-" \
      2>/dev/null || true
    echo "  Done."
  else
    echo "  $resource: not found, skipping."
  fi
}

echo "Adopting hook-created resources for release=$RELEASE namespace=$NAMESPACE"
adopt_resource "secret/$SECRET_NAME"
adopt_resource "clickhouseinstallation/$CHI_NAME"
echo "Adoption complete."
