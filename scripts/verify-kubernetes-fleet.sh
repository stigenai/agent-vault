#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered_dir="$(mktemp -d)"
trap 'rm -rf "$rendered_dir"' EXIT
rendered="$rendered_dir/agent-vault-production.yaml"

for tool in kustomize kubeconform yq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

kustomize build "$repo_root/examples/kubernetes" >"$rendered"
kubeconform -strict -summary -ignore-missing-schemas "$rendered"

if yq eval-all -r 'select(.kind == "Secret") | .metadata.name' "$rendered" | grep -q .; then
  echo "rendered package must not contain inline Kubernetes Secrets" >&2
  exit 1
fi

if grep -Eq 'image: .*:latest([[:space:]]|$)' "$rendered"; then
  echo "rendered package contains a mutable latest image tag" >&2
  exit 1
fi

if grep -q 'hostPath:' "$rendered"; then
  echo "rendered package contains a hostPath; use SPIFFE CSI or scoped volumes" >&2
  exit 1
fi

bad_service_accounts="$(yq eval-all -r '
  select(.kind == "ServiceAccount" and .automountServiceAccountToken != false) |
  (.metadata.namespace + "/" + .metadata.name)
' "$rendered")"
if [[ -n "$bad_service_accounts" ]]; then
  echo "service accounts must disable token automount:" >&2
  echo "$bad_service_accounts" >&2
  exit 1
fi

# yq variables intentionally live inside this single-quoted expression.
# shellcheck disable=SC2016
bad_workloads="$(yq eval-all -r '
  select(.kind == "Deployment" or .kind == "CronJob") |
  (.spec.template.spec // .spec.jobTemplate.spec.template.spec) as $pod |
  (($pod.containers // []) + ($pod.initContainers // [])) as $containers |
  select(
    $pod.serviceAccountName == null or
    $pod.automountServiceAccountToken != false or
    $pod.securityContext.runAsNonRoot != true or
    $pod.securityContext.seccompProfile.type != "RuntimeDefault" or
    ($containers | any_c(
      .securityContext.allowPrivilegeEscalation != false or
      .securityContext.readOnlyRootFilesystem != true or
      ((.securityContext.capabilities.drop // []) | contains(["ALL"]) | not) or
      .resources.requests.cpu == null or
      .resources.requests.memory == null or
      .resources.limits.cpu == null or
      .resources.limits.memory == null
    ))
  ) |
  (.metadata.namespace + "/" + .metadata.name)
' "$rendered")"
if [[ -n "$bad_workloads" ]]; then
  echo "workloads failed restricted security-context or resource validation:" >&2
  echo "$bad_workloads" >&2
  exit 1
fi

for required in \
  'Deployment/agent-vault' \
  'Deployment/example-agent-relay' \
  'CronJob/agent-vault-reconciler' \
  'PodDisruptionBudget/agent-vault' \
  'NetworkPolicy/agent-vault-default-deny-ingress' \
  'NetworkPolicy/example-agent-default-deny'; do
  kind="${required%%/*}"
  name="${required#*/}"
  if ! yq eval-all -e "select(.kind == \"$kind\" and .metadata.name == \"$name\")" "$rendered" >/dev/null; then
    echo "rendered package is missing $required" >&2
    exit 1
  fi
done

if ! yq eval-all -e '
  select(.kind == "Deployment" and .metadata.name == "agent-vault") |
  .spec.replicas >= 2 and
  .spec.strategy.rollingUpdate.maxUnavailable == 0 and
  .spec.strategy.rollingUpdate.maxSurge == 1 and
  .spec.template.spec.volumes[] |
  select(.name == "spire-agent-socket" and .csi.driver == "csi.spiffe.io" and .csi.readOnly == true)
' "$rendered" >/dev/null; then
  echo "broker HA rollout or SPIFFE CSI configuration is invalid" >&2
  exit 1
fi

echo "Kubernetes fleet package verification passed: $rendered"
