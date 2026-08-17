#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cluster_name="agent-vault-relay-policy-${RANDOM}"
calico_version=${CALICO_VERSION:-v3.30.3}

cleanup() {
  if [[ ${KEEP_CLUSTER:-0} == 1 ]]; then
    printf 'kept kind cluster %s\n' "$cluster_name"
    return
  fi
  kind delete cluster --name "$cluster_name"
}
trap cleanup EXIT

kind create cluster --name "$cluster_name" --config=- <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
EOF

context="kind-${cluster_name}"
kubectl --context "$context" apply -f "https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests/calico.yaml"
kubectl --context "$context" -n kube-system rollout status daemonset/calico-node --timeout=5m
kubectl --context "$context" -n kube-system rollout status deployment/calico-kube-controllers --timeout=5m
kubectl --context "$context" wait --for=condition=Ready node --all --timeout=5m

kubectl --context "$context" create namespace agents
kubectl --context "$context" create namespace agent-vault
kubectl --context "$context" -n agents apply -f "$repo_dir/examples/kubernetes/relay/network-policies.yaml"

kubectl --context "$context" apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: example-agent
  namespace: agents
  labels:
    app.kubernetes.io/name: example-agent
    agent-vault.stigen.ai/identity: example-agent
    agent-vault.stigen.ai/role: agent
spec:
  automountServiceAccountToken: false
  containers:
    - name: probe
      image: busybox:1.36.1
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
---
apiVersion: v1
kind: Pod
metadata:
  name: example-agent-relay
  namespace: agents
  labels:
    app.kubernetes.io/name: example-agent-relay
    agent-vault.stigen.ai/identity: example-agent
    agent-vault.stigen.ai/role: relay
spec:
  automountServiceAccountToken: false
  containers:
    - name: probe
      image: busybox:1.36.1
      command: ["sh", "-c", "mkdir -p /tmp/www && echo relay > /tmp/www/index.html && exec httpd -f -p 14322 -h /tmp/www"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
---
apiVersion: v1
kind: Service
metadata:
  name: example-agent-relay
  namespace: agents
spec:
  selector:
    app.kubernetes.io/name: example-agent-relay
    agent-vault.stigen.ai/identity: example-agent
    agent-vault.stigen.ai/role: relay
  ports:
    - {port: 14322, targetPort: 14322}
---
apiVersion: v1
kind: Pod
metadata:
  name: other-agent-relay
  namespace: agents
  labels:
    app.kubernetes.io/name: example-agent-relay
    agent-vault.stigen.ai/identity: other-agent
    agent-vault.stigen.ai/role: relay
spec:
  automountServiceAccountToken: false
  containers:
    - name: probe
      image: busybox:1.36.1
      command: ["sh", "-c", "mkdir -p /tmp/www && echo other > /tmp/www/index.html && exec httpd -f -p 14322 -h /tmp/www"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
---
apiVersion: v1
kind: Service
metadata:
  name: other-agent-relay
  namespace: agents
spec:
  selector:
    app.kubernetes.io/name: example-agent-relay
    agent-vault.stigen.ai/identity: other-agent
    agent-vault.stigen.ai/role: relay
  ports:
    - {port: 14322, targetPort: 14322}
---
apiVersion: v1
kind: Pod
metadata:
  name: agent-vault
  namespace: agent-vault
  labels:
    app.kubernetes.io/name: agent-vault
spec:
  automountServiceAccountToken: false
  containers:
    - name: probe
      image: busybox:1.36.1
      command: ["sh", "-c", "mkdir -p /tmp/www && echo broker > /tmp/www/index.html && exec httpd -f -p 14322 -h /tmp/www"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
---
apiVersion: v1
kind: Service
metadata:
  name: agent-vault
  namespace: agent-vault
spec:
  selector:
    app.kubernetes.io/name: agent-vault
  ports:
    - {port: 14322, targetPort: 14322}
EOF

kubectl --context "$context" wait --for=condition=Ready pod --all -A --timeout=5m

agent_exec=(kubectl --context "$context" -n agents exec example-agent --)
relay_exec=(kubectl --context "$context" -n agents exec example-agent-relay --)

"${agent_exec[@]}" wget -q -T 3 -O /dev/null http://example-agent-relay:14322
"${relay_exec[@]}" wget -q -T 3 -O /dev/null http://agent-vault.agent-vault.svc.cluster.local:14322

if "${agent_exec[@]}" wget -q -T 3 -O /dev/null http://agent-vault.agent-vault.svc.cluster.local:14322; then
  printf 'agent bypassed relay and reached broker directly\n' >&2
  exit 1
fi
if "${agent_exec[@]}" wget -q -T 3 -O /dev/null http://other-agent-relay:14322; then
  printf 'agent reached another workload identity relay\n' >&2
  exit 1
fi
if "${agent_exec[@]}" test -e /run/spire/sockets/agent.sock; then
  printf 'agent pod received the SPIRE Workload API socket\n' >&2
  exit 1
fi
if "${agent_exec[@]}" test -e /var/run/secrets/kubernetes.io/serviceaccount/token; then
  printf 'agent pod received a Kubernetes service-account token\n' >&2
  exit 1
fi

printf 'relay policy verified: own relay allowed; broker bypass, cross-relay access, SPIRE socket, and service-account token denied\n'
