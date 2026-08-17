# Isolated Kubernetes workload relay

The production reference uses a workload-specific relay pod, not a sidecar. Kubernetes `NetworkPolicy` applies to a pod network namespace and cannot isolate two containers in the same pod. Keeping the agent and relay in separate pods ensures the untrusted agent never mounts the SPIRE Workload API socket and cannot bypass the relay to contact Agent Vault directly.

The relay has one logical agent identity. Register the `example-agent-relay` service account for the exact SPIFFE ID configured on that Agent Vault agent. Do not share a relay deployment between Agent Vault agent records.

Before applying:

1. Replace the images, trust domain, namespace, broker service name, and identity labels.
2. Install the SPIFFE CSI driver and register `agents:example-agent-relay` with SPIRE. Only the relay service account receives that registration.
3. Use a CNI that enforces `NetworkPolicy`. Kind's default `kindnet` does not enforce these policies.
4. Adapt the DNS selector when using NodeLocal DNS or a provider-specific DNS deployment.
5. Create `agent-vault-mitm-ca` from the broker's public interception CA. This ConfigMap contains no private key.

```bash
agent-vault ca fetch --output ca.pem
kubectl -n agents create configmap agent-vault-mitm-ca --from-file=ca.pem
kubectl apply -k examples/kubernetes/relay
```

The agent pod is default-denied and can reach only DNS and its matching relay on TCP 14322. The relay is independently default-denied and can receive traffic only from its matching agent, resolve DNS, and connect to the broker proxy port. If the broker namespace also has default-deny ingress, add a broker-side ingress policy selecting relay pods from namespaces explicitly labeled `agent-vault.stigen.ai/relay-clients=true`.

`listener_mode = "network"` is a deliberate opt-in. The relay rejects a non-loopback listener unless this mode is set. Local CLI and non-Kubernetes deployments continue to default to `loopback`.

Validate rendered resources before rollout:

```bash
kustomize build examples/kubernetes/relay >/tmp/agent-vault-relay.yaml
kubectl apply --dry-run=server -f /tmp/agent-vault-relay.yaml
```

The repository policy test creates a disposable Kind cluster with Calico, applies this exact policy file, and proves: agent-to-relay and relay-to-broker succeed, agent-to-broker and agent-to-other-relay fail, and no SPIRE socket or service-account token is mounted in the agent pod.

```bash
./scripts/verify-relay-network-policy.sh
```
