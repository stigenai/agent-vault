# Production Kubernetes fleet

This Kustomize base packages two broker replicas, a SPIFFE-authenticated reconciler, workload-specific relay resources, disruption controls, and NetworkPolicies. The top-level package renders both namespaces:

```bash
kustomize build examples/kubernetes > /tmp/agent-vault-production.yaml
```

The accepted relay topology is a separate Deployment and Service for each workload identity. The untrusted agent pod receives neither the SPIRE Workload API socket nor a Kubernetes service-account token.

## Prerequisites

- SPIRE and the `csi.spiffe.io` CSI driver are running.
- A CNI enforces Kubernetes `NetworkPolicy`.
- Central PostgreSQL is reachable from the broker namespace and presents a certificate for the hostname in `database-url`.
- The Agent Vault image tag is mirrored and pinned by digest in your production overlay.

Register these service accounts with your existing SPIRE registration mechanism after replacing `cluster.example` in the TOML files:

- `spiffe://cluster.example/ns/agent-vault/sa/agent-vault`
- `spiffe://cluster.example/ns/agent-vault/sa/agent-vault-reconciler`
- `spiffe://cluster.example/ns/agents/sa/example-agent-relay`

The reconciler ID is the one-time bootstrap owner in `server.toml`. The broker ID can authenticate to OpenBao and other SPIFFE-aware infrastructure. The relay ID must also exist as an Agent Vault actor with the grants needed by its workload.

## Supply secret files

The base deliberately contains no Kubernetes `Secret` and no credential value. Create the referenced Secret out of band or replace it with your secrets-store CSI projection:

```bash
kubectl create namespace agent-vault --dry-run=client -o yaml | kubectl apply -f -
kubectl -n agent-vault create secret generic agent-vault-secrets \
  --from-literal=database-url='postgres://agentvault:REPLACE@postgres.example:5432/agentvault' \
  --from-literal=master-password="$(openssl rand -hex 32)" \
  --from-file=postgres-ca.crt=/path/to/postgres-ca.crt
```

The URL intentionally omits `sslmode`; typed TOML requires `verify-full` and the mounted CA. Size PostgreSQL for at least `replicas × max_open_conns` plus operator, monitoring, migration, and failover headroom.

The example agent trusts only the public Agent Vault interception CA:

```bash
agent-vault ca fetch --output ca.pem
kubectl -n agents create configmap agent-vault-mitm-ca --from-file=ca.pem
```

Do not put the CA private key, database password, provider token, master password, or age identity in a ConfigMap.

## Choose DEK wrappers

The runnable base uses the legacy master-password file so it can be evaluated without cloud-specific values. A production overlay should configure an AWS KMS or OpenBao Transit primary wrapper and may add an age-X25519 recipient as recovery-only fallback:

```toml
[encryption]
primary_wrapper = "aws-production"

[[encryption.wrappers]]
name = "aws-production"
kind = "aws-kms"
[encryption.wrappers.aws_kms]
key_arn = "arn:aws:kms:us-east-1:123456789012:key/REPLACE"
region = "us-east-1"

[[encryption.wrappers]]
name = "offline-recovery"
kind = "age-x25519"
[encryption.wrappers.age]
recipient = "age1REPLACE_WITH_PUBLIC_RECIPIENT"
```

AWS uses the SDK default chain, including EKS Pod Identity or IRSA attached to the broker service account. For OpenBao Transit, select `kind = "openbao-transit"`; the broker authenticates with its rotating X.509-SVID, so no durable OpenBao token is mounted. The age private identity stays offline and is accepted only by the explicit recovery command.

## Network policy values

Label namespaces allowed to call the control API:

```bash
kubectl label namespace platform-operators agent-vault.stigen.ai/control-plane-client=true
```

Relay namespaces require `agent-vault.stigen.ai/relay-clients=true`; the included `agents` Namespace already has it. Broker ingress is default-denied except API traffic from labeled operator namespaces or the reconciler and proxy traffic from labeled relay namespaces. Reconciler ingress and egress are default-denied except DNS and the broker API.

Broker egress remains unrestricted in the portable base because PostgreSQL and secret-provider destinations are installation-specific. Restrict it in an overlay with CNI FQDN policies, explicit provider CIDRs, private endpoints, or cloud security groups. Do not add direct agent-to-broker egress.

## Validate and deploy

```bash
./scripts/verify-kubernetes-fleet.sh
kubectl apply --dry-run=server -f /tmp/agent-vault-production.yaml
kubectl apply -k examples/kubernetes
```

The broker's init container validates resolved TOML and mounted secret files before startup. Startup, readiness, and liveness use separate HTTPS endpoints; provider or PostgreSQL outages remove a pod from service without causing liveness restart loops.

Before production, create an overlay that replaces `ghcr.io/stigenai/agent-vault:v0.39.1` with the exact digest built from this fork and adjusts replicas, resources, provider endpoints, trust domain, PostgreSQL capacity, and namespace selectors.

## Run the fleet failure drill

The repository includes a destructive-to-itself E2E drill that creates and deletes a dedicated three-node Kind cluster. It installs pinned Calico and SPIRE releases, starts PostgreSQL, two broker replicas, a workload-specific relay, an untrusted agent, and a TLS test provider:

```bash
make test-kubernetes-e2e
```

The drill proves exact SPIFFE request attribution, relay-only network reachability, live short-TTL SVID rotation without pod restart, bounded broker-pod disruption, provider last-known-good behavior, max-staleness fail-close, and recovery. It exports only workload metadata and logs, scans them against every ephemeral secret sentinel, emits a secret-free JSON report, and removes the cluster. Set `KEEP_CLUSTER=1` only for local failure diagnosis; the retained cluster contains test-only credentials and must be deleted afterward.
