#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cluster_name="agent-vault-e2e-${RANDOM}"
context="kind-${cluster_name}"
evidence_dir="$(mktemp -d)"
tls_dir="$(mktemp -d)"
report_path="${AGENT_VAULT_KUBERNETES_E2E_REPORT:-$evidence_dir/report.json}"
image="${AGENT_VAULT_E2E_IMAGE:-agent-vault:e2e}"
postgres_image="${POSTGRES_IMAGE:-postgres:18.0-alpine}"
nginx_image="${NGINX_IMAGE:-nginxinc/nginx-unprivileged:1.29.4-alpine}"
curl_image="${CURL_IMAGE:-curlimages/curl:8.17.0}"
spire_chart_version="${SPIRE_CHART_VERSION:-0.30.0}"
spire_crds_chart_version="${SPIRE_CRDS_CHART_VERSION:-0.6.0}"
calico_version="${CALICO_VERSION:-v3.30.3}"
calico_cni_image="docker.io/calico/cni:${calico_version}"
calico_node_image="docker.io/calico/node:${calico_version}"
calico_controllers_image="docker.io/calico/kube-controllers:${calico_version}"
svid_ttl_seconds=20
max_staleness_seconds=25

database_password="e2e-database-password-${RANDOM}"
master_password="e2e-master-password-${RANDOM}"
connect_token="e2e-connect-token-${RANDOM}"
provider_secret="e2e-provider-secret-${RANDOM}"
stage="initialization"

cleanup() {
  local status="$?"
  if (( status != 0 )) && kubectl --context "$context" get namespace agent-vault >/dev/null 2>&1; then
    printf 'E2E failed during stage %q; diagnostics exclude secret values:\n' "$stage" >&2
    kubectl --context "$context" get pods --all-namespaces -o wide >&2 || true
    kubectl --context "$context" get events --all-namespaces \
      --sort-by=.metadata.creationTimestamp --field-selector type=Warning >&2 || true
  fi
  if [[ "${KEEP_CLUSTER:-0}" == "1" ]]; then
    printf 'kept kind cluster %s and evidence %s\n' "$cluster_name" "$evidence_dir"
    return "$status"
  fi
  kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
  # Both paths were created by mktemp above and are never user-controlled.
  rm -rf "$evidence_dir" "$tls_dir"
  return "$status"
}
trap cleanup EXIT

for tool in docker go helm kind kubectl openssl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

wait_for_sql() {
  local query="$1"
  local expected="$2"
  local _ value
  for _ in {1..90}; do
    value="$(sql "$query" 2>/dev/null || true)"
    if [[ "$value" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  printf 'timed out waiting for SQL result %q, last value %q\n' "$expected" "$value" >&2
  return 1
}

sql() {
  local query="$1"
  kubectl --context "$context" -n agent-vault exec deployment/postgres -- \
    env PGPASSWORD="$database_password" \
    psql --username agentvault --dbname agentvault --tuples-only --no-align --command "$query"
}

agent_request() {
  kubectl --context "$context" -n agents exec deployment/example-agent -- \
    curl --fail --silent --show-error --insecure \
      --connect-timeout 3 --max-time 8 \
      --proxy http://example-agent-relay:14322 \
      https://upstream.agent-vault.svc.cluster.local:8443/check >/dev/null
}

wait_for_request() {
  local _
  for _ in {1..60}; do
    if agent_request 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for a successful relay request" >&2
  return 1
}

wait_for_request_failure() {
  local _
  for _ in {1..30}; do
    if ! agent_request 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "relay continued serving after provider cache max-staleness" >&2
  return 1
}

echo "creating disposable Kind cluster $cluster_name"
stage="cluster creation"
kind create cluster --name "$cluster_name" --config=- <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
  - role: worker
  - role: worker
KIND

for calico_image in "$calico_cni_image" "$calico_node_image" "$calico_controllers_image"; do
  docker pull --quiet "$calico_image" >/dev/null
done
kind load docker-image --name "$cluster_name" \
  "$calico_cni_image" "$calico_node_image" "$calico_controllers_image" >/dev/null
kubectl --context "$context" apply --server-side \
  -f "https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests/calico.yaml" >/dev/null
kubectl --context "$context" -n kube-system rollout status daemonset/calico-node --timeout=5m
kubectl --context "$context" -n kube-system rollout status deployment/calico-kube-controllers --timeout=5m
kubectl --context "$context" wait --for=condition=Ready node --all --timeout=5m

echo "installing SPIRE $spire_chart_version with short-lived X.509-SVIDs"
stage="SPIRE installation"
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ \
  --force-update >/dev/null
helm upgrade --install spire-crds spiffe/spire-crds \
  --kube-context "$context" --namespace spire-server --create-namespace \
  --version "$spire_crds_chart_version" --wait --timeout 5m >/dev/null
helm upgrade --install spire spiffe/spire \
  --kube-context "$context" --namespace spire-server \
  --version "$spire_chart_version" \
  --set global.spire.trustDomain=cluster.example \
  --set global.spire.clusterName=agent-vault-e2e \
  --set spiffe-oidc-discovery-provider.enabled=false \
  --set-string "spire-server.controllerManager.identities.clusterSPIFFEIDs.default.ttl=${svid_ttl_seconds}s" \
  --wait --timeout 5m >/dev/null

echo "building and loading Agent Vault image"
stage="image preload"
docker build --quiet --tag "$image" . >/dev/null
docker pull --quiet "$postgres_image" >/dev/null
docker pull --quiet "$nginx_image" >/dev/null
docker pull --quiet "$curl_image" >/dev/null
kind load docker-image --name "$cluster_name" \
  "$image" "$postgres_image" "$nginx_image" "$curl_image" >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=Agent Vault E2E CA' \
  -keyout "$tls_dir/ca.key" -out "$tls_dir/ca.crt" >/dev/null 2>&1

make_leaf() {
  local name="$1"
  local dns_name="$2"
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=${dns_name}" -addext "subjectAltName=DNS:${dns_name}" \
    -keyout "$tls_dir/${name}.key" -out "$tls_dir/${name}.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -sha256 \
    -in "$tls_dir/${name}.csr" -CA "$tls_dir/ca.crt" -CAkey "$tls_dir/ca.key" \
    -CAcreateserial -copy_extensions copy -out "$tls_dir/${name}.crt" >/dev/null 2>&1
}

make_leaf connect connect.agent-vault.svc.cluster.local
make_leaf upstream upstream.agent-vault.svc.cluster.local

printf '{"version":1,"fields":[{"id":"password","label":"password","value":"%s"}]}\n' \
  "$provider_secret" >"$tls_dir/item.json"

cat >"$tls_dir/connect-nginx.conf" <<'NGINX'
pid /tmp/nginx.pid;
events {}
http {
  access_log /dev/stdout combined;
  error_log /dev/stderr warn;
  server {
    listen 8443 ssl;
    ssl_certificate /etc/tls/tls.crt;
    ssl_certificate_key /etc/tls/tls.key;
    location = /v1/vaults/vault/items/item {
      if ($http_authorization = "") { return 401; }
      default_type application/json;
      alias /srv/connect/item.json;
    }
  }
}
NGINX

cat >"$tls_dir/upstream-nginx.conf" <<NGINX
pid /tmp/nginx.pid;
events {}
http {
  access_log /dev/stdout combined;
  error_log /dev/stderr warn;
  map \$http_authorization \$authorized {
    default 0;
    "Bearer ${provider_secret}" 1;
  }
  server {
    listen 8443 ssl;
    ssl_certificate /etc/tls/tls.crt;
    ssl_certificate_key /etc/tls/tls.key;
    location /check {
      if (\$authorized = 0) { return 401; }
      default_type application/json;
      return 200 '{"authenticated":true}';
    }
  }
}
NGINX

kubectl --context "$context" create namespace agent-vault >/dev/null
kubectl --context "$context" create namespace agents >/dev/null

kubectl --context "$context" -n agent-vault create secret generic database \
  --from-literal="POSTGRES_PASSWORD=$database_password" \
  --from-literal="DATABASE_URL=postgres://agentvault:${database_password}@postgres.agent-vault.svc.cluster.local:5432/agentvault?sslmode=disable" \
  --from-literal="MASTER_PASSWORD=$master_password" \
  --from-literal="OP_CONNECT_TOKEN=$connect_token" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n agent-vault create secret generic connect-fixture \
  --from-file=tls.crt="$tls_dir/connect.crt" \
  --from-file=tls.key="$tls_dir/connect.key" \
  --from-file=nginx.conf="$tls_dir/connect-nginx.conf" \
  --from-file=item.json="$tls_dir/item.json" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n agent-vault create secret generic upstream-fixture \
  --from-file=tls.crt="$tls_dir/upstream.crt" \
  --from-file=tls.key="$tls_dir/upstream.key" \
  --from-file=nginx.conf="$tls_dir/upstream-nginx.conf" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n agent-vault create configmap e2e-ca \
  --from-file=ca.crt="$tls_dir/ca.crt" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kubectl --context "$context" -n agent-vault create configmap agent-vault-config \
  --from-literal=server.toml="$(cat <<'TOML'
schema_version = 1

[server]
host = "0.0.0.0"
port = 14321
proxy_port = 14322
external_address = "https://agent-vault.agent-vault.svc.cluster.local"
log_level = "info"
detach = false

[database]
url = "env://DATABASE_URL"
max_open_conns = 10
max_idle_conns = 4
conn_max_lifetime = "5m"
connect_timeout = "10s"
tls_mode = "disable"

[proxy]
allow_private_ranges = true
network_allowlist = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

[auth]
mode = "spiffe"
workload_api = "unix:///run/spire/sockets/spire-agent.sock"
trust_domains = ["spiffe://cluster.example"]
bootstrap_owner_ids = ["spiffe://cluster.example/ns/agent-vault/sa/operator"]

[client]
address = "https://agent-vault.agent-vault.svc.cluster.local"
workload_api = "unix:///run/spire/sockets/spire-agent.sock"
trust_domains = ["spiffe://cluster.example"]

[encryption]
legacy_master_password = "env://MASTER_PASSWORD"

[[secret_providers]]
name = "connect-e2e"
kind = "onepassword-connect"
address = "https://connect.agent-vault.svc.cluster.local:8443"
token = "env://OP_CONNECT_TOKEN"

[telemetry]
enabled = false
TOML
)" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kubectl --context "$context" -n agents create configmap relay-config \
  --from-literal=relay.toml="$(cat <<'TOML'
schema_version = 1

[client]
address = "https://agent-vault.agent-vault.svc.cluster.local"
workload_api = "unix:///run/spire/sockets/spire-agent.sock"
trust_domains = ["spiffe://cluster.example"]

[relay]
listener_mode = "network"
listen_address = "0.0.0.0:14322"
remote_address = "agent-vault.agent-vault.svc.cluster.local:14322"
TOML
)" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kubectl --context "$context" -n agent-vault create configmap desired-state \
  --from-literal=fleet.toml="$(cat <<TOML
schema_version = 1
manager = "kubernetes-e2e"

[[agents]]
name = "example-agent-relay"
spiffe_id = "spiffe://cluster.example/ns/agents/sa/example-agent-relay"
role = "no-access"

[[vaults]]
name = "e2e"

[[vaults.grants]]
agent = "example-agent-relay"
role = "proxy"

[[vaults.services]]
name = "upstream"
host = "upstream.agent-vault.svc.cluster.local"
port = 8443
enabled = true
auth = { kind = "bearer", credential = "UPSTREAM_TOKEN" }

[[vaults.credentials]]
name = "UPSTREAM_TOKEN"
mode = "reference"
source = "connect-e2e"
ref = "vault/item/password"
refresh_interval = "10s"
max_staleness = "${max_staleness_seconds}s"
TOML
)" \
  --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kubectl --context "$context" apply -f - <<YAML >/dev/null
apiVersion: v1
kind: ServiceAccount
metadata: {name: agent-vault, namespace: agent-vault}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: operator, namespace: agent-vault}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: example-agent-relay, namespace: agents}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: example-agent, namespace: agents}
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres, namespace: agent-vault, labels: {app: postgres}}
spec:
  replicas: 1
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: postgres
          image: ${postgres_image}
          imagePullPolicy: IfNotPresent
          env:
            - {name: POSTGRES_USER, value: agentvault}
            - {name: POSTGRES_DB, value: agentvault}
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: database, key: POSTGRES_PASSWORD}}
          ports: [{name: postgres, containerPort: 5432}]
          readinessProbe: {exec: {command: [pg_isready, -U, agentvault, -d, agentvault]}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: postgres, namespace: agent-vault}
spec: {selector: {app: postgres}, ports: [{name: postgres, port: 5432, targetPort: postgres}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: connect, namespace: agent-vault, labels: {app: connect}}
spec:
  replicas: 1
  selector: {matchLabels: {app: connect}}
  template:
    metadata: {labels: {app: connect}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: connect
          image: ${nginx_image}
          imagePullPolicy: IfNotPresent
          command: [nginx]
          args: [-g, "daemon off;", -c, /etc/nginx/nginx.conf]
          ports: [{name: https, containerPort: 8443}]
          volumeMounts:
            - {name: fixture, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf, readOnly: true}
            - {name: fixture, mountPath: /etc/tls, readOnly: true}
            - {name: fixture, mountPath: /srv/connect/item.json, subPath: item.json, readOnly: true}
      volumes: [{name: fixture, secret: {secretName: connect-fixture}}]
---
apiVersion: v1
kind: Service
metadata: {name: connect, namespace: agent-vault}
spec: {selector: {app: connect}, ports: [{name: https, port: 8443, targetPort: https}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: upstream, namespace: agent-vault, labels: {app: upstream}}
spec:
  replicas: 1
  selector: {matchLabels: {app: upstream}}
  template:
    metadata: {labels: {app: upstream}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: upstream
          image: ${nginx_image}
          imagePullPolicy: IfNotPresent
          command: [nginx]
          args: [-g, "daemon off;", -c, /etc/nginx/nginx.conf]
          ports: [{name: https, containerPort: 8443}]
          volumeMounts:
            - {name: fixture, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf, readOnly: true}
            - {name: fixture, mountPath: /etc/tls, readOnly: true}
      volumes: [{name: fixture, secret: {secretName: upstream-fixture}}]
---
apiVersion: v1
kind: Service
metadata: {name: upstream, namespace: agent-vault}
spec: {selector: {app: upstream}, ports: [{name: https, port: 8443, targetPort: https}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: agent-vault, namespace: agent-vault, labels: {app: agent-vault}}
spec:
  replicas: 2
  strategy: {type: RollingUpdate, rollingUpdate: {maxUnavailable: 0, maxSurge: 1}}
  selector: {matchLabels: {app: agent-vault}}
  template:
    metadata: {labels: {app: agent-vault}}
    spec:
      serviceAccountName: agent-vault
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 10
      containers:
        - name: agent-vault
          image: ${image}
          imagePullPolicy: Never
          args: [server, --config, /etc/agent-vault/server.toml]
          envFrom: [{secretRef: {name: database}}]
          env: [{name: SSL_CERT_FILE, value: /etc/e2e-ca/ca.crt}, {name: HOME, value: /tmp/home}]
          ports: [{name: api, containerPort: 14321}, {name: proxy, containerPort: 14322}]
          startupProbe: {httpGet: {path: /health/startup, port: api, scheme: HTTPS}, periodSeconds: 2, failureThreshold: 90}
          readinessProbe: {httpGet: {path: /health/ready, port: api, scheme: HTTPS}, periodSeconds: 2, failureThreshold: 2}
          livenessProbe: {httpGet: {path: /health/live, port: api, scheme: HTTPS}, periodSeconds: 5, failureThreshold: 3}
          volumeMounts:
            - {name: config, mountPath: /etc/agent-vault, readOnly: true}
            - {name: e2e-ca, mountPath: /etc/e2e-ca, readOnly: true}
            - {name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true}
            - {name: runtime, mountPath: /tmp}
      volumes:
        - {name: config, configMap: {name: agent-vault-config}}
        - {name: e2e-ca, configMap: {name: e2e-ca}}
        - {name: spire-agent-socket, csi: {driver: csi.spiffe.io, readOnly: true}}
        - {name: runtime, emptyDir: {}}
---
apiVersion: v1
kind: Service
metadata: {name: agent-vault, namespace: agent-vault}
spec:
  selector: {app: agent-vault}
  ports: [{name: api, port: 443, targetPort: api}, {name: proxy, port: 14322, targetPort: proxy}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: agent-vault, namespace: agent-vault}
spec: {minAvailable: 1, selector: {matchLabels: {app: agent-vault}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: example-agent-relay, namespace: agents, labels: {app: example-agent-relay}}
spec:
  replicas: 1
  selector: {matchLabels: {app: example-agent-relay}}
  template:
    metadata: {labels: {app: example-agent-relay}}
    spec:
      serviceAccountName: example-agent-relay
      automountServiceAccountToken: false
      containers:
        - name: relay
          image: ${image}
          imagePullPolicy: Never
          args: [relay, --config, /etc/agent-vault/relay.toml]
          env: [{name: HOME, value: /tmp/home}]
          ports: [{name: proxy, containerPort: 14322}]
          readinessProbe: {tcpSocket: {port: proxy}, periodSeconds: 2}
          volumeMounts:
            - {name: config, mountPath: /etc/agent-vault, readOnly: true}
            - {name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true}
            - {name: runtime, mountPath: /tmp}
      volumes:
        - {name: config, configMap: {name: relay-config}}
        - {name: spire-agent-socket, csi: {driver: csi.spiffe.io, readOnly: true}}
        - {name: runtime, emptyDir: {}}
---
apiVersion: v1
kind: Service
metadata: {name: example-agent-relay, namespace: agents}
spec: {selector: {app: example-agent-relay}, ports: [{name: proxy, port: 14322, targetPort: proxy}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: example-agent, namespace: agents, labels: {app: example-agent}}
spec:
  replicas: 1
  selector: {matchLabels: {app: example-agent}}
  template:
    metadata: {labels: {app: example-agent}}
    spec:
      serviceAccountName: example-agent
      automountServiceAccountToken: false
      containers:
        - name: agent
          image: ${curl_image}
          imagePullPolicy: IfNotPresent
          command: [sleep, infinity]
YAML

kubectl --context "$context" apply -f - <<'YAML' >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: agent-vault}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: agents}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dns, namespace: agent-vault}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}, podSelector: {matchLabels: {k8s-app: kube-dns}}}]
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dns, namespace: agents}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}, podSelector: {matchLabels: {k8s-app: kube-dns}}}]
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: broker-api-and-relay, namespace: agent-vault}
spec:
  podSelector: {matchLabels: {app: agent-vault}}
  policyTypes: [Ingress]
  ingress:
    - ports: [{protocol: TCP, port: 14321}]
    - from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: agents}}, podSelector: {matchLabels: {app: example-agent-relay}}}]
      ports: [{protocol: TCP, port: 14322}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: broker-egress, namespace: agent-vault}
spec:
  podSelector: {matchLabels: {app: agent-vault}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app: postgres}}}]
      ports: [{protocol: TCP, port: 5432}]
    - to: [{podSelector: {matchLabels: {app: connect}}}, {podSelector: {matchLabels: {app: upstream}}}]
      ports: [{protocol: TCP, port: 8443}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: operator-to-api, namespace: agent-vault}
spec:
  podSelector: {matchLabels: {app: operator}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app: agent-vault}}}]
      ports: [{protocol: TCP, port: 14321}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: data-ingress, namespace: agent-vault}
spec:
  podSelector:
    matchExpressions: [{key: app, operator: In, values: [postgres, connect, upstream]}]
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: agent-vault}}}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: agent-to-own-relay, namespace: agents}
spec:
  podSelector: {matchLabels: {app: example-agent}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {app: example-agent-relay}}}]
      ports: [{protocol: TCP, port: 14322}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: relay-ingress-egress, namespace: agents}
spec:
  podSelector: {matchLabels: {app: example-agent-relay}}
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: example-agent}}}]
      ports: [{protocol: TCP, port: 14322}]
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: agent-vault}}, podSelector: {matchLabels: {app: agent-vault}}}]
      ports: [{protocol: TCP, port: 14322}]
YAML

kubectl --context "$context" -n agent-vault rollout status deployment/postgres --timeout=3m
stage="workload rollout"
kubectl --context "$context" -n agent-vault rollout status deployment/connect --timeout=3m
kubectl --context "$context" -n agent-vault rollout status deployment/upstream --timeout=3m
kubectl --context "$context" -n agent-vault rollout status deployment/agent-vault --timeout=5m
kubectl --context "$context" -n agents rollout status deployment/example-agent-relay --timeout=3m
kubectl --context "$context" -n agents rollout status deployment/example-agent --timeout=3m

kubectl --context "$context" apply -f - <<YAML >/dev/null
apiVersion: batch/v1
kind: Job
metadata: {name: reconcile, namespace: agent-vault}
spec:
  backoffLimit: 2
  template:
    metadata: {labels: {app: operator}}
    spec:
      serviceAccountName: operator
      automountServiceAccountToken: false
      restartPolicy: Never
      containers:
        - name: reconcile
          image: ${image}
          imagePullPolicy: Never
          args: [config, apply, --yes, --file, /etc/agent-vault/desired/fleet.toml]
          env: [{name: AGENT_VAULT_CONFIG, value: /etc/agent-vault/server.toml}, {name: HOME, value: /tmp/home}]
          volumeMounts:
            - {name: runtime-config, mountPath: /etc/agent-vault/server.toml, subPath: server.toml, readOnly: true}
            - {name: desired-state, mountPath: /etc/agent-vault/desired, readOnly: true}
            - {name: spire-agent-socket, mountPath: /run/spire/sockets, readOnly: true}
            - {name: runtime, mountPath: /tmp}
      volumes:
        - {name: runtime-config, configMap: {name: agent-vault-config}}
        - {name: desired-state, configMap: {name: desired-state}}
        - {name: spire-agent-socket, csi: {driver: csi.spiffe.io, readOnly: true}}
        - {name: runtime, emptyDir: {}}
YAML
kubectl --context "$context" -n agent-vault wait --for=condition=complete job/reconcile --timeout=3m

stage="initial provider refresh"
wait_for_sql "SELECT health FROM credential_sources WHERE credential_key='UPSTREAM_TOKEN';" "ok"
wait_for_request

echo "proving the untrusted workload cannot bypass its relay"
stage="relay isolation"
if kubectl --context "$context" -n agents exec deployment/example-agent -- \
  curl --fail --silent --insecure --connect-timeout 2 --max-time 4 \
    --proxy http://agent-vault.agent-vault.svc.cluster.local:14322 \
    https://upstream.agent-vault.svc.cluster.local:8443/check >/dev/null 2>&1; then
  echo "untrusted workload bypassed the relay" >&2
  exit 1
fi
kubectl --context "$context" -n agents exec deployment/example-agent -- \
  sh -c 'test ! -d /run/spire/sockets && test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token'

echo "deleting one broker replica under proxy load"
stage="broker disruption"
load_result="$evidence_dir/load-result.txt"
(
  successes=0
  failures=0
  for _ in {1..24}; do
    if agent_request 2>/dev/null; then
      successes=$((successes + 1))
    else
      failures=$((failures + 1))
    fi
    sleep 0.5
  done
  printf '%d %d\n' "$successes" "$failures"
) >"$load_result" &
load_pid=$!
sleep 2
victim="$(kubectl --context "$context" -n agent-vault get pod -l app=agent-vault -o jsonpath='{.items[0].metadata.name}')"
kubectl --context "$context" -n agent-vault delete pod "$victim" --wait=false >/dev/null
wait "$load_pid"
read -r disruption_successes disruption_failures <"$load_result"
if (( disruption_successes < 18 || disruption_failures > 6 )); then
  printf 'broker disruption was not bounded: successes=%d failures=%d\n' "$disruption_successes" "$disruption_failures" >&2
  exit 1
fi
kubectl --context "$context" -n agent-vault rollout status deployment/agent-vault --timeout=5m

echo "proving short-lived SVID rotation without pod restart"
stage="SVID rotation"
broker_uids_before="$(kubectl --context "$context" -n agent-vault get pod -l app=agent-vault -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' | sort)"
relay_uid_before="$(kubectl --context "$context" -n agents get pod -l app=example-agent-relay -o jsonpath='{.items[0].metadata.uid}')"
sleep $((svid_ttl_seconds + 8))
agent_request
broker_uids_after="$(kubectl --context "$context" -n agent-vault get pod -l app=agent-vault -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' | sort)"
relay_uid_after="$(kubectl --context "$context" -n agents get pod -l app=example-agent-relay -o jsonpath='{.items[0].metadata.uid}')"
if [[ "$broker_uids_before" != "$broker_uids_after" || "$relay_uid_before" != "$relay_uid_after" ]]; then
  echo "a broker or relay restarted during the SVID rotation observation" >&2
  exit 1
fi

echo "proving last-known-good use, max-staleness fail-close, and recovery"
stage="provider outage"
kubectl --context "$context" -n agent-vault scale deployment/connect --replicas=0 >/dev/null
sleep 3
agent_request
outage_started="$(date +%s)"
sleep $((max_staleness_seconds + 5))
wait_for_request_failure
wait_for_sql "SELECT health FROM credential_sources WHERE credential_key='UPSTREAM_TOKEN';" "stale"
if kubectl --context "$context" -n agent-vault get endpointslice \
  -l kubernetes.io/service-name=agent-vault \
  -o jsonpath='{range .items[*].endpoints[*]}{.conditions.ready}{"\n"}{end}' | grep -q '^true$'; then
  echo "stale provider cache left a broker endpoint ready" >&2
  exit 1
fi

recovery_started="$(date +%s)"
stage="provider recovery"
kubectl --context "$context" -n agent-vault scale deployment/connect --replicas=1 >/dev/null
kubectl --context "$context" -n agent-vault rollout status deployment/connect --timeout=3m
wait_for_sql "SELECT health FROM credential_sources WHERE credential_key='UPSTREAM_TOKEN';" "ok"
wait_for_request
recovery_seconds=$(( $(date +%s) - recovery_started ))
outage_fail_closed_seconds=$(( recovery_started - outage_started ))

stage="identity attribution"
for _ in {1..30}; do
  attributed_requests="$(sql "SELECT COUNT(*) FROM request_logs l JOIN agents a ON a.id=l.actor_id WHERE a.spiffe_id='spiffe://cluster.example/ns/agents/sa/example-agent-relay' AND l.host='upstream.agent-vault.svc.cluster.local:8443';" 2>/dev/null || true)"
  if [[ "$attributed_requests" =~ ^[0-9]+$ ]] && (( attributed_requests > 0 )); then
    break
  fi
  sleep 1
done
if [[ ! "$attributed_requests" =~ ^[0-9]+$ ]] || (( attributed_requests == 0 )); then
  echo "no request audit rows were attributed to the relay SPIFFE ID" >&2
  exit 1
fi

echo "collecting and scanning secret-free artifacts"
stage="artifact redaction"
kubectl --context "$context" get deployments,services,pods,networkpolicies,endpointslices \
  --all-namespaces -o yaml >"$evidence_dir/resources.yaml"
kubectl --context "$context" -n agent-vault logs -l app=agent-vault \
  --all-containers --prefix --tail=-1 >"$evidence_dir/broker.log"
kubectl --context "$context" -n agents logs -l app=example-agent-relay \
  --all-containers --prefix --tail=-1 >"$evidence_dir/relay.log"
kubectl --context "$context" -n agent-vault logs job/reconcile \
  --all-containers --prefix >"$evidence_dir/reconcile.log"

for forbidden in "$database_password" "$master_password" "$connect_token" "$provider_secret"; do
  if grep -R -F -- "$forbidden" "$evidence_dir" >/dev/null; then
    echo "collected Kubernetes artifact leaked an E2E secret sentinel" >&2
    exit 1
  fi
done

REPORT_PATH="$report_path" \
DISRUPTION_SUCCESSES="$disruption_successes" \
DISRUPTION_FAILURES="$disruption_failures" \
ATTRIBUTED_REQUESTS="$attributed_requests" \
OUTAGE_FAIL_CLOSED_SECONDS="$outage_fail_closed_seconds" \
RECOVERY_SECONDS="$recovery_seconds" \
SVID_TTL_SECONDS="$svid_ttl_seconds" \
python3 - <<'PY'
import json
import os

report = {
    "broker_replicas": 2,
    "relay_spiffe_id": "spiffe://cluster.example/ns/agents/sa/example-agent-relay",
    "svid_ttl_seconds": int(os.environ["SVID_TTL_SECONDS"]),
    "rotation_without_restart": True,
    "disruption_successes": int(os.environ["DISRUPTION_SUCCESSES"]),
    "disruption_failures": int(os.environ["DISRUPTION_FAILURES"]),
    "provider_lkg_during_outage": True,
    "outage_fail_closed_seconds": int(os.environ["OUTAGE_FAIL_CLOSED_SECONDS"]),
    "provider_recovery_seconds": int(os.environ["RECOVERY_SECONDS"]),
    "attributed_requests": int(os.environ["ATTRIBUTED_REQUESTS"]),
    "relay_bypass_blocked": True,
    "artifact_secret_scan_passed": True,
}
with open(os.environ["REPORT_PATH"], "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

python3 -m json.tool "$report_path"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Agent Vault Kubernetes fleet E2E"
    echo '```json'
    python3 -m json.tool "$report_path"
    echo '```'
  } >>"$GITHUB_STEP_SUMMARY"
fi

echo "Kubernetes SPIRE fleet failure scenarios passed."
