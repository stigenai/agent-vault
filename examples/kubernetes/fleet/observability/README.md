# Fleet observability examples

This optional overlay installs a Grafana dashboard ConfigMap and
PrometheusRule alerts. It assumes the Prometheus Operator CRDs are installed:

```sh
kubectl apply -k examples/kubernetes/fleet/observability
```

Enable broker metrics with `telemetry.metrics_enabled = true`. The broker
serves `GET /metrics` on the API listener and applies the normal authentication
chain. In SPIFFE-only mode the scraper therefore needs a valid SVID whose exact
ID is bound to an active Agent Vault agent. Use a SPIFFE-aware collector or a
SPIRE helper/Envoy sidecar that rotates short-lived scraper certificates; do
not create a durable scrape token.

Label the collector namespace so the production NetworkPolicy admits the API scrape:

```sh
kubectl label namespace monitoring agent-vault.stigen.ai/metrics-scrapers=true
```

For relays, set `relay.metrics_address` to an explicit address. The relay
metrics listener always uses SPIFFE mTLS and permits only peers in a configured
trust domain. If it is non-loopback, `relay.listener_mode = "network"` is also
required and Kubernetes NetworkPolicy should restrict it to the monitoring
collector.

Metrics deliberately omit SPIFFE IDs, vault and agent names, provider names,
secret references, error text, DSNs, tokens, payloads, and credential keys.
Only the fixed `backend` and `health` label enums are exported.
