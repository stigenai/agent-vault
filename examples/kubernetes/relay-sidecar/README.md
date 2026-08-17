# Agent Vault relay sidecar

This example keeps the SPIRE Workload API socket exclusively in the relay
container. The agent receives only a loopback proxy address and the public MITM
CA bundle. Replace the example images, trust domain, and service names before
deployment.

Create the public CA ConfigMap before applying the example:

```sh
agent-vault ca fetch --output ca.pem
kubectl -n agents create configmap agent-vault-mitm-ca --from-file=ca.pem
kubectl -n agents apply -k examples/kubernetes/relay-sidecar
```

Register the pod's service account with SPIRE using the exact SPIFFE ID stored
on its Agent Vault agent actor. The pod intentionally disables Kubernetes
service-account token automounting. Apply the companion NetworkPolicy from the
fleet deployment so the agent container cannot bypass the relay to reach the
broker directly.
