#!/usr/bin/env bash
set -euo pipefail

read -r -a postgres_versions <<<"${POSTGRES_VERSIONS:-13 14 15 16 17 18}"
containers=()

cleanup() {
  for container in "${containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

for version in "${postgres_versions[@]}"; do
  container="agent-vault-postgres-ha-${version}-${RANDOM}"
  containers+=("$container")
  printf 'testing PostgreSQL %s\n' "$version"
  docker run -d --name "$container" \
    -e POSTGRES_USER=agentvault \
    -e POSTGRES_PASSWORD=test-password \
    -e POSTGRES_DB=agentvault \
    -p 127.0.0.1::5432 \
    "postgres:${version}-alpine" >/dev/null

  ready=0
  for _ in {1..60}; do
    if docker exec "$container" pg_isready -U agentvault -d agentvault >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ $ready != 1 ]]; then
    docker logs "$container"
    printf 'PostgreSQL %s did not become ready\n' "$version" >&2
    exit 1
  fi

  port=$(docker port "$container" 5432/tcp | sed -n 's/.*://p' | head -1)
  if ! AGENT_VAULT_TEST_POSTGRES_URL="postgres://agentvault:test-password@127.0.0.1:${port}/agentvault?sslmode=disable" \
    go test -race ./internal/store -run '^TestPostgresHA' -count=1; then
    docker logs "$container"
    exit 1
  fi
  docker rm -f "$container" >/dev/null
done

printf 'PostgreSQL HA verification passed for majors: %s\n' "${postgres_versions[*]}"
