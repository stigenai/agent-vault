#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
run_id="$$-${RANDOM}"
source_container="agent-vault-backup-source-$run_id"
target_container="agent-vault-backup-target-$run_id"
report_dir="$(mktemp -d)"
report_path="$report_dir/backup-drill-report.json"

cleanup() {
  docker rm -f "$source_container" "$target_container" >/dev/null 2>&1 || true
  rm -rf "$report_dir"
}
trap cleanup EXIT

for tool in docker go pg_dump pg_restore python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

client_major="$(pg_dump --version | awk '{print $3}' | cut -d. -f1)"
postgres_image="${POSTGRES_IMAGE:-postgres:${client_major}-alpine}"

start_postgres() {
  local name="$1"
  docker run --detach --rm \
    --name "$name" \
    --publish 127.0.0.1::5432 \
    --env POSTGRES_USER=agentvault \
    --env POSTGRES_PASSWORD=test-password \
    --env POSTGRES_DB=agentvault \
    "$postgres_image" >/dev/null
}

wait_postgres() {
  local name="$1"
  local _
  for _ in {1..60}; do
    if docker exec "$name" pg_isready -U agentvault -d agentvault >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "PostgreSQL container did not become ready: $name" >&2
  return 1
}

mapped_port() {
  docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$1"
}

start_postgres "$source_container"
start_postgres "$target_container"
wait_postgres "$source_container"
wait_postgres "$target_container"

source_port="$(mapped_port "$source_container")"
target_port="$(mapped_port "$target_container")"

AGENT_VAULT_TEST_BACKUP_SOURCE_URL="postgres://agentvault:test-password@127.0.0.1:${source_port}/agentvault?sslmode=disable" \
AGENT_VAULT_TEST_BACKUP_TARGET_URL="postgres://agentvault:test-password@127.0.0.1:${target_port}/agentvault?sslmode=disable" \
AGENT_VAULT_BACKUP_DRILL_REPORT="$report_path" \
  go test -count=1 -v ./cmd -run '^TestPostgresBackupRestoreAndExplicitRecovery$'

python3 -m json.tool "$report_path"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Agent Vault backup/recovery drill"
    echo '```json'
    python3 -m json.tool "$report_path"
    echo '```'
  } >>"$GITHUB_STEP_SUMMARY"
fi
echo "Backup, restore, primary unwrap, and explicit offline recovery drill passed."
