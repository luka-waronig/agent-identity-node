#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${PROFILE:-.smoke-node}"
PORT="${PORT:-18787}"
export AIN_IDENTITY_PASSWORD="${AIN_IDENTITY_PASSWORD:-agent-identity-node-smoke-test}"

rm -rf "$PROFILE" vault_researcher-agent

cargo run -p agent-node-daemon -- init --profile "$PROFILE" --role researcher-agent
cargo run -p agent-node-daemon -- run --profile "$PROFILE" --port "$PORT" &
PID="$!"

cleanup() {
  kill "$PID" >/dev/null 2>&1 || true
  rm -rf "$PROFILE" vault_researcher-agent
}
trap cleanup EXIT

TOKEN="$(cat "$PROFILE/agent.token")"
BASE="http://127.0.0.1:$PORT"

for _ in $(seq 1 60); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS "$BASE/healthz" >/dev/null
curl -fsS "$BASE/.well-known/agent-card.json" >/dev/null
curl -fsS "$BASE/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' >/dev/null

REQUEST_ID="$(
  curl -fsS "$BASE/auth/request-code" \
    -H "Content-Type: application/json" \
    -d '{"subject":"smoke-agent","requested_scopes":["manifest:read","capabilities:read","tool:scan_vault"]}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["request"]["request_id"])'
)"

AUTH_HEADER="$(
  curl -fsS "$BASE/auth/grants" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"request_id\":\"$REQUEST_ID\",\"subject\":\"smoke-agent\",\"scopes\":[\"manifest:read\",\"capabilities:read\",\"tool:scan_vault\"],\"ttl_seconds\":300}" \
  | python -c 'import json,sys; print(json.load(sys.stdin)["authorization_header"])'
)"

curl -fsS "$BASE/manifest" -H "Authorization: $AUTH_HEADER" >/dev/null
curl -fsS "$BASE/execute" \
  -H "Authorization: $AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"SCAN_VAULT","payload":""}' >/dev/null
curl -fsS "$BASE/mcp" \
  -H "Authorization: $AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' >/dev/null
curl -fsS "$BASE/mcp" \
  -H "Authorization: $AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"SCAN_VAULT","arguments":{"payload":""}}}' >/dev/null

echo "smoke test passed"
