# Agent Identity Node

Agent Identity Node is a small Rust-first substrate for local agent authorization. It gives an agent runtime a durable cryptographic node identity, encrypted key storage, bootstrap authentication, signed scoped capability grants, and explicit capability policies.

This repository is intended for researchers and developers who want to experiment with verifiable local identity and policy enforcement without installing a larger desktop agent system. It was extracted from the broader HIVE research project as a standalone, inspectable security substrate.

## What This Is

- An encrypted Ed25519 libp2p identity stored locally with Argon2 plus AES-256-GCM.
- A local HTTP daemon that exposes identity, manifest, capability, grant issuance, grant verification, and policy-gated execution endpoints.
- An MCP-style JSON-RPC tool endpoint that verifies the same signed grants before tool calls.
- An A2A Agent Card at `/.well-known/agent-card.json` for discovery by agent registries and clients.
- A JSON capability policy schema for tool, vault, task, provider, and broadcast permissions.
- An optional libp2p mesh crate for signed gossipsub transport experiments.
- Minimal Rust and Python client examples.

## What This Is Not

- Not the full HIVE application.
- Not an agent framework, model router, desktop UI, benchmark harness, or mission orchestration layer.
- Not a finished security product. This is an alpha research substrate and should be reviewed before production use.

## Quick Start

Install the daemon from a checked-out repository:

```bash
cargo install --path crates/node-daemon
```

Run a local profile after installation:

```bash
AIN_IDENTITY_PASSWORD="change-me-for-local-testing" agent-node init --profile .dev-node --role researcher-agent && AIN_IDENTITY_PASSWORD="change-me-for-local-testing" agent-node run --profile .dev-node --port 8787
```

On PowerShell:

```powershell
$env:AIN_IDENTITY_PASSWORD="change-me-for-local-testing"; agent-node init --profile .dev-node --role researcher-agent; agent-node run --profile .dev-node --port 8787
```

For development without installing:

```powershell
cd agent-identity-node
$env:AIN_IDENTITY_PASSWORD="change-me-for-local-testing"
cargo run -p agent-node-daemon -- init --profile .dev-node --role researcher-agent
cargo run -p agent-node-daemon -- run --profile .dev-node --port 8787
```

In a second terminal:

```powershell
$token = Get-Content .dev-node\agent.token
Invoke-RestMethod http://127.0.0.1:8787/manifest -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod http://127.0.0.1:8787/execute `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body '{"tool_name":"SCAN_VAULT","payload":""}'
```

## Authentication And Verifiability Pipeline

The daemon separates bootstrap authentication from ongoing agent authorization.

1. **Identity creation**: `agent-node init` creates an Ed25519 libp2p identity and encrypts the private key locally with Argon2 plus AES-256-GCM. The private key never leaves the daemon.
2. **Bootstrap token**: the profile receives a local bearer token. This is an administrative bootstrap secret used to initialize or rotate agent access.
3. **Authorization request**: an agent asks `POST /auth/request-code` for a one-time `request_code` tied to a subject and optional requested scopes.
4. **Grant issuance**: a trusted bootstrap caller sends `POST /auth/grants` with the bearer token, request id, subject, scopes, and TTL. The daemon checks those scopes against the active policy, then signs a grant with the node identity.
5. **Scoped request**: the agent calls protected endpoints with `Authorization: AIN-Grant <base64-json-grant>`. The daemon verifies issuer, signature, expiration, and required scope before policy enforcement.
6. **External verifiability**: `GET /manifest` exposes the node peer id and public key protobuf bytes. Researchers can verify that a grant or signed broadcast was issued by the node identity without seeing private key material.

Example grant flow:

```powershell
$authRequest = Invoke-RestMethod http://127.0.0.1:8787/auth/request-code `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"subject":"python-agent","requested_scopes":["manifest:read","tool:scan_vault"]}'

$grant = Invoke-RestMethod http://127.0.0.1:8787/auth/grants `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body (@{
    request_id = $authRequest.request.request_id
    subject = "python-agent"
    scopes = @("manifest:read", "tool:scan_vault")
    ttl_seconds = 600
  } | ConvertTo-Json)

Invoke-RestMethod http://127.0.0.1:8787/execute `
  -Method Post `
  -Headers @{ Authorization = $grant.authorization_header } `
  -ContentType "application/json" `
  -Body '{"tool_name":"SCAN_VAULT","payload":""}'
```

## Workspace Layout

```text
crates/
  identity-core/        encrypted local identity primitives
  capability-policy/    policy schema and enforcement helpers
  mesh/                 optional libp2p mesh transport primitives
  node-daemon/          runnable local daemon and API
schemas/                JSON Schemas for policy, manifest, grants, broadcasts
scripts/                release smoke tests
examples/
  python-agent/         minimal Python client
  rust-agent/           minimal Rust client
docs/
  integrations.md       MCP and A2A integration surface
  protocol.md           HTTP API and signed payload notes
  policy-schema.md      capability policy reference
  threat-model.md       initial security model
CHANGELOG.md            version history
```

## API Surface

- `GET /healthz`: unauthenticated readiness.
- `POST /auth/request-code`: creates a short-lived `request_code` for grant requests.
- `POST /auth/grants`: bearer-authenticated signed grant issuance.
- `POST /auth/verify`: grant signature, issuer, expiration, and optional scope verification.
- `GET /.well-known/agent-card.json`: public A2A Agent Card for discovery.
- `GET /status`: authenticated status summary.
- `GET /manifest`: authenticated node identity and policy manifest.
- `GET /capabilities`: authenticated tool catalog and policy view.
- `POST /mcp`: MCP-style JSON-RPC endpoint for `initialize`, `tools/list`, and `tools/call`.
- `POST /execute`: authenticated, policy-gated tool request.
- `POST /broadcast`: authenticated signed message envelope.

Agents can authenticate with `Authorization: Bearer <token>` for bootstrap/admin operations or `Authorization: AIN-Grant <base64-json-grant>` for scoped runtime operations.

## Integrations

Agent Identity Node does not replace MCP or A2A. It gives those runtimes a local authority that can hold raw keys, issue scoped grants, verify grants, enforce policy, and expose a verifiable node identity.

- MCP clients can call `POST /mcp` with JSON-RPC `initialize`, `tools/list`, and `tools/call`. Tool calls require either the bootstrap bearer token or an `AIN-Grant` with the matching `tool:*` scope.
- A2A-aware clients and registries can fetch `GET /.well-known/agent-card.json` to discover the node identity authority, supported interfaces, auth schemes, and policy-exposed skills.

## Roadmap

- Add grant revocation and persisted authorization/audit logs.
- Add a daemon flag that publishes signed broadcasts through the optional libp2p mesh crate.
- Publish signed invocation receipts.
- Add formal message signature verification examples.
- Add cargo-deny, secret scanning, and dependency review workflows.

## License

Agent Identity Node is dual-licensed under either:

- MIT, see `LICENSE-MIT`
- Apache-2.0, see `LICENSE-APACHE`

You may use this project under either license, at your option.

## Relationship To HIVE

HIVE uses a richer desktop and orchestration environment around similar concepts: identity, capability manifests, local enforcement, agent process supervision, mission state, and telemetry. Agent Identity Node is the small open-source core that focuses only on identity and capability enforcement.
