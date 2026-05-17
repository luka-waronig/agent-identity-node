# Protocol

Agent Identity Node exposes a small local HTTP API. `/healthz`, `/auth/request-code`, `/auth/verify`, and `/.well-known/agent-card.json` are public. Runtime endpoints require either the bootstrap bearer token or a signed scoped grant.

```text
Authorization: Bearer <agent-token>
Authorization: AIN-Grant <base64-json-grant>
```

The bearer token is generated during `agent-node init` and stored in the profile directory. Grants are signed by the encrypted node identity and can be verified against the public key in `/manifest`.

## Authentication Flow

1. `POST /auth/request-code` returns a request id, `request_code`, subject, requested scopes, and expiration.
2. `POST /auth/grants` requires the bearer token. It consumes the authorization request, checks requested scopes against active policy, and returns a signed grant plus a ready-to-use `Authorization` header value.
3. Protected routes verify the grant signature, issuer peer id, expiration, and route-specific scope.
4. The route then performs normal policy enforcement, so grants cannot outlive policy changes.

Current route scopes:

- `status:read`
- `manifest:read`
- `capabilities:read`
- `broadcast:write`
- `tool:read_file`
- `tool:archive_data`
- `tool:scan_vault`

## Endpoints

### `GET /healthz`

Returns unauthenticated daemon readiness.

### `GET /status`

Returns a compact authenticated status payload with peer id, role, and current capabilities.

### `GET /manifest`

Returns the full node manifest:

- schema version,
- peer id,
- identity public-key fingerprint,
- API auth mode,
- effective tool catalog,
- loaded policy.

### `GET /capabilities`

Returns the effective tool catalog, allowed auth scopes, and policy.

### `GET /.well-known/agent-card.json`

Returns a public A2A Agent Card describing the node as a local authorization and capability authority. The card declares the MCP-style endpoint, the native HTTP binding, supported auth schemes, and policy-exposed skills. It does not contain private keys, bearer tokens, or signed grants.

### `POST /mcp`

Accepts JSON-RPC 2.0 requests for a minimal MCP-style tool surface.

Supported methods:

- `initialize`: returns protocol version, tool capabilities, and server info.
- `tools/list`: returns the current policy-exposed tools. Requires `capabilities:read`.
- `tools/call`: runs a policy-gated tool call. Requires the corresponding `tool:*` scope.

Example `tools/call`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "SCAN_VAULT",
    "arguments": {
      "payload": ""
    }
  }
}
```

### `POST /auth/request-code`

Creates a short-lived `request_code` for grant issuance. The request code is random data bound into the signed grant so a grant request cannot be silently reused as if it were new.

```json
{
  "subject": "python-agent",
  "requested_scopes": ["manifest:read", "tool:scan_vault"],
  "ttl_seconds": 300
}
```

### `POST /auth/grants`

Requires `Authorization: Bearer <agent-token>`. Issues a signed scoped grant.

```json
{
  "request_id": "request id from /auth/request-code",
  "subject": "python-agent",
  "scopes": ["manifest:read", "tool:scan_vault"],
  "ttl_seconds": 600
}
```

### `POST /auth/verify`

Verifies a grant and optionally checks a required scope.

```json
{
  "grant_base64": "base64-json-grant",
  "required_scope": "tool:scan_vault"
}
```

### `POST /execute`

Runs a policy-gated tool request.

```json
{
  "tool_name": "SCAN_VAULT",
  "payload": ""
}
```

### `POST /broadcast`

Creates a signed local broadcast envelope. The alpha daemon returns the signed envelope but does not yet publish it to a libp2p mesh.

```json
{
  "content": "hello from an authorized agent"
}
```

## Grant Signature Payload

The daemon signs the JSON claims object:

- `schema_version`
- `issuer_peer_id`
- `subject`
- `scopes`
- `issued_at`
- `expires_at`
- `request_code`

The grant wrapper contains the claims plus `signature_base64`.

## Broadcast Signature Payload

The daemon signs a canonical JSON string containing:

- `sender_peer_id`
- `timestamp`
- `content`

Future versions should publish a stable binary or JSON canonicalization rule before broad interoperability claims are made.
