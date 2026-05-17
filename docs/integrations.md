# Integrations

Agent Identity Node is an authorization layer for agent runtimes. It does not try to replace MCP tool servers or A2A task agents. It gives them a local trust authority that can hold raw identity keys, issue signed scoped grants, verify those grants, and enforce node policy.

## MCP Surface

`POST /mcp` accepts JSON-RPC 2.0 requests for a minimal MCP-style tool surface.

Supported methods:

- `initialize`
- `tools/list`
- `tools/call`

`initialize` is public so clients can negotiate the basic server shape. `tools/list` requires `capabilities:read`. `tools/call` requires the matching `tool:*` grant scope, such as `tool:scan_vault`.

Example:

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

The response uses MCP-style tool content:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[]"
      }
    ],
    "isError": false
  }
}
```

This is not a full MCP host implementation. It is a grant-verified tool endpoint that follows the MCP method names and JSON-RPC shape needed by simple clients and adapter experiments.

## A2A Discovery

`GET /.well-known/agent-card.json` returns an A2A Agent Card. The card advertises the node as a local authorization and capability authority, not as a full task-orchestration agent.

The card includes:

- public node endpoint URL
- supported interfaces
- auth schemes for bearer bootstrap and `AIN-Grant`
- policy-exposed skills derived from the tool catalog
- a scoped-grants extension URI

The card never includes private key material, bearer tokens, signed grants, local file paths, or profile secrets.

## Integration Pattern

1. a runtime fetches the Agent Card or calls `initialize` on `/mcp`.
2. the runtime requests a `request_code` for the scopes it needs.
3. a trusted bootstrap process exchanges that request for a signed grant.
4. the runtime calls `/mcp` or native HTTP endpoints with `Authorization: AIN-Grant <base64-json-grant>`.
5. the daemon verifies issuer, signature, expiration, route/tool scope, and active policy before executing.

This gives MCP and A2A deployments a local-first trust layer for scoped authorization without giving untrusted agents raw signing keys.
