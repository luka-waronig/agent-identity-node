# Policy Schema

The alpha policy schema is identified as:

```text
agent-node/v0alpha1
```

Example:

```json
{
  "schema_version": "agent-node/v0alpha1",
  "role": "researcher-agent",
  "tool_policy": {
    "allowed_tools": ["READ_FILE", "ARCHIVE_DATA", "SCAN_VAULT"],
    "denied_tools": []
  },
  "broadcast_policy": {
    "allow_agent_broadcasts": true,
    "max_payload_bytes": 32768
  },
  "task_policy": {
    "allow_announce": true,
    "allow_claim": true,
    "allow_complete": true,
    "allow_verify": false,
    "allowed_requested_roles": ["researcher-agent"]
  },
  "vault_policy": {
    "vault_dir": "vault_researcher-agent",
    "allow_read": true,
    "allow_list": true,
    "allow_write": true
  },
  "provider_policy": {
    "allowed_providers": [],
    "allowed_models": [],
    "allow_local": true,
    "allow_cloud": false
  }
}
```

## Enforcement Rules

- Denied tools override allowed tools.
- Unknown tools are rejected.
- Vault read, list, and write permissions gate the corresponding tool names.
- Empty `allowed_requested_roles` means any role may be requested.
- Provider policy is exposed for client-side and orchestration decisions; the alpha daemon does not call model providers.
