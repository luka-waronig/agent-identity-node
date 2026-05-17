# Changelog

## 0.1.0-alpha.1

Initial alpha release of AIN.

Included:
- encrypted Ed25519 libp2p identity storage with Argon2 and AES-256-GCM.
- signed scoped capability grants with `request_code` binding.
- local daemon endpoints for manifest, capabilities, grant issuance, grant verification, execution, and signed broadcasts.
- MCP-style JSON-RPC endpoint for grant-verified tool listing and tool calls.
- A2A Agent Card discovery at `/.well-known/agent-card.json`.
- capability policy schema and enforcement helpers.
- optional libp2p mesh transport primitives.
- Rust and Python agent client examples.
- JSON Schemas for policy, manifest, grants, and signed broadcasts.
- security notes and initial threat model.
