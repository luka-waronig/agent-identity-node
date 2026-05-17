# Threat Model

This document describes the initial alpha threat model for Agent Identity Node.

## Assets

- Node private identity key.
- Local API bearer token.
- Signed scoped capability grants.
- Capability policy files.
- Vault contents.
- Signed broadcast envelopes.

## Intended Protections

- Private node identity keys are encrypted at rest.
- Agent runtimes cannot access raw private key material through the daemon API.
- Local API calls require a bearer token.
- Runtime agent calls can use short-lived grants signed by the node identity.
- Tool requests are checked against a node capability policy before execution.
- Vault file access is restricted to sanitized file names.

## Out Of Scope For The Alpha

- Protection from a fully compromised host operating system.
- Protection from malware that can read the token file and key password.
- Multi-user OS sandboxing.
- Remote network exposure beyond localhost.
- Formal verification of cryptographic protocols.

## Main Risks

- Token leakage gives API access until the token is rotated.
- Grant leakage gives scoped access until the grant expires.
- Weak identity passwords reduce the strength of encrypted key storage.
- Expanding the tool catalog without careful review can create policy bypasses.
- Binding the API to a public interface exposes the daemon to remote clients.

## Near-Term Hardening Work

- Add grant revocation and audit logs.
- Add per-request proof-of-possession for grants.
- Add JSON Schema validation for policy files.
- Add audit logs for policy decisions.
- Add dependency review and cargo-deny.
