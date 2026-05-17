# Security Policy

Agent Identity Node is currently alpha research software.

Please do not treat this daemon as a hardened production security boundary until the threat model, cryptographic design, dependency set, and API behavior have been independently reviewed.

## Reporting

Report security concerns through GitHub private vulnerability reporting for this repository. If private reporting is not enabled yet, do not publish a production-facing release until a private disclosure path exists.

## Current Security Posture

- Node identity material is encrypted at rest with Argon2-derived AES-256-GCM keys.
- The daemon exposes local HTTP endpoints protected by bearer bootstrap tokens or signed scoped grants.
- Grants are signed by the node identity, include subject, scopes, request code, issuer, and expiration, and can be verified without private key access.
- Tool execution is policy-gated and scoped to a configured vault directory.
- The daemon can sign outbound broadcast envelopes with the node identity.
- An optional libp2p mesh crate provides signed gossipsub transport primitives for experiments.

## Known Alpha Limitations

- Bearer tokens are local shared secrets and should be protected like passwords.
- Grants are currently bearer-capability tokens after issuance; a stolen unexpired grant can be replayed until expiration.
- Grant revocation and persistent audit logs are not implemented yet.
- The current daemon does not yet run the peer-to-peer transport directly; mesh support is exposed as a library crate.
- Policy JSON is trusted as local configuration.
- The vault tooling is intentionally minimal and should be reviewed before expanding the tool catalog.
