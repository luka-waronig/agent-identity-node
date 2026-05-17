# Contributing

Thanks for helping make agent identity infrastructure inspectable and boring in the best possible way.

## Prerequisites

For contributing to this project, you will need to have installed:

- Rust stable, with `cargo`, `rustfmt`, and `clippy`
- Git
- PowerShell 7+ on Windows, or Bash on Linux/macOS
- Python 3.10+ for clients or other scripts
- curl, which isuseful for testing the HTTP API manually
- a local code editor with TOML, JSON, Markdown, Rust, and Python support

Optional:

- Node.js 20+ if working on future TypeScript examples or SDKs
- Kubo/IPFS if experimenting with HIVE-style decentralized artifact storage
- GitHub CLI if preparing releases, issues, or pull requests

## Development

```bash
cargo fmt
cargo test
cargo run -p agent-node-daemon -- init --profile .dev-node
cargo run -p agent-node-daemon -- run --profile .dev-node
```

## Pull request expectations/advice:

- When working on top of this particular repo, my good advice here is to keep changes small and security-relevant. There are several more related repositories, which will be published in the near future, that will open-suorce more subsystems of the Hive agent architecture.
- Add your own tests for identity, authorization, policy, and tool execution behavior.
- Don't commit generated identities, tokens, vault contents, local databases, or logs.
- Document API or policy schema changes in `docs/`.

## Design preferences/advice:

The Rust node daemon should own identity, authorization, and enforcement. Client examples in Python, JavaScript, or other languages should consume the node daemon API without receiving raw private keys or any such material.

## Licensing

Unless explicitly stated otherwise, contributions are accepted under the same dual license as the project: MIT OR Apache-2.0.
