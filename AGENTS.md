# Safe Petal development

- Keep owner signatures and service credentials out of route reads and logs.
- Treat Transaction Service responses as untrusted and recompute all Safe hashes.
- Never add arbitrary delegatecall support. Only pinned MultiSendCallOnly and CreateCall deployments are allowed.
- Keep Safe owner signing and outer EVM execution as separate lifecycle steps and hashes.
- Run `cargo test --manifest-path route/Cargo.toml`, `cargo clippy --manifest-path route/Cargo.toml --all-targets -- -D warnings`, and `scripts/build.sh`.
