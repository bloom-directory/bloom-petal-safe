# Safe Petal development

- Keep owner signatures and service credentials out of route reads and logs.
- Treat Transaction Service responses as untrusted and recompute all Safe hashes.
- Never add arbitrary delegatecall support. Only pinned MultiSendCallOnly and CreateCall deployments are allowed.
- Keep Safe owner signing and outer EVM execution as separate lifecycle steps and hashes.
- Every wallet-scoped route is mounted under `[wallet]/[index]`. Bloom derives
  the signing key and the outbox sender from that account, so read the owner
  address from `wallets/<wallet>/<index>/address.evm` and never from account 0
  or the retired wallet-root leaves. `[wallet]/$index.rs` stays empty; Bloom
  enumerates accounts from its own projection.
- Run `cargo test --manifest-path route/Cargo.toml`, `cargo clippy --manifest-path route/Cargo.toml --all-targets -- -D warnings`, and `scripts/build.sh`.
