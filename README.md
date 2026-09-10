# Bloom Safe Petal

Operate an existing Safe smart account with Bloom-backed owner signing and EVM execution. Owner and executor private keys stay in Bloom; no deployment or signing key is placed in an environment variable.

The Petal supports Safe 1.3.0, 1.4.1, and 1.5.0, native transfers, arbitrary calls, ERC-20 transfers, call-only batches, Safe Transaction Builder imports, CREATE, CREATE2, rejection transactions, Safe Transaction Service proposal/confirmation, offline signature collection, and outbox execution.

## Install and policy

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-safe
bloom petals ls
```

The owner wallet policy must allow the Petal package and `destination = "exact"` on the numeric EVM chain, for example `chain = "evm-1"`. Configure an `evm-*` RPC in Bloom. To use a custom Transaction Service, configure the Petal endpoint binding `transaction-service` to the same HTTPS origin stored in the binding.

## Bind a Safe

Write this JSON to `petals/safe/safes/<wallet>/<safe-id>.json`:

```json
{
  "chain": "evm-1",
  "safe_address": "0x...",
  "transaction_service": "https://safe-transaction-mainnet.safe.global"
}
```

Bloom verifies code at the address, chain ID, singleton, `VERSION()`, owners, threshold, nonce, guard, all enabled modules (up to 64), and fallback handler. The Bloom wallet address must be a current owner. Read the same path to compare the bound configuration with current chain state.

Hosted Safe Transaction Service API keys are optional and write-only:

```text
petals/safe/service-keys/<wallet>/<safe-id>
```

The value is stored in the Petal's secret namespace. It cannot be read through VFS.

## Draft

Write `{"safe_id":"treasury","transaction":...}` to `petals/safe/transactions/<wallet>/<transaction-id>/draft.json`. Supported transaction bodies include:

```json
{"kind":"native_transfer","to":"0x...","value":"1000000000000000"}
{"kind":"call","to":"0x...","value":"0","data":"0x..."}
{"kind":"erc20_transfer","token":"0x...","to":"0x...","amount":"1000000"}
{"kind":"batch","calls":[{"to":"0x...","value":"0","data":"0x..."}]}
{"kind":"transaction_builder","builder":{"version":"1.0","chainId":"1","createdAt":0,"meta":{"createdFromSafeAddress":"0x..."},"transactions":[{"to":"0x...","value":"0","data":null,"contractMethod":{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","payable":false},"contractInputsValues":{"to":"0x...","amount":"1000000"}}]}}
{"kind":"create","value":"0","initcode":"0x..."}
{"kind":"create2","value":"0","initcode":"0x...","salt":"0x<32 bytes>"}
{"kind":"rejection"}
```

Batches and multi-transaction Builder files use only the pinned canonical `MultiSendCallOnly`. Builder entries may contain raw `data` or a standard `contractMethod` plus `contractInputsValues`; Bloom ABI-encodes scalar, array, and tuple inputs and rejects missing, extra, or invalid values. Deployments use only the pinned canonical `CreateCall`. The Petal reads and hashes the runtime code before drafting. Arbitrary delegatecalls and Safe self-calls are rejected. Refund fields are fixed to zero.

## Confirm and propose

Write an empty body to `.../<transaction-id>/confirm.json`. Bloom displays Broker's independently decoded Safe review, then signs the exact EIP-712 Safe transaction. Retry the same write after approval. The Petal recovers the owner address from the returned signature.

If the binding has a Transaction Service, the Petal proposes a new transaction or adds its confirmation to an existing exact transaction. Service responses are checked against every Safe transaction field and hash. Without a service, the signature remains in Petal-private state for direct execution.

## Execute

Write to `.../<transaction-id>/execute.json`:

```json
{
  "executor_wallet": "gas-payer",
  "signatures": [],
  "max_fee_per_gas": "30000000000",
  "max_priority_fee_per_gas": "1000000000"
}
```

When a Transaction Service is configured, confirmations are fetched automatically. Otherwise, add 65-byte EOA owner signatures to `signatures`. Every signature is recovered against `safeTxHash`, checked against current owners, deduplicated, sorted by owner address, and threshold checked. Contract signatures are intentionally unsupported in this release.

The encoded `execTransaction` is staged in Bloom's native EVM outbox and requires the normal executor-wallet approval. Read `.../<transaction-id>/status.json` to reconcile it.

## Hash lifecycle

`safe_tx_hash` identifies the Safe owner authorization. `execution_tx_hash` identifies the outer EVM transaction that calls `execTransaction`. They are never interchangeable. Same-nonce Safe proposals can conflict; only the transaction executed first can advance the Safe nonce.

## Security limits

- Only the current on-chain Safe nonce can be signed.
- Safe configuration drift blocks signing and execution until the Safe is rebound.
- All Safe gas reimbursement fields are zero.
- Safe self-administration, arbitrary delegatecalls, modules as authorization, future nonce queues, and EIP-7702 accounts are rejected.
- A configured guard or module is surfaced in every review; guards can still reject execution, and modules may execute transactions outside this Petal.

## Development

Run the Rust and component checks with `cargo test --manifest-path route/Cargo.toml`, `cargo clippy --manifest-path route/Cargo.toml --all-targets -- -D warnings`, and `scripts/build.sh`. The Anvil proof installs the official Safe 1.4.1 runtime and executes every supported transaction family against it, checking the Safe transaction encoding on-chain. It drives the Safe contracts directly rather than the compiled route, and installs only 1.4.1, so the 1.3.0 and 1.5.0 pinned deployments are not covered by it:

```sh
npm ci
forge build
anvil --port 18545 --silent &
npm run test:anvil
```

Licensed under the MIT License. See [LICENSE](./LICENSE).
