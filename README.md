# Bloom Safe Petal

Operate an existing Safe smart account with Bloom-backed owner signing and EVM execution. Owner and executor private keys stay in Bloom; no deployment or signing key is placed in an environment variable.

The Petal supports Safe 1.3.0, 1.4.1, and 1.5.0, native transfers, arbitrary calls, ERC-20 transfers, call-only batches, Safe Transaction Builder imports, CREATE, CREATE2, rejection transactions, Safe Transaction Service proposal/confirmation, offline signature collection, and outbox execution.

## Install and policy

```sh
bloom petals install https://github.com/bloom-directory/bloom-petal-safe
bloom petals ls
```

The owner wallet policy must allow the Petal package and carry `{"chain": "evm-<chain id>", "destination": "exact"}` (Broker keys Safe signing by chain id, for example `evm-1` for Ethereum mainnet). The executor wallet policy must allow the Safe address as a destination on the chain's configured Bloom name, for example `{"chain": "ethereum", "destination": "0x<safe>"}`, because the outer `execTransaction` goes through Bloom's native outbox. It must also allow the Petal package, since the Petal stages that entry; if it does not, the first confirm opens a policy-update ceremony that adds it. To use a self-hosted Transaction Service, configure the Petal endpoint binding `transaction-service` to its HTTPS origin and store the same origin in the binding; it must serve `/api/v1/` at the root.

## Bind a Safe

Write this JSON to `petals/safe/safes/<wallet>/<safe-id>.json`:

```json
{
  "chain": "ethereum",
  "safe_address": "0x...",
  "transaction_service": "https://api.safe.global/tx-service/eth"
}
```

`transaction_service` is optional. Safe's hosted service is
`https://api.safe.global/tx-service/<slug>`, for example `eth`, `base`, `arb1`,
`oeth`, `gno` or `sep`. The old `safe-transaction-<network>.safe.global` hosts
now redirect there, and Bloom does not follow redirects to an undeclared host,
so bind the new base directly. Omit the field to collect signatures offline.

Bloom verifies code at the address, chain ID, singleton, `VERSION()`, owners, threshold, nonce, guard, all enabled modules (up to 64), and fallback handler. The Bloom wallet's account 0 EVM address (`wallets/<wallet>/0/address.evm`) must be a current owner. Read the same path to compare the bound configuration with current chain state.

Hosted Safe Transaction Service API keys are optional and write-only:

```text
petals/safe/service-keys/<wallet>/<safe-id>
```

The value is stored in the Petal's secret namespace. It cannot be read through VFS.

## Find what is already there

Every directory lists what it holds, so nothing has to be remembered outside
Bloom:

```text
petals/safe/safes/                       wallets holding a binding
petals/safe/safes/<wallet>/              <safe-id>.json per bound Safe
petals/safe/transactions/                wallets holding a transaction
petals/safe/transactions/<wallet>/       one directory per transaction id
petals/safe/service-keys/<wallet>/       Safes that have a service key set
```

A listing shows at most 1,024 names. The service-key listing projects record
names only. The stored key is never read back, there or anywhere else.

Reading `safes/<wallet>/<safe-id>.json` also returns `queue` and `history` for
that Safe: every transaction this wallet drafted against it, ordered by Safe
nonce, so two drafts competing for the same nonce are visible before either is
signed. `history_complete` is false when the wallet holds more transactions
than a listing returns or a record could not be read; `unreadable_transactions`
names the skipped records. `service_key_configured` is `null` when it could not
be determined.

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

## Read the plan

`.../<transaction-id>/plan.md` renders one drafted transaction: the decoded
action, the exact fields that get signed, how many signatures the threshold
still needs and from which owners, and the next step for the current phase.

It reads stored state only. The Safe configuration it shows is what was
recorded when the transaction was drafted, not a fresh observation, and the
file says so. `status.json` is the live view. Reading the plan starts no
ceremony and signs nothing: Broker's own reconstruction during the approval
ceremony, not this file, is what authorizes a signature.

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

The encoded `execTransaction` is staged in Bloom's native EVM outbox and requires the normal executor-wallet approval. Confirm that outbox entry as the executor wallet (`bloom wallet confirm <executor> <chain> <outbox_id>`, with `outbox_id` from `status.json`), then read `.../<transaction-id>/execute.json` until its `phase` is `executed` or `execution_failed` to reconcile it: Bloom scopes outbox inspection to the route that staged the entry, so only the execute route can observe the receipt. Every other read of the transaction returns the last reconciled state.

If the outer transaction reverts or fails, `execute.json` reads `execution_failed`. Write `execute.json` again to stage a new attempt; Bloom refuses it once the Safe nonce has moved.

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
