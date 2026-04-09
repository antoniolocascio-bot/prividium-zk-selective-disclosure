# Prividium ZK Selective Disclosure — Design

**Status:** draft v0. Not yet implemented.

## 1. Goal

Let the operator (or any party with access) of a Prividium (private ZKsync
rollup) produce a succinct zero-knowledge proof that attests to a specific,
well-defined fact about the chain state *at an L1-committed batch*, without
revealing any other state.

Concretely, the verifier of such a proof learns **only**:

- the statement type being disclosed;
- the public parameters of the statement (e.g. an address and a balance);
- the L1 batch commitment the statement is relative to.

The verifier learns **nothing** about any other accounts, transactions, or
state. The verifier's trust root is whatever L1 commitment the diamond proxy
contract exposes on the settlement layer, so the scheme inherits the security
of the rollup itself.

Out of scope for this design: proofs about history older than a single L1
batch's state commitment, aggregation of multiple disclosures into a single
proof, privacy of the prover (metadata-level). These are noted as
extensions in §11.

## 2. Statements

The initial scope is three statements. The common shape is:

```
statement_id : u32
public inputs: (batch_number, l1_commitment, <statement-specific fields>)
private inputs: witnesses needed to bind the public input to l1_commitment
```

Every statement's public input is bound into a single 256-bit commitment — the
guest program's committed output — so that a proof can only satisfy one
statement instance.

### 2.1 `balance_of`

> "At L1 batch `batch_number` (whose stored batch hash on L1 is
> `l1_commitment`), account `address` had base-token balance `balance`."

| Field | Type | Role |
|---|---|---|
| `batch_number` | `u64` | public |
| `l1_commitment` | `bytes32` | public |
| `address` | `address` (20 bytes) | public |
| `balance` | `u256` | public |

### 2.2 `observable_bytecode_hash`

> "At L1 batch `batch_number`, account `address` had deployed bytecode whose
> `keccak256` observable hash equals `observable_bytecode_hash`."

This is the hash external tools see via `eth_getCode` + `keccak256`, matching
Ethereum semantics (see `zksync-os/docs/system/io/io.md` §Storage model for
accounts, and `zksync-os-server/docs/src/design/state.md` §Bytecodes).

| Field | Type | Role |
|---|---|---|
| `batch_number` | `u64` | public |
| `l1_commitment` | `bytes32` | public |
| `address` | `address` | public |
| `observable_bytecode_hash` | `bytes32` | public |

A natural variant (future, not in v0) proves a full bytecode preimage rather
than its hash; this requires additionally streaming the bytecode into the
guest.

### 2.3 `tx_inclusion`

> "At L1 batch `batch_number`, the block with L2 number `block_number`
> (which lies in the last-256-blocks window committed by that batch's
> chain state commitment) contains a transaction with hash `tx_hash`."

| Field | Type | Role |
|---|---|---|
| `batch_number` | `u64` | public |
| `l1_commitment` | `bytes32` | public |
| `block_number` | `u64` | public |
| `tx_hash` | `bytes32` | public |

Notes:

- The ZKsync OS chain state commitment embeds a Blake2s hash of the last 256
  block hashes (see `zksync-os/docs/l1_integration.md`). So inclusion is only
  directly provable for blocks inside that 256-block window relative to the
  batch's tip. Older blocks would need chaining of multiple batch commitments
  via `parent_hash` walkback — deferred.
- `block_number` is derivable inside the guest from
  `state_commitment_preimage.block_number` (the batch tip `N`) and the
  private `selected_block_index` ∈ `[0, 255]`:
  `block_number = N - 255 + selected_block_index`. The bootloader orders the
  window oldest-first when it builds `last_256_block_hashes_blake`
  (`post_tx_op_proving_*_batch.rs`), so index 0 is `N-255` and index 255 is
  `N`. Exposing `block_number` is therefore free from a binding perspective:
  it is fully determined by the (already-bound) state commitment plus the
  private window index, and the guest commits to it in the public input.
- The ZKsync OS block header uses a Keccak256 *rolling* hash of all
  in-block tx hashes as `transactions_root` (see
  `basic_bootloader/src/bootloader/block_flow/zk/block_data.rs`
  `TransactionsRollingKeccakHasher`), not a Merkle trie. That means proving
  inclusion of a single tx requires knowing *all* tx hashes in that block in
  order, to replay the rolling hash. There is no cheaper path.

## 3. Trust root: the L1 commitment

The verifier's trust anchor is the L1 diamond proxy contract's
`storedBatchHash(batch_number)` mapping, which stores the keccak256 of
`StoredBatchInfo` for each committed batch. On ZKsync OS this is:

```solidity
struct StoredBatchInfo {
    uint64  batchNumber;
    bytes32 batchHash;                    // = chain_state_commitment (blake2s)
    uint64  indexRepeatedStorageChanges;  // always 0
    uint256 numberOfLayer1Txs;
    bytes32 priorityOperationsHash;
    bytes32 dependencyRootsRollingHash;
    bytes32 l2ToL1LogsRootHash;
    uint256 timestamp;                    // always 0
    bytes32 commitment;
}
```

where `batchHash` is the Blake2s `chain_state_commitment`:

```
chain_state_commitment = blake2s(
    state_root                          ||  // 32 bytes
    next_free_slot.to_be_bytes(8)       ||
    block_number.to_be_bytes(8)         ||
    last_256_block_hashes_blake         ||  // 32 bytes
    last_block_timestamp.to_be_bytes(8)
)
```

and `last_256_block_hashes_blake` is `blake2s(h[N-255] || h[N-254] || ... || h[N])`
where `N = block_number` is the last L2 block in the batch
(`post_tx_op_proving_*_batch.rs`).

Sources:

- `zksync-os/docs/l1_integration.md` §Block public input
- `zksync-os-server/docs/src/design/zks_getProof.md` §Tree Structure,
  §Verification
- `zksync-os/basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/post_tx_op_proving_singleblock_batch.rs`

## 4. Architecture

Three artifacts, matching the rough sketch from the task:

```
┌──────────────────────────────┐
│   prividium-sd-guest         │  airbender guest (riscv32, no_std)
│   single guest binary,       │  commits 32-byte public input
│   statement dispatched by    │  derived from statement_id + params.
│   leading statement_id tag   │
└──────────────┬───────────────┘
               │  airbender-host
┌──────────────┴───────────────┐
│   prividium-sd-prover        │  native Rust CLI
│   1. fetch witness from RPCs │    uses zks_getProof +
│   2. call guest via host     │    eth_getBlockByNumber +
│      SDK and generate proof  │    eth_getTransactionByHash + eth_call
│   3. package proof + public  │
│      metadata                │
└──────────────┬───────────────┘
               │
               │  .proof bundle ─────────┐
               │                         │
┌──────────────┴───────────────┐   ┌─────┴──────────────────────┐
│   prividium-sd-verifier      │   │ recipient of a disclosure  │
│   native Rust CLI            │◀──┤ wants to verify the claim  │
│   1. read proof bundle       │   │ is valid                   │
│   2. query L1 diamond proxy  │   └────────────────────────────┘
│   3. verify proof via        │
│      airbender-host          │
└──────────────────────────────┘
```

### 4.1 Guest program

- One airbender guest binary in `guest/`, depending on `airbender-sdk`.
- Reads a `StatementId` tag followed by the statement-specific witness.
- Dispatches on `StatementId`, runs the statement-specific verification logic,
  computes the public-input commitment, and returns it via the airbender
  `Commit` mechanism (8 `u32` words = 32 bytes in registers `x10..x17`).
- On any verification failure, calls `airbender::guest::exit_error()` rather
  than panicking, so the host's `ExecutionResult` cleanly reports failure.

One binary (not N binaries, one per statement) is chosen so that all
statements share a single verification key on the recipient side. The
`StatementId` tag is bound into the public input so a `balance_of` witness
cannot be substituted for a `tx_inclusion` proof and vice versa.

### 4.2 Prover host

- Native Rust CLI that takes (statement, parameters, RPC endpoints, batch
  number) as input, fetches the witness from the relevant sources, invokes
  the airbender host SDK to run + prove the guest, and writes a proof bundle.
- Two RPC endpoints are expected:
  1. A **ZKsync OS** JSON-RPC endpoint (for `zks_getProof`,
     `eth_getBlockByNumber`, `eth_getTransactionByHash`, etc.). This is the
     Prividium's private L2 RPC.
  2. An **L1** JSON-RPC endpoint for the settlement layer, to read the diamond
     proxy's `storedBatchHash(batch_number)` and recent `BlockCommit` events,
     so the prover can confirm it is producing a proof against the exact L1
     commitment the verifier will later fetch.

The prover does **not** trust either RPC: everything it fetches from them is
re-verified inside the guest program against the L1 commitment (the L2 RPC
can lie; the guest will reject). The L1 RPC is only used to sanity-check
the commitment in the prover's own output so it fails fast.

### 4.3 Verifier host

- Native Rust CLI that reads the proof bundle, reconstructs the expected 32-
  byte public-input commitment from `(statement_id, batch_number, l1_commitment,
  params)`, queries the L1 diamond proxy for
  `storedBatchHash(batch_number)`, asserts it matches `l1_commitment` in
  the bundle, and calls the airbender host SDK to verify the proof against
  that expected public input.
- The L1 RPC is the only external dependency of the verifier.

## 5. Public input format

The guest commits exactly 32 bytes as public output:

```
pub_input = keccak256(
    statement_id.to_be_bytes(4)     ||
    batch_number.to_be_bytes(8)     ||
    l1_commitment                   ||   // 32 bytes
    statement_params                      // statement-specific, fixed length
)
```

Packed into 8 `u32` words for the airbender receipt. `keccak256` is chosen
because the L1 commitment is itself a keccak256 hash and the verifier side is
native Rust (not on-chain), so Blake2s's prover-friendliness is not needed at
this boundary. Inside the guest we still use Blake2s for tree/state commitment
work because that is what ZKsync OS uses.

`statement_params` layouts:

| Statement | `statement_id` | `statement_params` (packed big-endian) |
|---|---|---|
| `BalanceOf` | `1` | `address[20] \|\| balance[32]` |
| `ObservableBytecodeHash` | `2` | `address[20] \|\| observable_bytecode_hash[32]` |
| `TxInclusion` | `3` | `block_number_be8[8] \|\| tx_hash[32]` |

Lengths are fixed per statement so there is no ambiguity and no need for a
length prefix; this also makes the verifier's reconstruction a simple
concatenation.

The statement ID space is a single `u32` managed in this repo. Adding a new
statement is an additive change and old proofs remain verifiable as long as
the guest binary / VK does not change.

## 6. Witnesses and in-guest verification logic

All three statements share the same L1-commitment re-derivation pipeline:

1. **Verify a Blake2s Merkle path** from a leaf in the ZKsync OS state tree
   up to a `state_root`.
2. **Hash the `state_root` with the `state_commitment_preimage`** (next free
   slot, block number, last-256 block hashes blake, last block timestamp)
   to get `chain_state_commitment`, i.e. ZKsync OS's `batchHash`.
3. **Reconstruct the on-chain `StoredBatchInfo`** from `chain_state_commitment`
   plus `l1_verification_data` (numberOfLayer1Txs, priorityOperationsHash,
   dependencyRootsRollingHash, l2ToL1LogsRootHash, commitment) with the two
   fixed-zero fields (`indexRepeatedStorageChanges`, `timestamp`), and
   abi-encode it.
4. **Keccak256 the abi-encoded struct** to obtain the *computed* L1
   commitment.
5. **Assert** the computed L1 commitment equals the public `l1_commitment`
   parameter. If not, `exit_error()`.

Steps 1–5 match the reference verification procedure in
`zksync-os-server/docs/src/design/zks_getProof.md` §Verification.

Each statement adds statement-specific logic on top:

### 6.1 `balance_of` witness

Private inputs:

- `account_properties_preimage`: 124 bytes, the ZKsync OS account
  encoding (see
  `basic_system/.../flat_storage_model/account_cache_entry.rs`).
- A `zks_getProof`-style Merkle proof for the tree slot at
  `key = blake2s(ACCOUNT_PROPERTIES_STORAGE_ADDRESS_padded32 || address_padded32)`,
  where `ACCOUNT_PROPERTIES_STORAGE_ADDRESS = 0x8003`. The proof's stored
  value is `blake2s(account_properties_preimage)`.
- `state_commitment_preimage` fields.
- `l1_verification_data` fields.

Guest logic:

1. Walk the Merkle proof → `state_root` and `stored_value`.
2. Check `stored_value == blake2s(account_properties_preimage)`.
3. Decode `account_properties_preimage` into `AccountProperties` (the 124-byte
   layout at `account_cache_entry.rs:112`).
4. Assert `decoded.balance == public.balance`.
5. Run steps 2–5 of §6 to verify the L1 commitment.
6. Commit `pub_input` (§5).

Non-existence case: if the account was never touched, `zks_getProof` returns
a `nonExisting` proof with left/right neighbors. The guest must handle this
by asserting `public.balance == 0` and validating the non-existence proof
per the reference verifier (left.nextIndex == right.index, left.leafKey <
flatKey < right.leafKey, both walks yield the same root).

### 6.2 `observable_bytecode_hash` witness

Same witness structure as §6.1 (the bytecode hash is a field of
`AccountProperties`). The statement-specific step is:

4'. Assert `decoded.observable_bytecode_hash == public.observable_bytecode_hash`.

Note on undeployed accounts: if `public.observable_bytecode_hash` is the
all-zeros hash, the proof may correspond to a non-existent account (handled
identically to §6.1 non-existence) *or* to an existing but codeless EOA.
Both are legitimate and must be accepted.

### 6.3 `tx_inclusion` witness

Private inputs:

- `state_commitment_preimage` (as in §6.1) — in particular, the
  `last_256_block_hashes_blake` and `block_number` (= batch tip `N`) fields
  are what we bind against.
- `block_hashes_window[256]`: the 256 raw `bytes32` block hashes whose
  Blake2s concatenation equals `last_256_block_hashes_blake`, *in the same
  order used by the bootloader* (oldest first: entry `i` is block `N-255+i`).
  The guest re-hashes them to check.
- `selected_block_index`: `u32` in `[0, 255]`, which of the 256 blocks the
  target tx is in. Private — the verifier receives only the derived
  `block_number`, not this index, though the two are trivially linked.
- `block_header`: the full RLP-encodable `BlockHeader` for
  `block_hashes_window[selected_block_index]` (see
  `basic_bootloader/src/bootloader/block_header.rs`). All fields.
- `block_tx_hashes`: the ordered list of every tx hash in that block.
- `tx_index`: `u32`, the position of `public.tx_hash` inside `block_tx_hashes`.
- `l1_verification_data` fields.

Guest logic:

1. Assert `selected_block_index < 256` and `tx_index < block_tx_hashes.len()`.
2. Blake2s over `block_hashes_window` and assert it equals
   `state_commitment_preimage.last_256_block_hashes_blake`.
3. Compute `derived_block_number =
   state_commitment_preimage.block_number - 255 + selected_block_index`
   (checked subtraction; also assert the batch tip is `≥ 255`, which holds
   for any chain past genesis warmup — alternatively clamp the window in
   the bootloader logic; note that for chains with fewer than 256 total
   blocks the oldest entries of the window are zero-padded, which the guest
   must handle gracefully). Assert `derived_block_number ==
   public.block_number`.
4. Hash the RLP-encoded `block_header` with keccak256; assert the result
   equals `block_hashes_window[selected_block_index]`. Assert
   `block_header.number == derived_block_number` as a belt-and-braces check
   against a malicious bootloader window construction (the block hash
   binding above should already enforce this, but checking the RLP-decoded
   number costs nothing).
5. Replay the `TransactionsRollingKeccakHasher` starting from the empty-keccak
   constant `0xc5d2...a470`, folding `block_tx_hashes` in order. Assert the
   final rolling hash equals `block_header.transactions_root`.
6. Assert `block_tx_hashes[tx_index] == public.tx_hash`.
7. Rebuild the `chain_state_commitment` from `state_commitment_preimage` and
   continue with §6 steps 3–5 using `l1_verification_data`. *Note*: for this
   statement, the Merkle-proof step of §6.1 is not needed — the `state_root`
   field of `state_commitment_preimage` is unverified on its own but is bound
   into the L1 commitment, so an attacker who wants to forge the statement
   must already know a valid `state_commitment_preimage`, and that preimage
   is fixed by the L1 commitment via the Blake2s.
8. Commit `pub_input`.

The public `block_number` is therefore the unique value for which there
exists a valid `selected_block_index` satisfying both the window-hash check
(step 2) and the header-hash check (step 4), given the L1 commitment. A
malicious prover cannot detach `block_number` from the actual L2 block it
points at without breaking either Blake2s or Keccak256.

### 6.4 What about Merkle proof size?

ZKsync OS trees have a logical depth of 64 with empty-subtree compression
(see `zks_getProof.md` §Siblings). For sparse Prividium state at early
blocks, the effective Merkle path is short; for mature chains, the upper
bound is 64 Blake2s compressions per proof, plus a non-existence proof
doubles that. This is well within the proving budget of a single airbender
run.

Blake2s inside the guest should use the crypto-feature Blake2s primitive
from `airbender-sdk` to get the prover-accelerated path, rather than a
generic-Rust implementation.

## 7. Data sources (prover-side)

The prover host fetches:

| Data | Source | Notes |
|---|---|---|
| `zks_getProof(address, keys, batch_number)` | ZKsync OS L2 RPC | For `balance_of` and `observable_bytecode_hash`. See `zksync-os-server/docs/src/design/zks_getProof.md`. |
| Account properties preimage | ZKsync OS L2 RPC | ZKsync OS stores account properties as *preimages* keyed by their blake2s hash, accessible via a preimage-lookup RPC. The exact RPC name needs to be pinned down (likely `zks_getAccountProperties` or similar — TBD in §12). |
| `eth_getBlockByNumber(batch_last_block, true)` and 255 predecessors | ZKsync OS L2 RPC | For `tx_inclusion`: to get the 256 block-hash window and each block's ordered tx hash list. 256 block fetches is manageable; the prover can parallelize. |
| Block header fields for the target block | ZKsync OS L2 RPC | Needs every field that goes into the RLP encoding (see `basic_bootloader/.../block_header.rs:122`). |
| `storedBatchHash(batch_number)` on the diamond proxy | L1 RPC | Read-only `eth_call`. Used by prover for sanity-check, used by verifier as source of truth. |

The prover host does not trust the L2 RPC: it only uses the RPC data to
assemble witnesses that the guest re-verifies against the (L1-sourced)
commitment. The L1 RPC is trusted to correctly report the diamond proxy's
storage, which is the same trust assumption as for any ZKsync OS client.

## 8. Verifier flow

Pseudocode:

```
input:
  proof_bundle := {
      statement_id,
      batch_number,
      l1_commitment,        // what the prover claims
      statement_params,     // plaintext
      proof                 // airbender proof bytes
  }
  l1_rpc_url
  expected_vk               // committed / shipped with this tool version

steps:
  1. onchain_l1_commitment := eth_call(
         diamond_proxy,
         "storedBatchHash(uint64)",
         batch_number
     )
  2. require onchain_l1_commitment == bundle.l1_commitment
  3. expected_pi := keccak256(
         bundle.statement_id.to_be_bytes(4)   ||
         bundle.batch_number.to_be_bytes(8)   ||
         bundle.l1_commitment                 ||
         encode_params(bundle.statement_id, bundle.statement_params)
     )
  4. airbender_host::verify(bundle.proof, expected_vk, expected_pi)?
  5. print "OK: <statement human-readable>"
```

Step 2 guarantees the proof is bound to state that is actually committed on
L1 (and still committed — the diamond proxy keeps historical
`storedBatchHash` entries as described in `zks_getProof.md`). Step 4 binds
the guest VK to the specific statement dispatch logic.

## 9. Security considerations

- **Trust anchor is L1 only.** The L2 RPC can be fully malicious; it can only
  make the prover fail, never forge a valid proof, because the guest re-
  derives `l1_commitment` from the witness and compares to the public input.
- **Binding statements to IDs.** The `statement_id` tag is mixed into the
  keccak256 commitment before everything else, so two statements with
  identical trailing parameters cannot be confused.
- **Fixed-length parameter encoding.** Because each statement has a fixed
  parameter length, there is no length-extension / ambiguity attack across
  statement boundaries.
- **Non-existence proofs.** Both `balance_of` and `observable_bytecode_hash`
  must accept the `nonExisting` proof form from `zks_getProof` and verify
  the usual left-neighbor/right-neighbor conditions. A buggy acceptance
  would let a prover claim arbitrary values for any uninitialized slot.
- **Tx rolling-hash replay.** For `tx_inclusion`, the guest must replay the
  rolling hash strictly from the canonical starting seed
  `keccak256(empty) = 0xc5d2...a470`, matching
  `TransactionsRollingKeccakHasher::empty()`.
- **Block-header RLP.** The `BlockHeader::hash` encoding in
  `basic_bootloader/.../block_header.rs:122` is the authoritative serializer.
  The guest's implementation must be byte-for-byte identical. Any drift
  (field order, number encoding, empty-ommer constant) will break inclusion
  proofs or, worse, let mismatched headers verify. A conformance test
  against the ZKsync OS bootloader's own `hash()` output is required.
- **Underconstraint of `state_root` in `tx_inclusion`.** Because
  `tx_inclusion` does not touch any tree leaf, the full 32-byte
  `state_root` field in `state_commitment_preimage` is not independently
  verified inside the guest — it only gets baked into the blake2s/keccak
  funnel. This is fine: to produce a valid commitment-match, the prover
  must know the real `state_root`, which is the same one the L1 diamond
  proxy is committing to. No soundness loss, just worth documenting.
- **Replay across chains.** Nothing in the current public-input design
  binds the chain id. Two Prividium deployments with the same batch
  numbers could in principle share the same `l1_commitment` (they would
  not in practice, because each deployment has its own diamond proxy),
  but the verifier already queries a specific diamond proxy address, so
  cross-chain replay is prevented by the verifier's L1 RPC step. If we
  later support serving bundles where the proxy address is itself
  untrusted, we must add the chain id and/or proxy address to the
  public input. Noted as an open item.

## 10. What the guest does NOT commit to

- Any other account balance / state.
- Any other tx in the same block (neither their hashes nor their count,
  beyond the length of `block_tx_hashes` which is not hashed into the
  public input — only the final rolling hash is observed).
- Any pubdata, logs, or messaging information.
- The prover's identity or network location.
- The position of the disclosed tx within its block (`tx_index`), even
  though `block_number` itself is disclosed.

## 11. Out-of-scope extensions (possible future statements)

- `tx_inclusion_hiding_block` (variant that suppresses `block_number`
  from the public input, if a use case arises where the disclosing party
  does not want to reveal which block within the 256-window the tx is in).
- `nonce_of`, `storage_slot_value` — trivial variants reusing the §6.1
  skeleton.
- `event_emitted` — needs an L2→L1 log Merkle proof (different tree,
  `l2ToL1LogsRootHash` in `StoredBatchInfo`).
- Older-than-256-blocks proofs via chained batch commitments.
- Proof aggregation: multiple statements in one proof via a composite guest.
- Full-bytecode disclosure rather than just the observable hash.

Explicitly *not* possible against a single L1 commitment:

- `balance_of_at_block` (and any other intra-batch, block-level state query).
  ZKsync OS only commits the post-batch state tree to L1; individual block
  headers inside a batch have `state_root` hardcoded to `Bytes32::ZERO`
  (`basic_bootloader/src/bootloader/block_header.rs:99`), so there is no
  L1-rooted way to recover a per-block state root. The finest granularity
  available is "state as of some committed batch". Proving balances/state
  at a specific *block* inside a batch would require either a protocol
  change (populating `BlockHeader.state_root`) or an auxiliary commitment
  scheme outside the current L1 flow, and is therefore excluded from this
  tool's scope.

## 12. Open questions

1. **Exact RPC for the account-properties preimage.** `zks_getProof` returns
   the tree-level value (the blake2s hash of `AccountProperties`) but not
   the preimage itself. We need to confirm the ZKsync OS server exposes a
   preimage lookup (or bundles it into the `zks_getProof` response) and
   pin down the method name / shape. If no such method exists we will
   need to add one before the prover host can be built.
2. **Block-header field availability over RPC.** Some `BlockHeader` fields
   (e.g. `mix_hash`, `beneficiary`, `base_fee_per_gas`) must be recovered
   exactly from RPC responses to reconstruct the keccak. Need to confirm
   `eth_getBlockByNumber(_, true)` returns them in the form we need,
   otherwise we need a ZKsync OS-specific RPC.
3. **Diamond-proxy address and chain id in the public input.** As noted in
   §9, leaving these out only works as long as the verifier is hard-wired
   to a specific proxy. Decide whether to bind them into the pub input now
   (adds 32 bytes of packed data) or defer.
4. **Prover / verifier bundle format.** JSON vs. postcard vs. airbender
   codec. Probably postcard with a versioned envelope.
5. **Airbender backend.** v0 should use `dev_prover` / `dev_verifier` for
   iteration speed. For a real deployment, the host must switch to
   `gpu_prover` + `real_verifier` with a recursion level consistent with
   how the proof will be consumed.
6. **Merkle path decoder compatibility.** `zks_getProof`'s JSON proof shape
   must be decoded into whatever in-guest proof representation we pick.
   Since the guest is `no_std`, we will want a simple binary witness
   format that the prover host translates into, rather than decoding JSON
   inside the guest.
7. **Observable-bytecode-hash for EOAs.** Confirm that EOAs and
   never-deployed addresses both yield `observable_bytecode_hash =
   keccak256("") = 0xc5d2...a470` on-chain in ZKsync OS, and not the
   zero hash. The account-properties layout at
   `account_cache_entry.rs:130-134` suggests `TRIVIAL_VALUE` uses
   `Bytes32::ZERO`, which is inconsistent with Ethereum semantics for
   `eth_getCode` on EOAs. We need to check how `eth_getCode` / code
   introspection works on Prividium before finalizing §6.2.

## 13. Repository layout (post-implementation)

```
prividium-zk-selective-disclosure/
├── DESIGN.md                    # this file
├── guest/                       # airbender guest, statement dispatcher
│   └── src/
│       ├── main.rs              # entry + dispatch
│       ├── pub_input.rs         # keccak256 commitment over (id||batch||l1||params)
│       ├── l1_commitment.rs     # shared state-commitment + StoredBatchInfo re-derivation
│       ├── tree.rs              # Blake2s Merkle proof verifier (existing + non-existing)
│       ├── account_properties.rs # 124-byte AccountProperties decoder
│       ├── block_header.rs      # RLP encoder for ZKsync OS BlockHeader
│       └── statements/
│           ├── balance_of.rs
│           ├── observable_bytecode_hash.rs
│           └── tx_inclusion.rs
├── host-prover/                 # native CLI, fetches witness, calls airbender-host
│   └── src/
│       ├── main.rs
│       ├── rpc_l2.rs            # zks_getProof, eth_getBlockByNumber, ...
│       ├── rpc_l1.rs            # storedBatchHash via ethers/alloy
│       └── witness/
│           ├── balance_of.rs
│           ├── observable_bytecode_hash.rs
│           └── tx_inclusion.rs
├── host-verifier/               # native CLI
│   └── src/
│       ├── main.rs
│       └── rpc_l1.rs            # storedBatchHash query
├── shared/                      # types shared between guest and both hosts
│   └── src/
│       ├── statement_id.rs
│       ├── params.rs            # fixed-layout public-parameter structs
│       └── witness.rs           # witness binary encoding (prover → guest)
└── host/                        # the existing dummy scaffold (will be replaced)
```

`shared/` is a separate crate so the prover and verifier can depend on it
without pulling in `airbender-sdk` (guest-only) or `airbender-host` (host-
only) transitively.
