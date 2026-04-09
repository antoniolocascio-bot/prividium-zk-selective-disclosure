# Implementation Plan — guest-first, RPC-free

Goal for this plan: implement the airbender guest program from `DESIGN.md`
(all three statements) and get it to a state where it can be end-to-end
exercised (run + prove + verify) from native Rust **without** depending on
any live L1 or L2 RPCs. RPC clients for the prover/verifier hosts are
deferred.

The plan is sequenced so that each phase produces something runnable and
testable before the next phase starts.

## Guiding principles

1. **All logic lives in a shared `no_std` core crate.** The guest is a thin
   shim that reads witness bytes, dispatches on `StatementId`, and calls
   into core. This means every primitive can be unit-tested natively
   (fast), and the airbender integration tests only have to confirm that
   the same code behaves identically inside the RISC-V VM.
2. **No two implementations of the same primitive.** The native test
   fixtures that build synthetic witnesses use the exact same core crate
   to compute Blake2s, Keccak256, RLP encodings, StoredBatchInfo hashes,
   etc. If the fixture builder produces a witness, the guest will accept
   it by construction (modulo real bugs we want tests to catch).
3. **Cryptography via RustCrypto for v0.** `blake2` + `sha3` crates in
   `no_std` mode compile for both native and `riscv32im-risc0-zkvm-elf`.
   They will be slow in proving but are fine for bring-up. A future
   `accelerated` feature flag can swap in `airbender-sdk`'s accelerated
   primitives for the guest build once the logic is stable.
4. **Witnesses are binary, fixed-layout, and defined in the core crate.**
   Not JSON. Not serde on unknown types. The prover host (later) will be
   responsible for translating RPC JSON into this binary format; the
   guest never sees RPC structures.
5. **Each phase lands with a green test.** No phase is "done" until the
   test it introduces passes.

## Proposed repository layout

```
prividium-zk-selective-disclosure/
├── DESIGN.md
├── PLAN.md                      # this file
├── rust-toolchain.toml
├── core/                        # no_std crate, shared by guest + tests
│   ├── Cargo.toml               # deps: blake2, sha3, serde (derive), thiserror-no-std or manual
│   └── src/
│       ├── lib.rs
│       ├── statement_id.rs
│       ├── params.rs            # fixed-layout public params per statement
│       ├── pub_input.rs         # keccak256(id || batch || l1 || params) → [u8; 32]
│       ├── hash.rs              # thin wrappers over blake2 / sha3
│       ├── state_commitment.rs  # ChainStateCommitment + blake2s derivation
│       ├── stored_batch_info.rs # abi.encode + keccak256 → l1_commitment
│       ├── tree/
│       │   ├── mod.rs           # re-exports
│       │   ├── empty.rs         # emptyHash[i] precomputation
│       │   ├── merkle.rs        # verifyExisting / verifyNonExisting
│       │   └── key.rs           # flat-key derivation (blake2s(addr_pad32 || key))
│       ├── account_properties.rs # 124-byte decoder + compute_hash
│       ├── block_header.rs      # fields + RLP encoder + keccak256
│       ├── tx_rolling_hash.rs   # Keccak rolling replay
│       ├── witness.rs           # binary witness encoding / decoding (per statement)
│       └── statements/
│           ├── mod.rs
│           ├── balance_of.rs
│           ├── observable_bytecode_hash.rs
│           └── tx_inclusion.rs
├── guest/                       # airbender riscv32 binary, thin dispatcher
│   └── src/main.rs
├── test-fixtures/               # std, dev-only crate
│   ├── Cargo.toml               # deps: core, rand, etc.
│   └── src/
│       ├── lib.rs
│       ├── mock_tree.rs         # build a mock ZKsync OS state tree + proofs
│       ├── mock_block.rs        # build synthetic blocks + windows
│       └── scenarios.rs         # canned end-to-end scenarios per statement
└── host/                        # currently dummy; becomes integration test runner
    ├── Cargo.toml
    ├── src/main.rs              # tiny CLI for manual invocation of a scenario
    └── tests/
        ├── balance_of.rs
        ├── observable_bytecode_hash.rs
        └── tx_inclusion.rs
```

No `host-prover` or `host-verifier` yet — those come after the guest is
solid.

## Phase 0 — scaffolding

Deliverable: the new crate layout compiles, the existing dummy guest still
runs via airbender-host, and `cargo test -p zksd-core` runs zero tests
successfully.

Tasks:

0.1. Add `core/` crate with `Cargo.toml` and empty `lib.rs`. `no_std`,
     `alloc` feature, `serde`/`blake2`/`sha3` dependencies. Name the crate
     something like `zksd-core` (internal).
0.2. Add `test-fixtures/` crate with `Cargo.toml` depending on
     `zksd-core`. `std` enabled. Empty `lib.rs`.
0.3. Update `guest/Cargo.toml` to depend on `zksd-core` via relative path.
     Do not yet call into it; the existing `n + 1` dummy stays in place.
0.4. Update root `rust-toolchain.toml` if needed. Verify
     `cargo check` in `core/`, `test-fixtures/`, `guest/` (RISC-V), and
     `host/` all succeed.

Checkpoint: `cargo check --workspace` equivalent green. Guest still runs.

## Phase 1 — core primitives (no statement logic yet)

Deliverable: every cryptographic + encoding primitive needed by any
statement, with native unit tests.

Tasks (can land as several commits):

1.1. **`hash.rs`** — `blake2s_256(input: &[u8]) -> [u8; 32]` and
     `keccak256(input: &[u8]) -> [u8; 32]` thin wrappers. Also streaming
     versions (`Blake2sHasher::new().update(..).finalize()` pattern) for
     incremental hashing (needed by `account_properties::compute_hash`
     and the block-window hash).
1.2. **Empty-subtree hashes** — deferred unless we actually need them.
     Because `TestingTree::get_proof_for_position` fills trailing
     sibling entries with `empty_hashes[..]` before returning the
     proof, our verifier only ever sees a fully-populated 64-entry
     path and does not have to reconstruct empty-subtree hashes
     itself. If a future data source (e.g. a real `zks_getProof`
     response) gives us compressed proofs, we'll add an empty-hash
     table then.
1.3. **`tree/key.rs`** — `flat_key(address: [u8; 20], storage_key: [u8; 32])
     -> [u8; 32]` = `blake2s(zero_pad_left_20_to_32(address) || storage_key)`.
     Unit test against a hand-computed fixture.
1.4. **`tree/merkle.rs`** — types mirroring
     `basic_system::FlatStorageLeaf` and `basic_system::LeafProof` so
     translation from the `TestingTree` output is a field-by-field copy:
     ```rust
     pub struct FlatStorageLeaf {
         pub key: [u8; 32],
         pub value: [u8; 32],
         pub next: u64,
     }
     pub struct LeafProof {
         pub index: u64,
         pub leaf: FlatStorageLeaf,
         pub path: Box<[[u8; 32]; 64]>, // uncompressed, matches TestingTree
     }
     pub enum AccountMerkleProof {
         Existing(LeafProof),
         NonExisting { left: LeafProof, right: LeafProof },
     }
     ```
     Leaf hashing per `zks_getProof.md`:
     `blake2s(key || value || next.to_le_bytes(8))` — note the `next`
     field is **little-endian**, matching
     `FlatStorageLeaf::update_digest` in `simple_growable_storage.rs:99`.
     Verifier entry points:
     `recompute_root(proof: &LeafProof) -> [u8; 32]` and
     `verify_account_proof(proof: &AccountMerkleProof, flat_key: &[u8; 32])
     -> Result<([u8; 32], [u8; 32]), Error>` returning `(state_root,
     value)` (value = `[0u8; 32]` in the non-existing case, and with
     the usual `left.next == right.index` and `left.key < flat_key <
     right.key` assertions per the reference verifier). Walks the full
     64-entry `path` array directly, no empty-subtree padding logic
     needed — `TestingTree::get_proof_for_position` already filled
     trailing empty-subtree entries for us, and the guest just walks
     whatever it's given.
1.5. **`account_properties.rs`** — mirror the 124-byte layout from
     `basic_system/.../account_cache_entry.rs:112-121`. Decoder,
     encoder, `compute_hash(&self) -> [u8; 32]` via streaming blake2s.
     Unit test: encode/decode round trip + `compute_hash` stability
     against a vector copied from the ZKsync OS unit tests.
1.6. **`state_commitment.rs`** — `ChainStateCommitment { state_root,
     next_free_slot, block_number, last_256_block_hashes_blake,
     last_block_timestamp }` with a `compute()` method matching
     `zks_getProof.md` §verification (`blake2s(state_root ||
     next_free_slot_be8 || block_number_be8 || blob || ts_be8)`).
1.7. **`stored_batch_info.rs`** — `StoredBatchInfo { batch_number,
     batch_hash, number_of_layer1_txs, priority_operations_hash,
     dependency_roots_rolling_hash, l2_to_l1_logs_root_hash, commitment }`
     with a `compute_l1_commitment() -> [u8; 32]` that does an
     **in-crate** ABI encoder (no ethers/alloy — they are heavy and
     not no_std). The encoding is fixed and trivial: seven 32-byte
     words in order, with `indexRepeatedStorageChanges = 0` and
     `timestamp = 0` inlined. Cross-check: unit test that encodes a
     fixture and compares to a known keccak from ZKsync OS tests or
     a one-off ethers-based helper run natively.
1.8. **`block_header.rs`** — struct mirroring
     `basic_bootloader/.../block_header.rs:22`. `hash()` implementation
     must byte-match the bootloader's. Strategy: port the existing RLP
     helpers from the bootloader (`rlp::estimate_bytes_encoding_len`,
     `apply_*_encoding_to_hash`) into `core/` verbatim, or vendor the
     module. Test with a hand-constructed header whose expected keccak
     is taken from a ZKsync OS unit test (search the codebase for
     existing header hash fixtures; if none, compute one natively with
     a spin-up of the bootloader in a dev test). This is the trickiest
     primitive — any off-by-one here silently invalidates
     `tx_inclusion`.
1.9. **`tx_rolling_hash.rs`** — `pub struct TxRollingHasher { state:
     [u8; 32] }` starting at `0xc5d246…a470`, `push(tx_hash: &[u8; 32])`
     updates `state = keccak256(state || tx_hash)`, `finalize(self) ->
     [u8; 32]` returns `state`. Unit test against a two-tx fixture
     derived from the ZKsync OS test at
     `block_data.rs:173 rolling_keccak_count_increases_on_add_tx_hash`.
1.10. **`pub_input.rs`** — `pub_input(statement_id: u32, batch_number:
      u64, l1_commitment: &[u8; 32], params: &[u8]) -> [u8; 32]` = the
      keccak256 of their big-endian concatenation. Unit tests for each
      statement's layout with a hand-computed hash.
1.11. **`statement_id.rs`** — `enum StatementId { BalanceOf = 1,
      ObservableBytecodeHash = 2, TxInclusion = 3 }` with
      `TryFrom<u32>` and a serde helper.
1.12. **`params.rs`** — fixed-layout param structs and
      `to_bytes(&self) -> Vec<u8>` for each (address || balance, etc.).

Checkpoint: `cargo test -p zksd-core` green with unit tests for every
primitive above. Nothing else depends on this yet.

## Phase 2 — test fixtures

Deliverable: a native helper that, given a logical scenario ("account A
has balance X at batch B"), produces a fully valid witness blob that the
guest will accept — without touching any network.

Tasks:

2.1. **`test-fixtures/mock_tree.rs`** — a thin wrapper around
     `basic_system::system_implementation::flat_storage_model::TestingTree`
     (`TESTING_TREE_HEIGHT = 64`, `Blake2sStorageHasher`, `RANDOMIZED =
     false`). This is the same type the ZKsync OS `forward_system` tests
     (`forward_system/src/run/test_impl/tree.rs`) use to stand up an
     in-memory state tree with fully-computed hashes and Merkle proofs,
     so every fixture we produce is byte-identical to what the real
     server would emit for the same inputs — no risk of a hand-rolled
     mock drifting from the reference implementation.

     The wrapper's job is narrow:
     - `insert_account(address, AccountProperties)` — computes the
       flat key `blake2s(0x8003_padded32 || address_padded32)`, hashes
       the encoded 124-byte account properties with Blake2s, and
       inserts `(flat_key, account_hash)` via `TestingTree::insert`.
     - `insert_raw(key, value)` — pass-through for non-account slots.
     - `account_proof(address) -> AccountMerkleProof` — builds the
       `AccountMerkleProof` our core crate expects, using
       `TestingTree::get` (which already returns the right `Existing`
       / `NonExisting` split) and a translation step from
       `basic_system::LeafProof<64, Blake2sStorageHasher>` →
       `zksd_core::tree::LeafProof`. The translation is a field-by-field
       copy: both types carry `index: u64`, `leaf: { key, value, next }`,
       `path: [Bytes32; 64]`.
     - `root() / next_free_slot()` — forwarded to the underlying
       `TestingTree`; used by scenarios to build a
       `ChainStateCommitment`.

     This keeps `basic_system` (and its whole transitive dep chain) out
     of `zksd-core` and out of the guest build — only `test-fixtures/`
     pays that compile cost, and only for `std` dev builds.
2.2. **`test-fixtures/mock_block.rs`** — helpers to:
     - build a `BlockHeader` with arbitrary tx list,
     - compute its hash via `core::block_header::hash`,
     - build a sliding window of `N` block headers where block `k`'s
       `parent_hash` = hash of block `k-1`,
     - take the last 256 (or pad if fewer exist) and produce the
       `last_256_block_hashes_blake`.
2.3. **`test-fixtures/scenarios.rs`** — one function per statement that
     returns `(StatementId, public_params, l1_commitment, witness_bytes,
     expected_pub_input)`:
     - `balance_of_scenario(address, balance) -> Scenario`
     - `observable_bytecode_hash_scenario(address, code) -> Scenario`
     - `tx_inclusion_scenario(block_number, tx_hash, other_txs) -> Scenario`
     Each scenario internally:
     1. builds a `MockStateTree` containing one or a few accounts,
     2. constructs a `ChainStateCommitment`,
     3. wraps it into a `StoredBatchInfo`, computes `l1_commitment`,
     4. builds the witness struct,
     5. serializes the witness to bytes (the same format the guest
        will read),
     6. computes `expected_pub_input` via `core::pub_input`.
2.4. Native smoke tests: each scenario, when its `witness_bytes` is
     passed to the corresponding `core::statements::X::verify(...)`
     function (which we'll add in phase 3), returns
     `Ok(expected_pub_input)`.

Checkpoint: phase 3's statement logic has a ready-made test oracle.

## Phase 3 — statement verifiers (native-only first)

Deliverable: each of the three statement verification functions, runnable
natively via `cargo test -p zksd-core`, using `test-fixtures` scenarios.
Still no airbender involvement.

Tasks:

3.1. **`core::witness` encoding** — a small hand-written binary format
     per statement, read by a `ByteReader` struct. No serde yet:
     explicit `read_u32_be`, `read_u64_be`, `read_bytes32`, `read_vec`
     (length-prefixed). Keeping it hand-rolled avoids pulling
     serde_bytes / bincode into the guest and makes the format
     trivially auditable. The shape is:
     ```
     BalanceOfWitness {
         public: BalanceOfParams,
         state_commitment_preimage: ChainStateCommitment,
         stored_batch_info_rest: StoredBatchInfoRest, // the 5 fields not derived
         account_proof: AccountMerkleProof,
         account_properties_preimage: [u8; 124],
     }
     AccountMerkleProof = Existing(ExistingLeaf) | NonExisting(NonExistingProof)
     ObservableBytecodeHashWitness { ... same as BalanceOf with different public params }
     TxInclusionWitness {
         public: TxInclusionParams,
         state_commitment_preimage: ChainStateCommitment,
         stored_batch_info_rest: StoredBatchInfoRest,
         block_hashes_window: [[u8; 32]; 256],
         selected_block_index: u32,
         block_header: BlockHeader,
         block_tx_hashes: Vec<[u8; 32]>,
         tx_index: u32,
     }
     ```
     Encoder + decoder live in `core/` so both the guest and the
     fixture builder use them.
3.2. **`core::statements::balance_of::verify(bytes: &[u8]) -> Result<
     [u8; 32], Error>`** — decodes the witness, runs the logic in
     DESIGN.md §6.1, returns the `pub_input` on success. Unit test
     uses `test-fixtures::scenarios::balance_of_scenario` for happy
     path plus tamper tests (wrong balance, wrong state root, wrong
     l1 commitment — each must return `Err`).
3.3. **`core::statements::observable_bytecode_hash::verify`** — same
     skeleton, check the observable_bytecode_hash field instead of
     balance.
3.4. **`core::statements::tx_inclusion::verify`** — per DESIGN.md §6.3.
     Tests: happy path, wrong tx_hash, wrong block_number, wrong
     selected_block_index, wrong window hash, out-of-window
     `tx_index`.
3.5. A shared dispatcher `core::statements::verify(statement_id,
     bytes) -> Result<[u8; 32], Error>` that will be called from the
     guest.

Checkpoint: `cargo test -p zksd-core` runs native verification for all
three statements with positive and negative cases. No riscv target
touched yet.

## Phase 4 — guest wiring

Deliverable: the guest binary compiles, dispatches `StatementId` →
`core::statements::verify` → commits the returned 32 bytes as output,
and a single host-side integration test runs it successfully via
`airbender-host`.

Tasks:

4.1. **Guest `main.rs`** — replace the dummy with:
     ```rust
     #![no_std]
     #![no_main]
     use airbender::guest::{read, commit, exit_error};
     use zksd_core::{StatementId, statements};

     #[airbender::main]
     fn main() {
         let id_raw: u32 = match read() { Ok(v) => v, Err(_) => exit_error() };
         let id = match StatementId::try_from(id_raw) {
             Ok(id) => id, Err(_) => exit_error(),
         };
         let witness: alloc::vec::Vec<u8> = match read() {
             Ok(v) => v, Err(_) => exit_error(),
         };
         let pub_input = match statements::verify(id, &witness) {
             Ok(h) => h, Err(_) => exit_error(),
         };
         commit(PubInput(pub_input)); // custom Commit impl packing [u8; 32] → [u32; 8]
     }
     ```
     With a local `PubInput([u8; 32])` implementing `airbender::guest::Commit`.
4.2. Confirm `zksd-core` compiles for `riscv32im-risc0-zkvm-elf` (all
     deps are `no_std`-clean; RustCrypto `blake2` / `sha3` do this
     fine but their `simd` features must be off). May need to gate
     `std` off explicitly in `core/Cargo.toml`. Unit tests in `core/`
     should still work on the host because they run in native Rust.
4.3. **Integration test — balance_of** in `host/tests/balance_of.rs`:
     - build the scenario via `test-fixtures`,
     - push `(StatementId as u32, witness_bytes)` to the guest via
       `Inputs::push`,
     - run via `Program::transpiler_runner`,
     - assert `execution.receipt.output` equals the 8-word packing of
       `expected_pub_input`.
     - One positive test, one negative (tampered balance → expect
       `execution.reached_end == false` or a non-success receipt).
4.4. Verify `cargo test -p prividium-sd-host --release` runs the
     integration test green. This requires `cargo airbender build` to
     have been run for the guest first; the test harness should
     automate that (either a `build.rs` in `host/` that shells out to
     `cargo-airbender`, or a `just`/`make` target — decide when we
     get there; simplest is to require running `cargo airbender
     build` manually before the test, and document it).
4.5. Add the same integration test for `observable_bytecode_hash` and
     `tx_inclusion`. Both should "just work" given the core crate is
     already tested.
4.6. Optional but cheap: also run the scenarios through
     `program.dev_prover().build()?.prove(...)` and
     `dev_verifier().verify(...)` to confirm the full prove+verify
     round-trip works against the same expected `pub_input`. This
     doubles the runtime of the test suite but gives strong confidence
     the guest is "real".

Checkpoint: `cargo test -p prividium-sd-host` runs all three statements
end to end through the airbender transpiler (and optionally dev
prover/verifier), entirely from fixtures, no network.

## Phase 5 — cleanup + docs

Tasks:

5.1. Update `README.md` with the new layout, the build commands
     (`cargo airbender build` in `guest/` then `cargo test` in
     `host/`), and a note that `prividium-sd-prover` /
     `prividium-sd-verifier` (with RPC fetching) are deferred.
5.2. Write a short `core/README.md` documenting the witness binary
     format per statement — useful as a reference for the prover
     host that will translate RPC responses into these bytes later.
5.3. Audit for any `unwrap`/`expect` on paths reachable from untrusted
     witness bytes in `core/`. All decode failures must return
     `Err(WitnessError::...)` so the guest can `exit_error()` cleanly
     rather than panicking and burning cycles.
5.4. Bump the dummy `.gitignore` / `Cargo.lock` handling if needed.

Checkpoint: someone cloning the repo can run the full test suite from
a clean checkout with documented commands and no external state.

## Risk log (things most likely to bite)

| Risk | Phase | Mitigation |
|---|---|---|
| `BlockHeader` RLP encoding drifts from the bootloader's, silently accepting malformed headers. | 1.8 | Port the bootloader's RLP helpers verbatim; add a conformance test that compares `core::block_header::hash(h)` against a hash captured from a ZKsync OS bootloader test fixture for a header with non-trivial `extra_data` and `base_fee_per_gas`. |
| `AccountProperties` encoding or hash disagrees with `account_cache_entry.rs`. | 1.5 | Direct unit-test vector from `account_cache_entry.rs` tests. |
| `StoredBatchInfo` ABI encoding layout off-by-one (tuple word ordering). | 1.7 | Cross-check one fixture against a native ethers/alloy ABI encoding run (the dep can stay out of `core/` and live only in a test-fixtures dev-dependency). |
| Empty-subtree hash table off-by-one (64 vs 63 entries, leaf level vs root). | 1.2 | Match the spec in `zks_getProof.md` §Siblings literally; test both the compressed and uncompressed paths. |
| `last_256_block_hashes_blake` endianness / ordering. | 2.2, 3.4 | Ordering is oldest-first, plain concatenation of 32-byte values (see `post_tx_op_proving_singleblock_batch.rs:137-145`). Test both the "full 256 window" and "chain with fewer than 256 total blocks" cases. Decide on the padding convention for the early-chain case by reading the bootloader. |
| RustCrypto `blake2` / `sha3` fail to compile for riscv32 with the required features. | 4.2 | Ensure `default-features = false` on both deps; smoke-test as soon as phase 0 lands so we fail fast if we need a different crate. |
| Guest binary grows past airbender's default cycle limit on `tx_inclusion` due to 256-entry blake + full rolling-hash replay. | 4.5 | Use `transpiler_runner().with_cycles(...)` to bump the limit; also consider later swapping to `airbender-sdk` accelerated Blake2s/Keccak. |

## What this plan explicitly does NOT include

- Prover host (RPC clients, witness translation from `zks_getProof` JSON).
- Verifier host (L1 `storedBatchHash` query).
- Recursion / real prover backend (`gpu_prover`) wiring.
- Bundle format for shipping proofs between prover and verifier.
- Any protocol-level integration (no touching of `airbender-platform` or
  `zksync-os` source trees).

Those come after the guest is trusted to do its job against local
fixtures — which is what phases 0–4 are for.
