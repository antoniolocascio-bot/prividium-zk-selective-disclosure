# prividium-zk-selective-disclosure

Rust tooling for selective disclosure over data in Prividiums (private zkSync
rollups). A guest program runs on top of the [Airbender
platform](https://github.com/matter-labs/airbender-platform) and proves a
statement selected from a group of possibilities; small host-side tools
(future) fetch the needed data from Prividium RPC endpoints, drive proof
generation, and verify proofs.

See `DESIGN.md` for the full design and `PLAN.md` for the implementation
plan.

## Status

All three initial statements are implemented end-to-end through the
airbender **dev** backend:

- `balance_of(batch_number, l1_commitment, address, balance)`
- `observable_bytecode_hash(batch_number, l1_commitment, address, hash)`
- `tx_inclusion(batch_number, l1_commitment, block_number, tx_hash)`

The host crate (`prividium-sd-host`) exposes library-level `prove` and
`verify_bundle` entry points that wrap the airbender prover/verifier in a
serializable [`ProofBundle`] format, plus a pluggable [`L1Source`] trait
(with an in-memory `MockL1Source`) so tests run without any network.

Every layer is exercised end-to-end through real fixtures built on top of
the ZKsync OS `TestingTree` and the real bootloader `BlockHeader::hash`,
so every proof the integration tests accept is byte-identical to what the
production server would emit for the same inputs.

**Not yet implemented:** real RPC clients for `zks_getProof` /
`eth_getBlockByNumber` / `storedBatchHash(batchNumber)`, a CLI that uses
them, and the real (GPU / CPU) airbender backends. The bundle format is
already designed to be additive for the real-backend transition.

## Layout

```
prividium-zk-selective-disclosure/
├── DESIGN.md           # design doc for all three statements
├── PLAN.md             # implementation plan (this was the roadmap)
├── Cargo.toml          # workspace = core, test-fixtures
├── rust-toolchain.toml # nightly-2026-02-10 (matches airbender-platform)
├── core/               # prividium-sd-core: no_std shared logic
│   └── src/
│       ├── hash.rs                 # Blake2s, Keccak256 wrappers
│       ├── tree/                   # flat-key derivation + Merkle verifier
│       ├── account_properties.rs   # 124-byte AccountProperties codec
│       ├── state_commitment.rs     # chain_state_commitment blake2s
│       ├── stored_batch_info.rs    # abi.encode + keccak256 → l1 commitment
│       ├── rlp.rs                  # port of bootloader's RLP helpers
│       ├── block_header.rs         # BlockHeader struct + hash()
│       ├── tx_rolling_hash.rs      # Keccak rolling accumulator
│       ├── params.rs               # per-statement public parameter layouts
│       ├── pub_input.rs            # keccak256(id || batch || l1 || params)
│       ├── statement_id.rs         # u32 tag enum
│       ├── witness.rs              # hand-rolled binary witness codec
│       └── statements/             # per-statement verify() entry points
│           ├── balance_of.rs
│           ├── observable_bytecode_hash.rs
│           └── tx_inclusion.rs
├── test-fixtures/      # prividium-sd-test-fixtures: std, wraps basic_system
│   ├── src/
│   │   ├── mock_tree.rs    # wraps TestingTree, produces AccountMerkleProofs
│   │   ├── mock_block.rs   # wraps bootloader BlockHeader, builds windows
│   │   └── scenarios.rs    # end-to-end Scenario builders per statement
│   └── tests/
│       └── scenarios.rs    # native verifier round-trip + tamper tests
├── guest/              # airbender riscv32 guest binary (dispatches on StatementId)
│   └── src/main.rs
└── host/               # prover + verifier library (+ minimal CLI)
    ├── src/
    │   ├── lib.rs          # public API surface
    │   ├── bundle.rs       # ProofBundle wire format (postcard)
    │   ├── prover.rs       # `prove(...)` driving the airbender dev prover
    │   ├── verifier.rs     # `verify_bundle(...)` + VerifiedDisclosure
    │   ├── l1_source.rs    # L1Source trait + MockL1Source impl
    │   └── main.rs         # placeholder CLI (defers to library)
    └── tests/
        ├── statements.rs   # raw guest via airbender transpiler_runner
        └── end_to_end.rs   # prover → bundle encode/decode → verifier
```

The workspace at the root contains `core` and `test-fixtures`. `guest`
(riscv32 target, special link flags) and `host` (separate profile
overrides for heavy proving-related crates) are excluded and each have
their own `Cargo.lock`.

## Dependencies

Both crates are expected to be checked out as siblings:

- `../airbender-platform` — provides `airbender-sdk` (guest) and
  `airbender-host` (host driver).
- `../zksync-os` — provides `basic_system::TestingTree`,
  `basic_bootloader::BlockHeader`, and friends. Only `test-fixtures/` depends
  on this tree; the guest never links against it.

## Build

Install `cargo-airbender` once:

```sh
cargo install --path ../airbender-platform/crates/cargo-airbender --no-default-features --force
```

Build the guest artifacts (produces `guest/dist/app/app.bin`, `.elf`, etc.):

```sh
(cd guest && cargo airbender build)
```

Re-run this every time `guest/` or `core/` changes. The integration tests
in `host/` load `guest/dist/app/` directly and will fail if the artifacts
are missing or stale.

## Test

Workspace unit + native scenario tests (fast, no guest execution):

```sh
cargo test
```

Host library + integration tests (run the built `app.bin` through
airbender and exercise the full prover / verifier path):

```sh
(cd host && cargo test --release)
```

The host tests are `--release` because the airbender transpiler runner is
several orders of magnitude slower in debug mode.

## Using the library

Library-level prover and verifier entry points live in
`prividium-sd-host`:

```rust
use prividium_sd_host::{prove, verify_bundle, MockL1Source, ProveRequest};

let bundle = prove(
    "../guest/dist/app",
    ProveRequest {
        statement_id: /* StatementId::BalanceOf, etc. */,
        batch_number,
        l1_commitment,
        params_bytes,    // canonical per-statement public parameter bytes
        witness_bytes,   // canonical per-statement witness bytes
    },
)?;

let l1 = MockL1Source::new().with_batch(batch_number, l1_commitment);
let disclosure = verify_bundle("../guest/dist/app", &bundle, &l1)?;
// disclosure: VerifiedDisclosure::{BalanceOf,ObservableBytecodeHash,TxInclusion}
```

To serialize the bundle for transport use `bundle.encode()`; to parse it
back use `ProofBundle::decode(&bytes)`. Both are versioned
(`BUNDLE_FORMAT_VERSION`) so breakage is caught loudly rather than
silently.

Real RPC-backed `L1Source` and `WitnessSource` implementations are not
yet included; see the open questions in `DESIGN.md` §12 for what's
needed.

## What the tests cover

| Layer | Test count | What it exercises |
|---|---|---|
| `core` unit tests | 69 | Hash wrappers, Merkle verifier (including non-existence rejection), `AccountProperties` codec, chain state commitment, `StoredBatchInfo` ABI + keccak layout, RLP helpers, `BlockHeader::hash` byte stream, tx rolling hash, public-input commit, pack/unpack, witness codec, common shared codec helpers. |
| `test-fixtures` unit tests | 9 | `MockStateTree` wrapping `TestingTree` (round-trip + non-existence + tamper rejects), `MockBlock` + 256-block `BlockWindow` construction (asserts bootloader `BlockHeader::hash` == our `BlockHeader::hash` on every block built). |
| `test-fixtures` integration tests (`tests/scenarios.rs`) | 9 | Each statement end-to-end through `core::statements::verify` with a real `TestingTree`-produced proof + a real bootloader-verified block hash, plus tamper-rejection tests for wrong balance, wrong L1 commitment, non-existing with non-zero claim, wrong tx hash, wrong block number. |
| `host` integration tests (`tests/statements.rs`) | 5 | Each statement run through the compiled airbender guest binary via `Program::load` + `transpiler_runner`, asserting the committed `[u32; 8]` receipt output unpacks to the expected 32-byte public input. Includes a tampered-balance rejection test (which catches the `exit_error()`-induced illegal-instruction panic from the transpiler runner). |
| `host` end-to-end tests (`tests/end_to_end.rs`) | 8 | Full prover → `ProofBundle` encode/decode → verifier round-trip for all three statements, plus rejection tests for (a) wrong L1 commitment returned by the `MockL1Source`, (b) missing batch in the L1 source, (c) post-hoc `params_bytes` tampering (airbender rejects on receipt mismatch), (d) tampered witness balance (prover rejects via `GuestRejected`). |
| **Total** | **100** | |

None of the tests require any network access or any RPC endpoint.
