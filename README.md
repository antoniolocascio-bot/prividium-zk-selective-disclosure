# prividium-zk-selective-disclosure

Rust tooling for selective disclosure over data in Prividiums (private ZKsync
rollups). A guest program runs on top of the [Airbender
platform](https://github.com/matter-labs/airbender-platform) and proves a
statement selected from a group of possibilities; host-side tools fetch
the needed data from Prividium RPC endpoints, drive proof generation,
and verify proofs.

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
serializable [`ProofBundle`] format. Three pluggable fetch seams keep
everything testable without a network:

- `L1Source` trait for `storedBatchHash(batchNumber)` lookups, with a
  real alloy-backed `RpcL1Source` and an in-memory `MockL1Source`.
- `WitnessSource` trait for building witnesses, with a real
  alloy-backed `RpcWitnessSource` (talks to `zks_getProof`,
  `zks_getAccountPreimage`, and `eth_getBlockByNumber` on the L2)
  and an in-memory `MockWitnessSource`.
- A CLI binary (`prividium-sd-host prove | verify | inspect`) that
  wires both real sources together for end-to-end usage against a
  live local or remote Prividium.

A `local-setup/` directory contains a `run_local.sh` that launches an
anvil L1 + a patched `zksync-os-server` L2 for offline testing. See
[`local-setup/README.md`](local-setup/README.md).

Every layer is exercised end-to-end through real fixtures built on top of
the ZKsync OS `TestingTree` and the real bootloader `BlockHeader::hash`,
so every proof the integration tests accept is byte-identical to what the
production server would emit for the same inputs.

**Upstream PR required:** `zks_getAccountPreimage`, the RPC method that
returns the 124-byte `AccountProperties::encoding()` blob used by
`balance_of` and `observable_bytecode_hash`, lives in
[matter-labs/zksync-os-server#1161](https://github.com/matter-labs/zksync-os-server/pull/1161)
and must be checked out as a branch until it merges. See
`local-setup/README.md` for the exact git steps. `tx_inclusion` works
against stock upstream `main`.

**Not yet implemented:** real (GPU / CPU) airbender backends. The
bundle format is already designed to be additive for that transition.

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
├── host/               # prover + verifier library + CLI
│   ├── src/
│   │   ├── lib.rs               # public API surface
│   │   ├── main.rs              # CLI: prove / verify / inspect
│   │   ├── bundle.rs            # ProofBundle wire format (postcard)
│   │   ├── prover.rs            # prove(), prove_from_source()
│   │   ├── verifier.rs          # verify_bundle() + VerifiedDisclosure
│   │   ├── disclosure_request.rs # high-level request enum
│   │   ├── l1_source.rs         # L1Source trait + MockL1Source
│   │   ├── witness_source.rs    # WitnessSource trait + MockWitnessSource
│   │   ├── rpc_wire.rs          # zks_getProof JSON wire types (mirrored)
│   │   ├── rpc_l1.rs            # RpcL1Source: alloy + storedBatchHash
│   │   └── rpc_l2.rs            # RpcWitnessSource: alloy + zks_getProof etc.
│   └── tests/
│       ├── statements.rs        # raw guest via airbender transpiler_runner
│       ├── end_to_end.rs        # prover → bundle → verifier (raw ProveRequest)
│       └── witness_source.rs    # DisclosureRequest → WitnessSource → prove → verify
└── local-setup/        # scripts to run anvil + zksync-os-server locally
    ├── README.md
    └── run_local.sh
```

The workspace at the root contains `core` and `test-fixtures`. `guest`
(riscv32 target, special link flags) and `host` (separate profile
overrides for heavy proving-related crates) are excluded and each have
their own `Cargo.lock`.

## Prerequisites

Sibling checkouts (all relative to this repo's parent directory):

- `../airbender-platform` — provides `airbender-sdk` (guest) and
  `airbender-host` (prover/verifier bindings).
- `../zksync-os` — provides `basic_system::TestingTree` and
  `basic_bootloader::BlockHeader`. Only `test-fixtures/` depends on
  this; the guest never links against it.
- `../zksync-os-server` — only needed for the local setup (see
  `local-setup/README.md`). The local-setup script currently
  requires this to be on the `prividium-sd-account-preimage-rpc`
  branch from [antoniolocascio-bot's fork][fork], until
  [PR #1161 on upstream][pr-1161] merges; the branch adds the
  `zks_getAccountPreimage` RPC method that `balance_of` and
  `observable_bytecode_hash` proofs need.

Tools on `PATH`:

- `cargo-airbender` — one-time install from the sibling
  airbender-platform checkout (run from this repo root):

  ```sh
  cargo install --path ../airbender-platform/crates/cargo-airbender \
      --no-default-features --force
  ```

- `anvil` — for the local setup only. Install via
  [foundry](https://getfoundry.sh):

  ```sh
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  export PATH="$HOME/.foundry/bin:$PATH"
  ```

[fork]: https://github.com/antoniolocascio-bot/zksync-os-server/tree/prividium-sd-account-preimage-rpc
[pr-1161]: https://github.com/matter-labs/zksync-os-server/pull/1161

## Build

Build the airbender guest artifacts (produces
`guest/dist/app/app.bin`, `.elf`, etc.):

```sh
(cd guest && cargo airbender build)
```

Re-run this every time `guest/` or `core/` changes. The integration
tests in `host/` load `guest/dist/app/` directly and will fail if the
artifacts are missing or stale.

## Test

Workspace unit + native scenario tests (fast, no guest execution,
no network):

```sh
cargo test
```

Host library + integration tests (run the built `app.bin` through
airbender and exercise the full prover / verifier path over
in-memory mocks):

```sh
(cd host && cargo test --release)
```

The host tests are `--release` because the airbender transpiler
runner is several orders of magnitude slower in debug mode.

None of the above tests need a network or RPC.

## Using the CLI against a local Prividium

See **[`local-setup/README.md`](local-setup/README.md)** for the
authoritative walkthrough — prerequisites, a one-liner launcher,
how to grep the diamond-proxy address out of the chain log, and a
verified end-to-end transcript for all three statements.

Abbreviated version: in terminal 1, launch the local chain:

```sh
./local-setup/run_local.sh --logs-dir /tmp/prividium-local-logs
```

Wait for `"All services started successfully"`. In terminal 2,
generate and verify a `tx_inclusion` proof for a tx from block 2:

```sh
TX_HASH=$(curl -s -X POST http://localhost:3050 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x2",false],"id":1}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["transactions"][0])')

DIAMOND_PROXY=$(grep -o 'diamond_proxy_l1: ZkChain { instance: IZKChainInstance([^)]*' \
    /tmp/prividium-local-logs/chain-*.log \
    | tail -1 | sed 's/.*IZKChainInstance(//')

./host/target/release/prividium-sd-host prove \
    --l2-rpc-url http://localhost:3050 \
    --out /tmp/proof.bin \
    tx-inclusion --batch-number 2 --tx-hash "$TX_HASH"

./host/target/release/prividium-sd-host verify \
    --l1-rpc-url http://localhost:8545 \
    --diamond-proxy "$DIAMOND_PROXY" \
    --in /tmp/proof.bin
```

Expected output from the final command:

```
Verified: TxInclusion
  batch number:  2
  l1 commitment: 0x...
  block number:  2
  tx hash:       0x...
```

### CLI argument-order gotcha

Clap parses `--l2-rpc-url` and `--out` as options on the `prove`
**parent** command, not on the statement subcommand. The correct
structure is:

```text
prividium-sd-host prove <parent-opts>    <statement>   <statement-opts>
                        --l2-rpc-url     balance-of    --batch-number
                        --out                          --address
                        --guest-dist
```

So `prove balance-of --out /tmp/x.bin ...` will fail with
`unexpected argument '--out' found`. Put `--out` and `--l2-rpc-url`
before the statement name, not after.

### Subcommands

The three prove subcommands are `balance-of`,
`observable-bytecode-hash`, and `tx-inclusion`. There is also an
`inspect` subcommand that dumps a bundle file without touching any
RPC. See `--help` on any of them for the full argument list, and
the local-setup README for worked examples of all three statements.

## Using the library

The CLI is a thin shell around the library. For programmatic usage:

```rust
use alloy::primitives::Address;
use prividium_sd_host::{
    prove_from_source, verify_bundle, DisclosureRequest, RpcL1Source,
    RpcWitnessSource, VerifiedDisclosure,
};

let l2 = RpcWitnessSource::new("http://localhost:3050")?;
let bundle = prove_from_source(
    "guest/dist/app",
    &l2,
    DisclosureRequest::BalanceOf {
        batch_number: 42,
        address: "0xababababababababababababababababababab".parse()?,
    },
)?;

// Ship `bundle.encode()?` over the wire here.

let l1 = RpcL1Source::new(
    "http://localhost:8545",
    diamond_proxy_address,
)?;
let disclosure: VerifiedDisclosure =
    verify_bundle("guest/dist/app", &bundle, &l1)?;
```

Both source types are traits — swap in `MockL1Source` /
`MockWitnessSource` for unit tests that don't need the network. See
`host/tests/witness_source.rs` for worked examples.

Bundles serialize via `bundle.encode()` / `ProofBundle::decode(&bytes)`.
The format is versioned (`BUNDLE_FORMAT_VERSION`) so breaking changes
fail loudly rather than silently.

## What the tests cover

| Layer | Test count | What it exercises |
|---|---|---|
| `core` unit tests | 69 | Hash wrappers, Merkle verifier (including non-existence rejection), `AccountProperties` codec, chain state commitment, `StoredBatchInfo` ABI + keccak layout, RLP helpers, `BlockHeader::hash` byte stream, tx rolling hash, public-input commit, pack/unpack, witness codec, common shared codec helpers. |
| `test-fixtures` unit tests | 9 | `MockStateTree` wrapping `TestingTree` (round-trip + non-existence + tamper rejects), `MockBlock` + 256-block `BlockWindow` construction (asserts bootloader `BlockHeader::hash` == our `BlockHeader::hash` on every block built). |
| `test-fixtures` integration tests (`tests/scenarios.rs`) | 9 | Each statement end-to-end through `core::statements::verify` with a real `TestingTree`-produced proof + a real bootloader-verified block hash, plus tamper-rejection tests for wrong balance, wrong L1 commitment, non-existing with non-zero claim, wrong tx hash, wrong block number. |
| `host` integration tests (`tests/statements.rs`) | 5 | Each statement run through the compiled airbender guest binary via `Program::load` + `transpiler_runner`, asserting the committed `[u32; 8]` receipt output unpacks to the expected 32-byte public input. Includes a tampered-balance rejection test (which catches the `exit_error()`-induced illegal-instruction panic from the transpiler runner). |
| `host` end-to-end tests (`tests/end_to_end.rs`) | 8 | Full prover → `ProofBundle` encode/decode → verifier round-trip for all three statements, plus rejection tests for (a) wrong L1 commitment returned by the `MockL1Source`, (b) missing batch in the L1 source, (c) post-hoc `params_bytes` tampering (airbender rejects on receipt mismatch), (d) tampered witness balance (prover rejects via `GuestRejected`). |
| `host` witness-source tests (`tests/witness_source.rs`) | 4 | `DisclosureRequest → WitnessSource::fetch → prove_from_source → verify_bundle` round-trip for all three statements through the in-memory `MockWitnessSource`, plus a "not registered" error case. Covers the high-level surface the CLI uses. |
| `host` library unit tests (`rpc_wire`, `witness_source::mock`) | 6 | JSON wire-format snapshots for `zks_getProof` response types (matches the upstream shape), and basic `MockWitnessSource` map semantics. |
| **Total** | **104** | |

None of the tests require any network access or any RPC endpoint. The
`RpcL1Source` / `RpcWitnessSource` / CLI paths are exercised manually
via `local-setup/run_local.sh` for now.
