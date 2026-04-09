# Local setup

Spins up an **anvil** (L1) + a **patched `zksync-os-server`** (L2) on
your machine so you can drive `prividium-sd-host prove` and
`prividium-sd-host verify` against a real Prividium without needing
any external network access.

`run_local.sh` is a thin wrapper around `zksync-os-server`'s own
`run_local.sh`; it adds prerequisite checks, automatic `db/*` cleanup
(so the server's interactive "wipe db?" prompt never stalls the
script), and a helpful post-startup banner with the endpoint URLs.

## Prerequisites

All of these are checked by the script at launch time, with a
specific error message for each. You don't need to install all of
them before the first run — you can run the script and let it tell
you what's missing.

### 1. Sibling `zksync-os-server` checkout on the PR #1161 branch

The `zks_getAccountPreimage` RPC method that `balance_of` and
`observable_bytecode_hash` need is not in upstream `main` yet — it
lives in [matter-labs/zksync-os-server#1161][pr-1161], and until
that merges you must run a branch off my fork.

```sh
# From wherever you keep your checkouts — sibling to
# prividium-zk-selective-disclosure/
cd ../zksync-os-server

# Add my fork if you haven't already:
git remote add fork https://github.com/antoniolocascio-bot/zksync-os-server.git
git fetch fork

# Check out the branch:
git checkout -B prividium-sd-account-preimage-rpc fork/prividium-sd-account-preimage-rpc
```

Once PR #1161 merges, upstream `main` will work directly and you can
skip this step.

**Not on the branch?** `tx-inclusion` proving will still work (it
doesn't use `zks_getAccountPreimage`). `balance-of` and
`observable-bytecode-hash` will fail with a "method not found" from
the L2 RPC. `run_local.sh` emits a loud yellow warning if it detects
the wrong branch at launch.

[pr-1161]: https://github.com/matter-labs/zksync-os-server/pull/1161

### 2. Sibling `airbender-platform` checkout

At `../airbender-platform` (relative to the repo root). This is the
same dependency the guest and host build paths already need, so if
you've run `cargo test` at all it's already in place.

### 3. `anvil` on `PATH`

From the [foundry](https://getfoundry.sh) toolchain. One-time install:

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
export PATH="$HOME/.foundry/bin:$PATH"   # add to your shell rc
anvil --version   # sanity check
```

### 4. `cargo-airbender` on `PATH`

From the sibling airbender-platform checkout. One-time install:

```sh
cargo install --path ../airbender-platform/crates/cargo-airbender \
    --no-default-features --force
```

## Quick start

From the `prividium-zk-selective-disclosure/` repo root, in one
terminal:

```sh
./local-setup/run_local.sh --logs-dir /tmp/prividium-local-logs
```

The script will, in order:

1. Check all prerequisites (`anvil`, `cargo-airbender`, sibling
   server checkout on the right branch, server's `run_local.sh`
   present).
2. Wipe `$SERVER_DIR/db/*` (pass `--keep-db` to skip — see below).
3. Build the `prividium-sd-host` CLI.
4. Build the airbender guest if `guest/dist/app/app.bin` is missing.
5. Start anvil on `localhost:8545`, loading the pre-baked L1 state
   snapshot from `$SERVER_DIR/local-chains/v30.2/l1-state.json.gz`.
6. Start the server on `localhost:3050`, using the config at
   `$SERVER_DIR/local-chains/v30.2/default/config.yaml`.
7. Block until you hit `Ctrl+C`; both processes are then killed
   cleanly.

When you see `"All services started successfully"` from the server's
launcher, the L1 and L2 are both ready.

## Finding the diamond proxy address

The `verify` command needs the diamond proxy address on L1 (it's not
in the CLI bundle; it's what the verifier uses to `eth_call`
`storedBatchHash(batch_number)`). Grep it out of the chain startup
log:

```sh
grep -o 'diamond_proxy_l1: ZkChain { instance: IZKChainInstance([^)]*' \
    /tmp/prividium-local-logs/chain-*.log \
    | tail -1
```

You should see something like:

```
diamond_proxy_l1: ZkChain { instance: IZKChainInstance(0x18f438bc08d755e164a7ae7c077e2ea93b0179ef
```

Copy the `0x18f4…` part. For the bundled `local-chains/v30.2/default`
config it is stable across runs, so once you've grabbed it once you
can just remember it.

## End-to-end example

These are the exact commands I ran against a fresh
`run_local.sh --logs-dir /tmp/prividium-local-logs` session. All
three statements verified against the live L1.

In **another** terminal (the one running `run_local.sh` is blocking):

### tx_inclusion

This one works on any branch — it doesn't need
`zks_getAccountPreimage`.

```sh
# Pick a tx hash out of some recent block on the L2:
curl -s -X POST http://localhost:3050 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x2",false],"id":1}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["transactions"][0])'
```

Output:

```
0x21f81c7019feea07bf3ea8dc6bd9d73746a2612c7e4ebe9eb45c40b4eff99e3f
```

Prove it was included at batch 2:

```sh
./host/target/release/prividium-sd-host prove \
    --l2-rpc-url http://localhost:3050 \
    --out /tmp/proof-tx.bin \
    tx-inclusion \
        --batch-number 2 \
        --tx-hash 0x21f81c7019feea07bf3ea8dc6bd9d73746a2612c7e4ebe9eb45c40b4eff99e3f
```

Output:

```
Proving "tx_inclusion" (batch 2) via http://localhost:3050...
Wrote proof bundle (3327 bytes) to /tmp/proof-tx.bin
```

Verify against L1:

```sh
./host/target/release/prividium-sd-host verify \
    --l1-rpc-url http://localhost:8545 \
    --diamond-proxy 0x18f438bc08d755e164a7ae7c077e2ea93b0179ef \
    --in /tmp/proof-tx.bin
```

Output:

```
Verified: TxInclusion
  batch number:  2
  l1 commitment: 0x663d85e013de8354aa14c7e3ef3c94367b10ad1c59a162127ef5e731337f1fd7
  block number:  2
  tx hash:       0x21f81c7019feea07bf3ea8dc6bd9d73746a2612c7e4ebe9eb45c40b4eff99e3f
```

### balance_of

This **requires the PR #1161 branch** of the server. Pick a
pre-deployed contract address from genesis — `0x01000c` is the
ZKsync wrapped base-token contract in the bundled `local-chains`
config.

```sh
./host/target/release/prividium-sd-host prove \
    --l2-rpc-url http://localhost:3050 \
    --out /tmp/proof-bal.bin \
    balance-of \
        --batch-number 2 \
        --address 0x000000000000000000000000000000000001000c

./host/target/release/prividium-sd-host verify \
    --l1-rpc-url http://localhost:8545 \
    --diamond-proxy 0x18f438bc08d755e164a7ae7c077e2ea93b0179ef \
    --in /tmp/proof-bal.bin
```

Output:

```
Verified: BalanceOf
  batch number:  2
  l1 commitment: 0x663d85e013de8354aa14c7e3ef3c94367b10ad1c59a162127ef5e731337f1fd7
  address:       0x000000000000000000000000000000000001000c
  balance (be):  0x0000000000000000000000000000000000000000000000000000000000000000
```

(The contract has zero base-token balance at genesis, which is
expected.)

### observable_bytecode_hash

Same address, same branch requirement:

```sh
./host/target/release/prividium-sd-host prove \
    --l2-rpc-url http://localhost:3050 \
    --out /tmp/proof-obh.bin \
    observable-bytecode-hash \
        --batch-number 2 \
        --address 0x000000000000000000000000000000000001000c

./host/target/release/prividium-sd-host verify \
    --l1-rpc-url http://localhost:8545 \
    --diamond-proxy 0x18f438bc08d755e164a7ae7c077e2ea93b0179ef \
    --in /tmp/proof-obh.bin
```

Output:

```
Verified: ObservableBytecodeHash
  batch number:  2
  l1 commitment: 0x663d85e013de8354aa14c7e3ef3c94367b10ad1c59a162127ef5e731337f1fd7
  address:       0x000000000000000000000000000000000001000c
  obh:           0xfa39c537efd212caa90984719215fe1dc24d45b8e74ec97841931f474f153b9c
```

### Inspect a bundle without any RPC

If you just want to see what's inside a bundle file:

```sh
./host/target/release/prividium-sd-host inspect --in /tmp/proof-tx.bin
```

Output:

```
Bundle at /tmp/proof-tx.bin
  format version: 1
  statement id:   3
  statement:      TxInclusion
  batch number:   2
  l1 commitment:  0x663d85e013de8354aa14c7e3ef3c94367b10ad1c59a162127ef5e731337f1fd7
  params (40B):  0x000000000000000221f81c7019feea07bf3ea8dc6bd9d73746a2612c7e4ebe9eb45c40b4eff99e3f
  dev input words: 2323
```

## CLI argument order

Clap parses `--l2-rpc-url` and `--out` as options on the `prove`
**parent** command, not on the statement subcommand. The correct
invocation is:

```text
prividium-sd-host prove <parent-opts> <statement> <statement-opts>
                        ^^^^^^^^^^^^^
                        --l2-rpc-url, --out, --guest-dist
```

So `prove tx-inclusion --out /tmp/foo.bin ...` will fail with
`unexpected argument '--out' found`. Put `--out` before the
statement name. The end-to-end example above has the correct order.

## Teardown

`Ctrl+C` in the `run_local.sh` terminal. It forwards SIGTERM to both
the server and anvil. If anything gets wedged:

```sh
pkill -TERM -f "zksync-os-server"
pkill -TERM -f "anvil --load-state"
```

The L2 db is automatically wiped on the next `run_local.sh` launch
(unless you pass `--keep-db`), so you do not need to clean it up
manually between runs.

## Troubleshooting

### "Error: 'anvil' is not on PATH."

Install foundry and re-source your shell rc:

```sh
curl -L https://getfoundry.sh | bash
foundryup
export PATH="$HOME/.foundry/bin:$PATH"
```

### "Warning: $SERVER_DIR is on branch 'main'" (or similar)

Check out the branch per the Prerequisites section above.
`tx-inclusion` still works without this; the other two statements do
not.

### "prove_from_source failed: native pre-verification rejected the witness: ..."

The native `core::statements::verify` pre-check caught a bug in the
witness before the airbender runner ever saw it. The specific
`StatementError` variant tells you where:

- `L1CommitmentMismatch` — the witness source computed an L1
  commitment that differs from the one the guest would derive
  internally. Usually a wire-format bug in `rpc_l2.rs` or the server
  returned unexpected data.
- `TxRollingHashMismatch` — the rolling keccak over the block's tx
  hashes doesn't match `block_header.transactions_root`. Check that
  the initial state is `[0u8; 32]` (bootloader-style) and not
  `keccak256("")`.
- `BlockHashMismatch` — the selected block's header RLP hash
  doesn't match the window entry at that index. Usually means
  `logs_bloom` wasn't zeroed when computing the header hash.
- `AccountPropertiesHashMismatch` — the 124-byte preimage doesn't
  hash to the tree-stored value. Check that the
  `zks_getAccountPreimage` response is decoded correctly and that
  the leaf flat key is right.

### "verify_bundle failed: bundle L1 commitment does not match storedBatchHash(batch_number)"

The prover's recomputed L1 commitment doesn't match what the diamond
proxy returns for the same batch. Usually means you're verifying
against the wrong `--diamond-proxy` address, or the server's anvil
was restarted after the bundle was produced (the L1 state resets on
every `run_local.sh` launch).

### "verify_bundle failed: l1 source error: storedBatchHash ABI decode failed: buffer overrun"

Same as above — the diamond proxy address is wrong, so the
`eth_call` is landing on a contract that doesn't implement
`storedBatchHash` and returns empty bytes. Double-check the grep
from the "Finding the diamond proxy address" section.
