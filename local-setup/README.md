# Local setup

Spins up an anvil (L1) + a patched `zksync-os-server` (L2) locally so
you can drive `prividium-sd-host prove` and `prividium-sd-host verify`
against a real Prividium without needing any external network
access.

This is the prividium-zk-selective-disclosure analogue of
`zksync-os-server`'s own `run_local.sh` — in fact it's a thin
wrapper around it.

## Prerequisites

- **Sibling `zksync-os-server` checkout** at `../../zksync-os-server`
  (relative to the repo root). It must have the
  `prividium-sd-account-preimage-rpc` branch checked out — that
  branch adds the `zks_getAccountPreimage` RPC method we need to
  build balance_of and observable_bytecode_hash witnesses. See
  <https://github.com/matter-labs/zksync-os-server/pull/1161>.

  ```sh
  cd ../zksync-os-server
  git fetch origin
  # If you haven't already, add antoniolocascio-bot as a remote:
  git remote add fork https://github.com/antoniolocascio-bot/zksync-os-server.git
  git fetch fork
  git checkout -B prividium-sd-account-preimage-rpc fork/prividium-sd-account-preimage-rpc
  ```

  Until PR #1161 is merged, you must be on that branch. Once it
  merges to upstream `main`, `origin/main` will work.

- **Sibling `airbender-platform` checkout** at
  `../../airbender-platform`. Used by the guest + host builds (same
  as the rest of the repo).

- **`anvil`** (`foundry` toolchain) on `PATH`, for the L1 side.

- **`cargo-airbender`** installed from the sibling airbender-platform
  checkout — the `host` integration tests already require it. See
  the top-level README.

## What `run_local.sh` does

1. Builds the prividium-sd-host CLI + the patched `zksync-os-server`
   from the sibling checkout.
2. Decompresses the L1 state snapshot from
   `../../zksync-os-server/local-chains/v30.2/l1-state.json.gz` into
   a temp dir.
3. Starts `anvil --load-state $TMP/l1-state.json --port 8545` and
   waits for it to respond.
4. Starts `zksync-os-server` pointed at that anvil via the server's
   own `local-chains/v30.2/default/config.yaml`.
5. Prints the useful endpoint URLs and wallet info:

   ```
   L1 RPC:       http://localhost:8545
   L2 RPC:       http://localhost:3050
   Chain ID:     6565 (ZKsync OS default)
   Diamond proxy: 0x... (printed from config)
   ```

6. Blocks until you hit Ctrl+C, then cleans up both processes.

## Manual usage

The script just chains `anvil` and the server's own `run_local.sh`.
If you want finer control or to tweak the config, run them directly:

```sh
# Terminal 1 — L1
cd ../../zksync-os-server
gzip -dfk local-chains/v30.2/l1-state.json.gz
anvil --load-state local-chains/v30.2/l1-state.json --port 8545

# Terminal 2 — L2 server (requires the PR #1161 branch)
cd ../../zksync-os-server
./run_local.sh ./local-chains/v30.2/default
```

Then from this repo:

```sh
# Generate a proof (tx_inclusion is the easiest to exercise — it
# doesn't need zks_getAccountPreimage and works on stock main)
cd ..  # prividium-zk-selective-disclosure repo root
./target/release/prividium-sd-host prove tx-inclusion \
    --l2-rpc-url http://localhost:3050 \
    --batch-number 1 \
    --tx-hash 0x<tx-hash> \
    --out proof.bin

# Verify it
./target/release/prividium-sd-host verify \
    --l1-rpc-url http://localhost:8545 \
    --diamond-proxy 0x<diamond-proxy-address-from-server-logs> \
    --in proof.bin
```

## Teardown

`run_local.sh` handles cleanup on Ctrl+C. If anything gets wedged,
kill both processes manually and remove the L1 state + server db:

```sh
pkill -f "anvil --load-state"
pkill -f "zksync-os-server"
rm -rf ../../zksync-os-server/db/*
```
