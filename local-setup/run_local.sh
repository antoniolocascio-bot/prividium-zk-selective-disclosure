#!/usr/bin/env bash
#
# Spins up a local anvil (L1) + a patched zksync-os-server (L2) for
# testing the prividium-sd-host CLI against a real RPC stack.
#
# Usage:
#   ./local-setup/run_local.sh [--logs-dir <path>] [--keep-db]
#
# Prerequisites: see local-setup/README.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
SERVER_DIR="$(cd "$REPO_ROOT/../zksync-os-server" && pwd)"

# Color codes.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOGS_DIR=""
KEEP_DB=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --logs-dir)
            if [[ -z "${2:-}" || "$2" == --* ]]; then
                echo -e "${RED}--logs-dir requires a path argument${NC}" >&2
                exit 1
            fi
            LOGS_DIR="$2"
            shift 2
            ;;
        --keep-db)
            KEEP_DB=1
            shift
            ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--logs-dir <path>] [--keep-db]

Starts an anvil L1 on localhost:8545 and a zksync-os-server L2 on
localhost:3050, using the server's own local-chains/v30.2/default
config. Both processes are killed on Ctrl+C.

Prerequisites (not auto-installed — the script checks and bails if
any are missing):

  - sibling \$SERVER_DIR checkout on the
    \`prividium-sd-account-preimage-rpc\` branch (needed until
    matter-labs/zksync-os-server#1161 merges upstream)
  - sibling \`../airbender-platform\` checkout (for guest builds)
  - anvil on PATH (foundry toolchain)
  - cargo-airbender on PATH
  - an up-to-date guest built under \`./guest/dist/app/\`

Options:
  --logs-dir <path>   Write anvil + chain logs under <path> instead
                      of the default temp location. Useful for
                      grepping the diamond-proxy address from chain
                      startup (see README).
  --keep-db           Do not wipe \$SERVER_DIR/db/* before launch.
                      The default is to wipe it, because the L1 state
                      is always reloaded fresh from the snapshot and
                      a stale L2 db would be inconsistent.
EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}" >&2
            echo -e "${RED}Run $0 --help for usage.${NC}" >&2
            exit 1
            ;;
    esac
done

# ======== prerequisite checks ========

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${RED}Error: '$1' is not on PATH.${NC}" >&2
        echo -e "${RED}  $2${NC}" >&2
        exit 1
    fi
}

check_cmd anvil "Install foundry (https://getfoundry.sh) and make sure ~/.foundry/bin is on PATH."
check_cmd cargo-airbender "Run: cargo install --path ../airbender-platform/crates/cargo-airbender --no-default-features --force"

if [[ ! -d "$SERVER_DIR" ]]; then
    echo -e "${RED}Error: $SERVER_DIR does not exist.${NC}" >&2
    echo -e "${RED}Expected a sibling zksync-os-server checkout.${NC}" >&2
    exit 1
fi

cd "$SERVER_DIR"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
if [[ "$CURRENT_BRANCH" != "prividium-sd-account-preimage-rpc" ]]; then
    echo -e "${YELLOW}Warning: $SERVER_DIR is on branch '$CURRENT_BRANCH', not${NC}"
    echo -e "${YELLOW}'prividium-sd-account-preimage-rpc'.${NC}"
    echo -e "${YELLOW}${NC}"
    echo -e "${YELLOW}This means the server won't expose zks_getAccountPreimage,${NC}"
    echo -e "${YELLOW}and 'prividium-sd-host prove balance-of' / 'observable-bytecode-hash'${NC}"
    echo -e "${YELLOW}will fail with 'method not found'. 'tx-inclusion' still works.${NC}"
    echo -e "${YELLOW}${NC}"
    echo -e "${YELLOW}To fix:${NC}"
    echo -e "${YELLOW}  cd $SERVER_DIR${NC}"
    echo -e "${YELLOW}  git remote add fork https://github.com/antoniolocascio-bot/zksync-os-server.git 2>/dev/null || true${NC}"
    echo -e "${YELLOW}  git fetch fork${NC}"
    echo -e "${YELLOW}  git checkout -B prividium-sd-account-preimage-rpc fork/prividium-sd-account-preimage-rpc${NC}"
    echo -e "${YELLOW}${NC}"
    echo -e "${YELLOW}Track the upstream PR at:${NC}"
    echo -e "${YELLOW}  https://github.com/matter-labs/zksync-os-server/pull/1161${NC}"
    echo
fi

# Locate the server's run_local.sh and config.
SERVER_RUN_LOCAL="$SERVER_DIR/run_local.sh"
SERVER_CONFIG_DIR="$SERVER_DIR/local-chains/v30.2/default"
if [[ ! -x "$SERVER_RUN_LOCAL" ]]; then
    echo -e "${RED}Error: $SERVER_RUN_LOCAL is not executable.${NC}" >&2
    exit 1
fi
if [[ ! -d "$SERVER_CONFIG_DIR" ]]; then
    echo -e "${RED}Error: $SERVER_CONFIG_DIR does not exist.${NC}" >&2
    exit 1
fi

# ======== pre-launch housekeeping ========

# Wipe the server's L2 db so the interactive "clean up db/?" prompt
# in the server's run_local.sh never fires. This is safe by default
# because we always reload anvil from a pristine L1 state snapshot,
# so any previous L2 db would be inconsistent anyway.
if [[ "$KEEP_DB" != "1" ]]; then
    if [[ -d "$SERVER_DIR/db" ]] && [[ -n "$(ls -A "$SERVER_DIR/db" 2>/dev/null || true)" ]]; then
        echo -e "${BLUE}Cleaning $SERVER_DIR/db/* (use --keep-db to override)${NC}"
        rm -rf "$SERVER_DIR/db"/*
    fi
fi

# Build the host CLI up front so we fail fast if the build is broken.
echo -e "${BLUE}Building prividium-sd-host CLI...${NC}"
(cd "$REPO_ROOT/host" && cargo build --release --bin prividium-sd-host)
CLI_BIN="$REPO_ROOT/host/target/release/prividium-sd-host"
echo -e "${GREEN}CLI built: $CLI_BIN${NC}"
echo

# Build the guest if it's missing. The integration tests would
# normally keep this up to date, but a fresh checkout won't have it.
GUEST_DIST="$REPO_ROOT/guest/dist/app"
if [[ ! -f "$GUEST_DIST/app.bin" ]]; then
    echo -e "${BLUE}Building guest artifacts with cargo airbender...${NC}"
    (cd "$REPO_ROOT/guest" && cargo airbender build)
    echo -e "${GREEN}Guest built: $GUEST_DIST/app.bin${NC}"
    echo
fi

# ======== launch ========

echo -e "${BLUE}Delegating to $SERVER_RUN_LOCAL${NC}"
echo
echo -e "${GREEN}Endpoints after startup:${NC}"
echo -e "  L1 RPC: ${BLUE}http://localhost:8545${NC}"
echo -e "  L2 RPC: ${BLUE}http://localhost:3050${NC}"
echo
echo -e "${GREEN}To find the diamond proxy address for 'verify', grep the chain log:${NC}"
if [[ -n "$LOGS_DIR" ]]; then
    echo -e "  ${BLUE}grep -o 'diamond_proxy_l1: ZkChain { instance: IZKChainInstance([^)]*' $LOGS_DIR/chain-*.log | tail -1${NC}"
else
    echo -e "  (re-run with ${BLUE}--logs-dir /tmp/prividium-local-logs${NC} to capture logs)"
fi
echo

if [[ -n "$LOGS_DIR" ]]; then
    exec "$SERVER_RUN_LOCAL" "$SERVER_CONFIG_DIR" --logs-dir "$LOGS_DIR"
else
    exec "$SERVER_RUN_LOCAL" "$SERVER_CONFIG_DIR"
fi
