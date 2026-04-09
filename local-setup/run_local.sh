#!/usr/bin/env bash
#
# Spins up a local anvil (L1) + a patched zksync-os-server (L2) for
# testing the prividium-sd-host CLI against a real RPC stack.
#
# Usage:
#   ./local-setup/run_local.sh [--logs-dir <path>]
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
while [[ $# -gt 0 ]]; do
    case "$1" in
        --logs-dir)
            LOGS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--logs-dir <path>]

Starts an anvil L1 on localhost:8545 and a zksync-os-server L2 on
localhost:3050, using the server's own local-chains/v30.2/default
config. Both processes are killed on Ctrl+C.

The sibling ../zksync-os-server checkout must be on the
prividium-sd-account-preimage-rpc branch (see local-setup/README.md)
until PR #1161 merges upstream.
EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}" >&2
            exit 1
            ;;
    esac
done

# Verify the server checkout exists and is on the expected branch.
if [[ ! -d "$SERVER_DIR" ]]; then
    echo -e "${RED}Error: $SERVER_DIR does not exist.${NC}" >&2
    echo -e "${RED}Expected a sibling zksync-os-server checkout.${NC}" >&2
    exit 1
fi

cd "$SERVER_DIR"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
if [[ "$CURRENT_BRANCH" != "prividium-sd-account-preimage-rpc" ]]; then
    echo -e "${YELLOW}Warning: $SERVER_DIR is on branch '$CURRENT_BRANCH', not${NC}"
    echo -e "${YELLOW}'prividium-sd-account-preimage-rpc'. balance_of and${NC}"
    echo -e "${YELLOW}observable_bytecode_hash proving will fail until PR #1161${NC}"
    echo -e "${YELLOW}merges upstream. tx_inclusion should still work.${NC}"
    echo -e "${YELLOW}See local-setup/README.md for branch setup instructions.${NC}"
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

# Build the host CLI up front so we fail fast if the build is broken.
echo -e "${BLUE}Building prividium-sd-host CLI...${NC}"
(cd "$REPO_ROOT/host" && cargo build --release --bin prividium-sd-host)
echo -e "${GREEN}CLI built: $REPO_ROOT/host/target/release/prividium-sd-host${NC}"
echo

# Delegate the actual launch to the server's own run_local.sh. It
# handles the anvil + server startup, readiness polling, and cleanup.
echo -e "${BLUE}Delegating to $SERVER_RUN_LOCAL${NC}"
if [[ -n "$LOGS_DIR" ]]; then
    exec "$SERVER_RUN_LOCAL" "$SERVER_CONFIG_DIR" --logs-dir "$LOGS_DIR"
else
    exec "$SERVER_RUN_LOCAL" "$SERVER_CONFIG_DIR"
fi
