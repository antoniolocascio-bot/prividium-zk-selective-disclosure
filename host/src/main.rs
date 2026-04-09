//! Minimal placeholder binary for `prividium-sd-host`.
//!
//! The real work lives in the library (`prove` / `verify_bundle`),
//! and the integration tests drive it end-to-end via `test-fixtures`.
//! A full CLI with `prove` / `verify` subcommands is intentionally
//! deferred until the RPC-backed witness source and L1 source land —
//! at that point the CLI becomes useful because users can point it
//! at real Prividium and Ethereum RPC endpoints.

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    eprintln!(
        "prividium-sd-host {} — library-only build.\n\
         Library entry points: `prividium_sd_host::prove` and \
         `prividium_sd_host::verify_bundle`.\n\
         See `host/tests/*.rs` for end-to-end examples, and \
         `DESIGN.md` / `PLAN.md` for the full architecture.",
        env!("CARGO_PKG_VERSION")
    );
    if args.iter().any(|a| a == "--help" || a == "-h") {
        // Exit 0 on explicit --help, non-zero otherwise to make it
        // obvious the binary currently has no action to perform.
        std::process::exit(0);
    }
    std::process::exit(2);
}
