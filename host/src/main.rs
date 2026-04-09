//! CLI for the Prividium selective-disclosure tool.
//!
//! Two subcommands:
//!
//! - `prove` — fetches a witness from a ZKsync OS L2 JSON-RPC
//!   endpoint via [`RpcWitnessSource`], runs the airbender prover,
//!   and writes a serialized [`ProofBundle`] to a file.
//! - `verify` — loads a [`ProofBundle`] from a file, queries an L1
//!   Ethereum JSON-RPC endpoint for `storedBatchHash(batch_number)`
//!   on the diamond proxy, and verifies the bundle end-to-end.
//!
//! Typical usage (assuming a local anvil + ZKsync OS node from
//! `local-setup/`):
//!
//! ```sh
//! # Prove account 0xab..ab had some balance at batch 42
//! prividium-sd-host prove balance-of \
//!     --l2-rpc-url http://localhost:3050 \
//!     --batch-number 42 \
//!     --address 0xababababababababababababababababababab \
//!     --out proof.bin
//!
//! # Verify it, checking the L1 commitment against anvil
//! prividium-sd-host verify \
//!     --l1-rpc-url http://localhost:8545 \
//!     --diamond-proxy 0xd8f8df05efacd52f28cdf11be22ce3d6ae0fabf7 \
//!     --in proof.bin
//! ```

use alloy::primitives::{Address, B256};
use clap::{Parser, Subcommand};
use prividium_sd_host::{
    prove_from_source, verify_bundle, DisclosureRequest, ProofBundle, RpcL1Source,
    RpcWitnessSource, VerifiedDisclosure,
};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "prividium-sd-host",
    version,
    about = "Prover + verifier for Prividium selective-disclosure proofs."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a proof bundle for a selective-disclosure statement.
    Prove(ProveArgs),
    /// Verify a previously-generated proof bundle against an L1 RPC.
    Verify(VerifyArgs),
    /// Print a human-readable summary of a bundle file (no proof
    /// verification, no RPC calls — useful for debugging).
    Inspect(InspectArgs),
}

#[derive(clap::Args)]
struct ProveArgs {
    /// URL of the ZKsync OS JSON-RPC endpoint for the Prividium
    /// (typically `http://localhost:3050` in local dev).
    #[arg(long, value_name = "URL", global = true)]
    l2_rpc_url: Option<String>,

    /// Path to the airbender guest `dist/app` directory. Defaults to
    /// `../guest/dist/app` relative to the binary's compile-time
    /// manifest dir, which is correct when running from the repo
    /// root.
    #[arg(long, value_name = "PATH")]
    guest_dist: Option<PathBuf>,

    /// Path to write the encoded proof bundle to.
    #[arg(long, value_name = "FILE")]
    out: PathBuf,

    /// Which statement to prove.
    #[command(subcommand)]
    statement: ProveStatement,
}

#[derive(Subcommand)]
enum ProveStatement {
    /// Prove that `account.balance == value` at batch `batch_number`.
    BalanceOf(ProveBalanceOfArgs),
    /// Prove that `account.observable_bytecode_hash == hash` at batch
    /// `batch_number`.
    ObservableBytecodeHash(ProveObservableBytecodeHashArgs),
    /// Prove that transaction `tx_hash` was included in one of the
    /// last 256 blocks committed by batch `batch_number`.
    TxInclusion(ProveTxInclusionArgs),
}

#[derive(clap::Args)]
struct ProveBalanceOfArgs {
    /// L1 batch number to anchor the proof to.
    #[arg(long)]
    batch_number: u64,
    /// EVM-style address of the account.
    #[arg(long)]
    address: Address,
}

#[derive(clap::Args)]
struct ProveObservableBytecodeHashArgs {
    #[arg(long)]
    batch_number: u64,
    #[arg(long)]
    address: Address,
}

#[derive(clap::Args)]
struct ProveTxInclusionArgs {
    #[arg(long)]
    batch_number: u64,
    /// 32-byte transaction hash (`0x`-prefixed hex).
    #[arg(long)]
    tx_hash: B256,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// URL of the L1 Ethereum JSON-RPC endpoint (e.g.
    /// `http://localhost:8545` for local anvil).
    #[arg(long, value_name = "URL")]
    l1_rpc_url: String,

    /// Address of the Prividium's diamond proxy contract on L1.
    /// Required for `storedBatchHash(batch_number)` lookups.
    #[arg(long, value_name = "ADDRESS")]
    diamond_proxy: Address,

    /// Path to the airbender guest `dist/app` directory. Must match
    /// the guest binary that produced the bundle being verified.
    #[arg(long, value_name = "PATH")]
    guest_dist: Option<PathBuf>,

    /// Path to the encoded proof bundle to verify.
    #[arg(long = "in", value_name = "FILE")]
    input: PathBuf,
}

#[derive(clap::Args)]
struct InspectArgs {
    #[arg(long = "in", value_name = "FILE")]
    input: PathBuf,
}

fn default_guest_dist() -> PathBuf {
    // Relative to the binary's manifest dir. At compile time this is
    // `<repo>/host`, so `../guest/dist/app` points at the
    // cargo-airbender output.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Prove(args) => run_prove(args),
        Command::Verify(args) => run_verify(args),
        Command::Inspect(args) => run_inspect(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run_prove(args: ProveArgs) -> anyhow::Result<()> {
    let l2_url = args
        .l2_rpc_url
        .ok_or_else(|| anyhow::anyhow!("--l2-rpc-url is required for `prove`"))?;
    let source = RpcWitnessSource::new(&l2_url)
        .map_err(|e| anyhow::anyhow!("failed to build L2 witness source: {e}"))?;
    let guest_dist = args.guest_dist.unwrap_or_else(default_guest_dist);

    let disclosure = match args.statement {
        ProveStatement::BalanceOf(a) => DisclosureRequest::BalanceOf {
            batch_number: a.batch_number,
            address: a.address,
        },
        ProveStatement::ObservableBytecodeHash(a) => DisclosureRequest::ObservableBytecodeHash {
            batch_number: a.batch_number,
            address: a.address,
        },
        ProveStatement::TxInclusion(a) => DisclosureRequest::TxInclusion {
            batch_number: a.batch_number,
            tx_hash: a.tx_hash,
        },
    };

    eprintln!(
        "Proving {:?} (batch {}) via {}...",
        discriminant_name(&disclosure),
        disclosure.batch_number(),
        l2_url
    );
    let bundle = prove_from_source(&guest_dist, &source, disclosure)
        .map_err(|e| anyhow::anyhow!("prove_from_source failed: {e}"))?;

    let bytes = bundle
        .encode()
        .map_err(|e| anyhow::anyhow!("bundle encode failed: {e}"))?;
    std::fs::write(&args.out, &bytes)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", args.out.display()))?;
    eprintln!(
        "Wrote proof bundle ({} bytes) to {}",
        bytes.len(),
        args.out.display()
    );
    Ok(())
}

fn run_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", args.input.display()))?;
    let bundle = ProofBundle::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("bundle decode failed: {e}"))?;

    let l1 = RpcL1Source::new(&args.l1_rpc_url, args.diamond_proxy)
        .map_err(|e| anyhow::anyhow!("failed to build L1 source: {e}"))?;
    let guest_dist = args.guest_dist.unwrap_or_else(default_guest_dist);

    let verified = verify_bundle(&guest_dist, &bundle, &l1)
        .map_err(|e| anyhow::anyhow!("verify_bundle failed: {e}"))?;

    print_verified(&verified);
    Ok(())
}

fn run_inspect(args: InspectArgs) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", args.input.display()))?;
    let bundle = ProofBundle::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("bundle decode failed: {e}"))?;

    println!("Bundle at {}", args.input.display());
    println!("  format version: {}", prividium_sd_host::BUNDLE_FORMAT_VERSION);
    println!("  statement id:   {}", bundle.statement_id_raw);
    match bundle.statement_id() {
        Ok(id) => println!("  statement:      {:?}", id),
        Err(e) => println!("  statement:      (invalid: {})", e),
    }
    println!("  batch number:   {}", bundle.batch_number);
    println!("  l1 commitment:  0x{}", hex::encode(bundle.l1_commitment));
    println!("  params ({}B):  0x{}", bundle.params_bytes.len(), hex::encode(&bundle.params_bytes));
    match &bundle.dev_only {
        Some(dev) => println!("  dev input words: {}", dev.input_words.len()),
        None => println!("  dev_only:       (none — real-backend bundle)"),
    }
    Ok(())
}

fn print_verified(verified: &VerifiedDisclosure) {
    println!("Verified: {:?}", verified.statement_id());
    println!("  batch number:  {}", verified.batch_number());
    println!("  l1 commitment: 0x{}", hex::encode(verified.l1_commitment()));
    match verified {
        VerifiedDisclosure::BalanceOf { params, .. } => {
            println!("  address:       0x{}", hex::encode(params.address));
            println!("  balance (be):  0x{}", hex::encode(params.balance));
        }
        VerifiedDisclosure::ObservableBytecodeHash { params, .. } => {
            println!("  address:       0x{}", hex::encode(params.address));
            println!(
                "  obh:           0x{}",
                hex::encode(params.observable_bytecode_hash)
            );
        }
        VerifiedDisclosure::TxInclusion { params, .. } => {
            println!("  block number:  {}", params.block_number);
            println!("  tx hash:       0x{}", hex::encode(params.tx_hash));
        }
    }
}

fn discriminant_name(req: &DisclosureRequest) -> &'static str {
    match req {
        DisclosureRequest::BalanceOf { .. } => "balance_of",
        DisclosureRequest::ObservableBytecodeHash { .. } => "observable_bytecode_hash",
        DisclosureRequest::TxInclusion { .. } => "tx_inclusion",
    }
}
