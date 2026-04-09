#![no_std]
#![no_main]

extern crate alloc;

use airbender::guest::{commit, exit_error, read};
use alloc::vec::Vec;
use prividium_sd_core::pub_input;
use prividium_sd_core::statement_id::StatementId;
use prividium_sd_core::statements;

/// Prividium selective-disclosure guest.
///
/// Input protocol (pushed by the host via `Inputs::push`, in this
/// exact order):
///
/// 1. `u32` — the `StatementId` tag (1 = BalanceOf, 2 =
///    ObservableBytecodeHash, 3 = TxInclusion).
/// 2. `Vec<u8>` — the statement-specific witness bytes in the hand-
///    rolled format defined by `prividium_sd_core::statements::*`.
///
/// Any decoding or verification failure calls `exit_error()` rather
/// than panicking, so the host receipt cleanly reports failure rather
/// than running to `panic_abort`.
///
/// On success the guest commits the 32-byte public-input commitment
/// packed as an `[u32; 8]` to registers `x10..x17`.
#[airbender::main]
fn main() {
    let id_raw: u32 = match read() {
        Ok(v) => v,
        Err(_) => exit_error(),
    };
    let id = match StatementId::try_from(id_raw) {
        Ok(id) => id,
        Err(_) => exit_error(),
    };
    let witness: Vec<u8> = match read() {
        Ok(v) => v,
        Err(_) => exit_error(),
    };

    let hash = match statements::verify(id, &witness) {
        Ok(h) => h,
        Err(_) => exit_error(),
    };

    commit(pub_input::pack_to_words(&hash));
}
