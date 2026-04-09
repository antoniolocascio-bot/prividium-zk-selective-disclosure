# prividium-sd-core

`no_std` + `alloc` shared logic for Prividium selective-disclosure proofs.

This crate is linked by both:

1. The airbender guest binary in `../guest`, which imports it to implement
   statement verification inside the riscv32 VM.
2. The native `../test-fixtures` crate, which imports it to build and
   decode witnesses against a real `TestingTree` from `zksync-os`.

There must be exactly one implementation of every cryptographic and
encoding primitive — no native / guest duplication. The RustCrypto
`blake2` and `sha3` crates compile cleanly for both `x86_64-unknown-linux-
gnu` and `riscv32im-risc0-zkvm-elf` in `no_std` mode, which is how we
achieve that.

## Modules

| Module | Role |
|---|---|
| `hash` | Blake2s-256 / Keccak256 one-shot + streaming wrappers |
| `tree::key` | Flat-key derivation (`blake2s(pad32(addr) \|\| key)`), account-properties slot helper |
| `tree::merkle` | `FlatStorageLeaf`, `LeafProof`, `AccountMerkleProof`, `recompute_root`, `verify_account_proof` |
| `account_properties` | 124-byte `AccountProperties` BE layout, encoder/decoder, `compute_hash` |
| `state_commitment` | `ChainStateCommitment::compute` → blake2s |
| `stored_batch_info` | Hand-rolled ABI encoder for 9-word `StoredBatchInfo` + keccak256 |
| `rlp` | Port of `basic_bootloader::bootloader::rlp` (used only by `block_header`) |
| `block_header` | ZKsync OS `BlockHeader` struct + `hash()` via RLP + keccak |
| `tx_rolling_hash` | `TxRollingHasher` (Keccak rolling accumulator for `transactions_root`) |
| `params` | Fixed-layout public-parameter structs per statement |
| `pub_input` | `keccak256(statement_id \|\| batch_number \|\| l1 \|\| params)`, plus 32-byte ↔ `[u32; 8]` packing |
| `statement_id` | `StatementId` enum with stable u32 discriminants |
| `witness` | `ByteReader` / `ByteWriter` with explicit error reporting |
| `statements` | Per-statement `verify(bytes) -> Result<[u8; 32], StatementError>` |

## Witness format

Every witness is a contiguous byte string. There is no serde, no framing,
no self-description — the guest decodes field-by-field in the exact order
each statement expects. The primitive types used in the layout below are:

| Token | Encoding |
|---|---|
| `u32_be` | 4 big-endian bytes |
| `u64_be` | 8 big-endian bytes |
| `u64_le` | 8 little-endian bytes |
| `[N]` | `N` raw bytes, no length prefix |
| `vec<[N]> max M` | `u32_be` length then `length * N` bytes; decoder rejects if `length > M` |
| `bool` | 1 byte, must be `0x00` or `0x01` (any other value is an error) |
| `enum tag` | 1 byte (0 = first variant, 1 = second, …) |

Shared sub-structures used by multiple statements:

```
ChainStateCommitment :=
    state_root: [32]
    next_free_slot: u64_be
    block_number: u64_be
    last_256_block_hashes_blake: [32]
    last_block_timestamp: u64_be

L1VerificationData :=
    number_of_layer1_txs: [32]          // uint256 BE
    priority_operations_hash: [32]
    dependency_roots_rolling_hash: [32]
    l2_logs_tree_root: [32]
    commitment: [32]

LeafProof :=
    index: u64_be
    leaf_key: [32]
    leaf_value: [32]
    leaf_next: u64_be
    path: 64 * [32]                     // uncompressed, TestingTree shape

AccountMerkleProof :=
    tag: enum tag
    tag == 0: LeafProof                 // Existing
    tag == 1: LeafProof LeafProof       // NonExisting (left, right)

BlockHeader :=
    parent_hash: [32]
    ommers_hash: [32]
    beneficiary: [20]
    state_root: [32]
    transactions_root: [32]
    receipts_root: [32]
    logs_bloom: [256]
    difficulty: [32]                    // U256 BE
    number: u64_be
    gas_limit: u64_be
    gas_used: u64_be
    timestamp: u64_be
    extra_data_len: u32_be              // ≤ 32, else LengthOverflow
    extra_data: extra_data_len * u8
    mix_hash: [32]
    nonce: [8]
    base_fee_per_gas: u64_be
```

### `balance_of` witness

```
batch_number: u64_be
l1_commitment: [32]
address: [20]
balance: [32]
ChainStateCommitment
L1VerificationData
AccountMerkleProof
account_properties_preimage: [124]
```

### `observable_bytecode_hash` witness

```
batch_number: u64_be
l1_commitment: [32]
address: [20]
observable_bytecode_hash: [32]
ChainStateCommitment
L1VerificationData
AccountMerkleProof
account_properties_preimage: [124]
```

### `tx_inclusion` witness

```
batch_number: u64_be
l1_commitment: [32]
block_number: u64_be
tx_hash: [32]
ChainStateCommitment
L1VerificationData
block_hashes_window: 256 * [32]         // oldest first
selected_block_index: u32_be            // < 256
BlockHeader
block_tx_hashes: vec<[32]> max 65536
tx_index: u32_be                        // < block_tx_hashes.len()
```

## Public-input commitment

The guest commits

```
pub_input = keccak256(
      statement_id.to_be_bytes(4)
   || batch_number.to_be_bytes(8)
   || l1_commitment
   || statement_params
)
```

packed as `[u32; 8]` via [`pub_input::pack_to_words`] (big-endian: byte
`4*i..4*i+4` becomes word `i`). The verifier reconstructs the bytes via
`pub_input::unpack_from_words`.

`statement_params` byte layouts:

| Statement | `statement_id` | `statement_params` |
|---|---|---|
| `BalanceOf` | `1` | `address[20] \|\| balance[32]` |
| `ObservableBytecodeHash` | `2` | `address[20] \|\| observable_bytecode_hash[32]` |
| `TxInclusion` | `3` | `block_number_be8[8] \|\| tx_hash[32]` |
