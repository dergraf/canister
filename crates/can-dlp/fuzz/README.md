# can-dlp fuzzing

LibFuzzer targets for the DLP detector / decode / normalize pipeline.

## Prerequisites

- Linux (libFuzzer is Linux-only via the rustc nightly sanitiser).
- `rustup toolchain install nightly`
- `cargo install cargo-fuzz`

## Running

From the `crates/can-dlp/fuzz/` directory:

```
cargo +nightly fuzz run fuzz_decode_layers
cargo +nightly fuzz run fuzz_normalize
cargo +nightly fuzz run fuzz_unescape
cargo +nightly fuzz run fuzz_detectors
cargo +nightly fuzz run fuzz_full_scanner
```

Each target runs indefinitely until a crash is found or you Ctrl-C. To
cap a run, pass `-- -max_total_time=300` (seconds).

## Corpus

`cargo-fuzz` automatically creates `corpus/<target>/` directories with
the inputs it generates. Crashing inputs land in `artifacts/<target>/`
named `crash-<sha>`. Commit interesting ones (especially regression
seeds) to `corpus/<target>/`; they are picked up on subsequent runs.

## Why these targets

- `fuzz_decode_layers` — the BFS / dedup / fragment-aware decode in
  `decode.rs` is the most complex piece of byte-mangling in the crate.
  Hard-cap on layer count is asserted to catch BFS explosions.
- `fuzz_normalize` / `fuzz_unescape` — the two normalisation passes
  must always terminate and never grow input beyond bounded factors.
- `fuzz_detectors` — guards against regex panics on malformed UTF-8
  edge cases.
- `fuzz_full_scanner` — covers interactions: decompression failures
  feeding into decode, decode feeding into regex with weird unicode
  classes, etc.

## Not in the workspace

This crate is intentionally **not** in the root `Cargo.toml` workspace
members list — libfuzzer-sys requires nightly + special build flags and
would break `cargo build --workspace` on stable.
