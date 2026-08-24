//! grocer — the narrow pin-store publisher.
//!
//! Writes pre-built artifacts into the sha256 artifact-store + `published-pins.toml`, ONLY to the explicit
//! `--store`/`--published-out` paths it is handed (no env redirect, no real-path fallback) — so handing it
//! STAGED paths makes a `market upgrade` pin-bump atomic by construction. Replaces the per-repo `publish.sh`
                                                                                                              

pub mod crosscheck;
pub mod elf_assert;
pub mod publish;
pub mod publish_manifest;

pub use publish::{run, Args};
