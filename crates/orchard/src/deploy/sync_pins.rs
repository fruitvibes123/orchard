//! `orchard sync-pins [--check]`: propagate the central `pins.toml` into the two files
//! that are format-locked to external tools and so can't read it at runtime — `rust-toolchain.toml`
//! (rustup) and the image-builder `Containerfile` (FROM base + the PGP-verified Rust-toolchain block,
//! Docker). Write mode regenerates them;
//! `--check` fails closed on drift, sharing `Pins::check_drift` with the `tests/pins_drift.rs`
//! make-verify gate so the CLI and the gate can never disagree. See `pins.toml`'s header for the
//! bump procedure.

use std::path::{Path, PathBuf};

use recipes_image_builder::pins::Pins;

#[derive(Debug, thiserror::Error)]
pub enum SyncPinsError {
    #[error(transparent)]
    Pins(#[from] recipes_image_builder::pins::PinsError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("generated files have drifted from pins.toml — run `orchard sync-pins`: {0}")]
    Drift(String),
}

pub struct SyncPinsOpts {
    pub repo_root: PathBuf,
    /// Verify-only: fail closed on drift instead of rewriting (the make-verify / CI shape).
    pub check: bool,
}

/// The two files `sync-pins` owns, relative to the repo root.
const RUST_TOOLCHAIN: &str = "rust-toolchain.toml";
const CONTAINERFILE: &str = "crates/image-builder/Containerfile";

/// Regenerate (or, with `check`, verify) the format-locked files from `pins.toml`. Returns the human
/// summary line for the CLI.
pub fn sync_pins(opts: &SyncPinsOpts) -> Result<String, SyncPinsError> {
    let pins = Pins::load(&opts.repo_root)?;

    if opts.check {
        let drifted = pins.check_drift(&opts.repo_root)?;
        if !drifted.is_empty() {
            return Err(SyncPinsError::Drift(drifted.join("; ")));
        }
        return Ok("deploy sync-pins --check: all generated files match pins.toml".to_string());
    }

    write(
        &opts.repo_root.join(RUST_TOOLCHAIN),
        &pins.render_rust_toolchain_toml(),
    )?;
    let cf_path = opts.repo_root.join(CONTAINERFILE);
    let containerfile = read(&cf_path)?;
    write(&cf_path, &pins.sync_containerfile(&containerfile)?)?;
    Ok(format!(
        "deploy sync-pins: regenerated {RUST_TOOLCHAIN} + synced {CONTAINERFILE} (FROM base + Rust-toolchain block) from pins.toml"
    ))
}

fn read(path: &Path) -> Result<String, SyncPinsError> {
    std::fs::read_to_string(path).map_err(|source| SyncPinsError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn write(path: &Path, contents: &str) -> Result<(), SyncPinsError> {
    std::fs::write(path, contents).map_err(|source| SyncPinsError::Io {
        path: path.display().to_string(),
        source,
    })
}
