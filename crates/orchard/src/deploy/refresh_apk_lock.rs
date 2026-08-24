//! `orchard refresh-apk-lock`: regenerate `crates/image-builder/pinned-apks.toml`
//! from `apk-world.toml` — resolve the runtime closure + pin the build-inputs, verify-before-record.
//! The committed lock's diff is the reviewable surface. Mirrors `update-cert-fingerprints` (a
//! deploy-host operator command; thin CLI arm, testable orchestration in the lib). Spec:
                                                                           

use std::path::{Path, PathBuf};

use recipes_image_builder::HttpFetcher;
use recipes_image_builder::apk_world::ApkWorld;
use recipes_image_builder::generate_lock::{ContainerResolver, generate_lock};

use crate::deploy::build_image::load_trusted_keys;

#[derive(Debug, thiserror::Error)]
pub enum RefreshApkLockError {
    #[error(transparent)]
    Gen(#[from] recipes_image_builder::generate_lock::GenError),
    #[error("apk-world.toml parse failed: {0}")]
    World(#[from] recipes_image_builder::AcquireError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

pub struct RefreshApkLockOpts {
    /// The recipes repo root — `apk-world.toml`, the Alpine trust anchors, and the lock all live
    /// under `crates/image-builder/`.
    pub repo_root: PathBuf,
    /// The pinned build-container image ref the apk closure resolution runs in.
    pub container_image: String,
}

/// Regenerate `pinned-apks.toml` from `apk-world.toml`; returns the written lock path. Fail-closed:
/// a resolve/fetch/provenance failure aborts WITHOUT writing a partial lock.
pub fn refresh_apk_lock(opts: &RefreshApkLockOpts) -> Result<PathBuf, RefreshApkLockError> {
    let ib = opts.repo_root.join("crates/image-builder");
    let read = |p: &Path| -> Result<String, RefreshApkLockError> {
        std::fs::read_to_string(p).map_err(|source| RefreshApkLockError::Io {
            path: p.display().to_string(),
            source,
        })
    };
    let world = ApkWorld::from_toml_str(&read(&ib.join("apk-world.toml"))?)?;
    let trusted = load_trusted_keys(&ib.join("alpine-trusted-keys"))
        .map_err(|e| RefreshApkLockError::Other(e.to_string()))?;

    let resolver = ContainerResolver::new(opts.container_image.clone());
    let fetcher = HttpFetcher::new();
                                                                                                       
    let lock = generate_lock(&world, &resolver, &fetcher, &trusted)?;

    let lock_path = ib.join("pinned-apks.toml");
    std::fs::write(&lock_path, lock).map_err(|source| RefreshApkLockError::Io {
        path: lock_path.display().to_string(),
        source,
    })?;
    Ok(lock_path)
}
