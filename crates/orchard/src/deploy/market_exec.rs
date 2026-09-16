                                                                                                             
//! PURE `Vec<Step>`, this is where those steps actually MUTATE the pin store — but never destructively:
//! every write is directed into a temporary STAGE, `market verify` runs against the staged result, and the
//! real trees + the shared artifact-store are touched ONLY by the final SWAP, which runs ONLY on full green.
//!
//! ## Why an overlay stage (not file overrides)
//! The hot-path [`crate::deploy::market::verify`] reads the orchard tree + the sibling repos + the cookbook
//! cert trail through paths relative to one `repo_root`. To verify the STAGED result with that code
//! UNCHANGED, the stage is an **overlay ecosystem root**: a temp dir mirroring the real layout where every
//! unchanged file is a symlink read-through to the real tree and every staged write is a real file shadowing
//! it. `verify` simply runs with `repo_root = <stage>/…/orchard`. A gap in the overlay can only make the
//! staged verify FAIL (a missing read → fail-closed), never silently pass a bad state — so incompleteness is
//! safe by construction.
//!
//! The ONE exception to symlink-overlay is `orchard/vendor/`: §3a-3 re-TARS it, and `tar` archives a symlink
//! as a symlink (not its content), which would corrupt the re-derived sha. So `vendor/` is COPIED (real
//! files) into the stage; everything else (read by sha/parse/cert-scan, which follow symlinks to content) is
//! symlinked. Sibling repos + the store + the cert trail are single dir-symlinks, copied-up on demand when a
//! step writes under them.
//!
//! ## Atomicity (AC5)
//! `execute` runs every step's effect into the stage, then `verify(&stage)`, then `stage.swap()`. A failure
//! at ANY step or at the staged verify returns BEFORE `swap` — so every real tree + the store is byte-identical
//! to the pre-run state (the stage is a temp dir that drops). The swap is the LAST + shortest step: N
//! per-file renames (same-dir atomic, with an EXDEV copy fallback). POSIX has no atomic multi-rename, so a
//! crash mid-swap leaves a partial state that re-running `market verify` DETECTS (the half-swapped store reds)
//! and re-running `market upgrade` RECOVERS. The tool NEVER auto-commits — the operator reviews the diff.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use recipes_image_builder::artifact_store::{StoreName, parse_store_name};
use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest};
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::market_upgrade::{Step, UpgradeError};

/// The real filesystem locations one `market upgrade` may touch, resolved from the manifests + the cwd. Every
/// staged path is computed as the same offset from a staged orchard root, so the overlay mirrors reality.
pub struct StoreLayout {
    /// The orchard repo root (holds `consume-pins.toml`, `vendor/`, `pins.toml`, the build).
    pub orchard_root: PathBuf,
    /// The shared artifact-store (C5-resolved at the CLI: the context chain's store value).
    pub store: PathBuf,
    /// The repo-manifest PATH the run resolved (C5); handed verbatim to grocer so a staged
    /// publish reads the SAME manifest this run's verify used, even under --repo-manifest.
    pub repo_manifest: PathBuf,
    /// repo name -> resolved real repo dir (the publish.sh + `published-pins.toml` owner).
    pub repos: BTreeMap<String, PathBuf>,
                                                                                   
    pub cert_trail: Option<PathBuf>,
}

/// Resolve the real layout from the repo-manifest (repo paths are joined lexically onto `orchard_root`,
/// exactly as `verify` resolves them).
pub fn resolve_layout(
    manifest: &RepoManifest,
    orchard_root: PathBuf,
    store: PathBuf,
    repo_manifest: PathBuf,
) -> StoreLayout {
    let repos = manifest
        .repos
        .iter()
        .map(|(name, e)| (name.clone(), orchard_root.join(&e.path)))
        .collect();
    let cert_trail = manifest.cert_trail_path(&orchard_root);
    StoreLayout {
        orchard_root,
        store,
        repo_manifest,
        repos,
        cert_trail,
    }
}

impl StoreLayout {
    /// The owning repo's `published-pins.toml` (the publish.sh `PUBLISHED_OUT` target).
    fn published_pins(&self, repo: &str) -> Option<PathBuf> {
        self.repos.get(repo).map(|d| d.join("published-pins.toml"))
    }
    /// Every external (non-orchard) dir the overlay must expose for `verify`: the sibling repos, the store,
    /// and the cert trail.
    fn externals(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.repos.values().cloned().collect();
        v.push(self.store.clone());
        if let Some(t) = &self.cert_trail {
            v.push(t.clone());
        }
        v
    }
}

                                                                                                         

/// Collapse `.`/`..` lexically (no symlink resolution). For absolute paths the leading root is preserved.
/// `pub(crate)`: `git_commit::bucket_of` reuses THIS normalizer for its prefix matching (one lexical
/// collapse in the crate — two would drift), since layout-derived paths carry embedded `..`.
pub(crate) fn normalize(p: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push(comp);
                }
            }
            c => out.push(c),
        }
    }
    out.iter().map(|c| c.as_os_str()).collect()
}

/// The lexical relative path from `base` to `target` (both NORMALIZED absolute), emitting `..` for each base
/// component past the common prefix. `relativize(/a/orchard, /a/seed-vault) == ../seed-vault`.
fn relativize(base: &Path, target: &Path) -> PathBuf {
    let b: Vec<Component> = base.components().collect();
    let t: Vec<Component> = target.components().collect();
    let mut i = 0;
    while i < b.len() && i < t.len() && b[i] == t[i] {
        i += 1;
    }
    let mut rel = PathBuf::new();
    for _ in i..b.len() {
        rel.push("..");
    }
    for c in &t[i..] {
        rel.push(c.as_os_str());
    }
    rel
}

/// Recursively copy `src` into `dst` (files by content, symlinks by re-link). Used to materialize the
/// vendor/ overlay (real files for the §3a-3 re-tar) and as the swap's cross-filesystem fallback.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_symlink() {
            symlink(fs::read_link(&from)?, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

                                                                                                        

/// One pending swap: a staged artifact + its real destination. Applied (and only applied) by [`Stage::swap`]
/// after the staged verify is green.
enum Swap {
    /// A single staged file replaces a real file (atomic same-dir rename; EXDEV copy fallback).
    File { staged: PathBuf, real: PathBuf },
    /// A staged directory replaces a real directory wholesale (re-vendored `vendor/`): rename the real dir
    /// aside, rename the staged dir in, drop the aside.
    Tree { staged: PathBuf, real: PathBuf },
}

impl Swap {
    fn real(&self) -> &Path {
        match self {
            Swap::File { real, .. } | Swap::Tree { real, .. } => real,
        }
    }
}

                                                                                                        

/// A staging overlay for one `market upgrade`. Constructed mirroring the real ecosystem subtree; steps write
/// into it via [`Stage::stage_write`]/[`Stage::stage_tree`]; the real trees change ONLY at [`Stage::swap`].
pub struct Stage {
    /// Keeps the temp dir alive until `swap` (or drop) — the whole overlay lives under it.
    _tmp: TempDir,
    /// The real orchard root, NORMALIZED (the bijection anchor for staged-path computation).
    orchard_root_n: PathBuf,
    /// The staged orchard root (`<tmp>/<eco>/<orchard>`) — `verify`'s `repo_root`.
    stage_orchard: PathBuf,
    /// Pending (staged -> real) moves, applied in order by `swap`.
    swaps: Vec<Swap>,
    /// Staged dirs already materialized as real overlay dirs (idempotency for the copy-up walk).
    populated: HashSet<PathBuf>,
}

impl Stage {
    /// Build the overlay: a temp ecosystem root with the orchard overlaid (children symlinked, `vendor/`
    /// COPIED), and each sibling repo / the store / the cert trail exposed as a single read-through dir-symlink.
    /// The temp dir is created beside the real trees (same filesystem) so the swap renames are atomic.
    pub fn new(layout: &StoreLayout) -> Result<Self, UpgradeError> {
        let orchard_root_n = normalize(&layout.orchard_root);
        let orchard_name = orchard_root_n
            .file_name()
            .ok_or_else(|| io::Error::other("orchard root has no final component"))?
            .to_owned();
        let eco_name = orchard_root_n
            .parent()
            .and_then(|p| p.file_name())
            .ok_or_else(|| io::Error::other("orchard root has no parent component"))?
            .to_owned();

                                                                                                        
                                                                                                           
        let mut builder = tempfile::Builder::new();
        builder.prefix("market-stage-");
        let tmp = match orchard_root_n.parent().and_then(|p| p.parent()) {
            Some(base) if base.is_dir() => builder.tempdir_in(base),
            _ => builder.tempdir(),
        }
        .map_err(UpgradeError::Io)?;

        let stage_eco = tmp.path().join(&eco_name);
        let stage_orchard = stage_eco.join(&orchard_name);
        fs::create_dir_all(&stage_eco).map_err(UpgradeError::Io)?;

        let mut stage = Stage {
            _tmp: tmp,
            orchard_root_n: orchard_root_n.clone(),
            stage_orchard: stage_orchard.clone(),
            swaps: Vec::new(),
            populated: HashSet::new(),
        };

                                                                                                           
                                                               
        fs::create_dir(&stage_orchard).map_err(UpgradeError::Io)?;
        for entry in fs::read_dir(&orchard_root_n).map_err(UpgradeError::Io)? {
            let entry = entry.map_err(UpgradeError::Io)?;
            let name = entry.file_name();
            let dst = stage_orchard.join(&name);
            if name == "vendor" && entry.path().is_dir() {
                copy_dir_recursive(&entry.path(), &dst).map_err(UpgradeError::Io)?;
            } else {
                symlink(entry.path(), &dst).map_err(UpgradeError::Io)?;
            }
        }
        stage.populated.insert(stage_orchard);

                                                                                                             
                                                                                                                
        for real in layout.externals() {
            let real_n = normalize(&real);
            if !real_n.exists() {
                continue;
            }
            let staged = stage.stage_path_of(&real_n);
            if let Some(parent) = staged.parent() {
                fs::create_dir_all(parent).map_err(UpgradeError::Io)?;
            }
            if !staged.exists() && !staged.is_symlink() {
                symlink(&real_n, &staged).map_err(UpgradeError::Io)?;
            }
        }

        Ok(stage)
    }

    /// `verify`'s `repo_root` for the staged result.
    pub fn verify_root(&self) -> &Path {
        &self.stage_orchard
    }

    /// The staged location mirroring `real` — the same lexical offset from the staged orchard as `real` has
    /// from the real orchard (works for orchard-internal paths AND `../sibling` / `../../recipes` paths).
    fn stage_path_of(&self, real: &Path) -> PathBuf {
        let real_n = normalize(real);
        let rel = relativize(&self.orchard_root_n, &real_n);
        normalize(&self.stage_orchard.join(rel))
    }

    /// Materialize `real_dir`'s staged counterpart as a REAL overlay directory (symlinking each child to the
    /// real one), replacing any read-through dir-symlink. Idempotent; recurses up so the parent is real first.
    fn ensure_real_dir(&mut self, real_dir: &Path) -> io::Result<PathBuf> {
        let real_dir = normalize(real_dir);
        let staged = self.stage_path_of(&real_dir);
        if self.populated.contains(&staged) {
            return Ok(staged);
        }
                                                                            
        if let (Some(real_parent), Some(staged_parent)) = (real_dir.parent(), staged.parent()) {
            let parent_real_dir = staged_parent.is_dir() && !staged_parent.is_symlink();
            if !parent_real_dir {
                self.ensure_real_dir(real_parent)?;
            }
        }
                                                                                                       
        if staged.is_symlink() {
            fs::remove_file(&staged)?;
        }
        if !staged.exists() {
            fs::create_dir(&staged)?;
        }
        for entry in fs::read_dir(&real_dir)? {
            let entry = entry?;
            let child = staged.join(entry.file_name());
            if !child.exists() && !child.is_symlink() {
                symlink(entry.path(), &child)?;
            }
        }
        self.populated.insert(staged.clone());
        Ok(staged)
    }

    /// Reserve a staged path for a single-file write to `real_file`: copy-up the parent chain (so siblings
    /// stay read-through), shadow the read-through symlink with a real COPY of the current content, record the
    /// swap, and return the staged path for the caller to read-modify-write. The real file is NOT touched
                                                                                                          
    /// `sync_pins`) read the staged path before overwriting it, so it must hold the current content, never be
    /// empty; a whole-file writer (publish.sh via `PUBLISHED_OUT=`) simply overwrites the copy.
    pub fn stage_write(&mut self, real_file: &Path) -> Result<PathBuf, UpgradeError> {
        let real_file = normalize(real_file);
        let parent = real_file
            .parent()
            .ok_or_else(|| io::Error::other("staged file has no parent"))
            .map_err(UpgradeError::Io)?;
        self.ensure_real_dir(parent).map_err(UpgradeError::Io)?;
        let staged = self.stage_path_of(&real_file);
                                                                                                        
        if staged.is_symlink() || staged.exists() {
            if staged.is_dir() && !staged.is_symlink() {
                fs::remove_dir_all(&staged).map_err(UpgradeError::Io)?;
            } else {
                fs::remove_file(&staged).map_err(UpgradeError::Io)?;
            }
        }
                                                                                                             
                                                                                                             
                                                                                 
        if real_file.is_file() {
            fs::copy(&real_file, &staged).map_err(UpgradeError::Io)?;
        }
        self.record_swap(Swap::File {
            staged: staged.clone(),
            real: real_file,
        });
        Ok(staged)
    }

    /// Reserve a staged DIRECTORY for a wholesale rewrite of `real_dir` (the re-vendored `vendor/`): copy-up
    /// to the parent, replace the staged dir with an EMPTY real dir for the caller to fill, and record a tree
    /// swap (the whole real dir is replaced, dropping any stale entries).
    pub fn stage_tree(&mut self, real_dir: &Path) -> Result<PathBuf, UpgradeError> {
        let real_dir = normalize(real_dir);
        let parent = real_dir
            .parent()
            .ok_or_else(|| io::Error::other("staged dir has no parent"))
            .map_err(UpgradeError::Io)?;
        self.ensure_real_dir(parent).map_err(UpgradeError::Io)?;
        let staged = self.stage_path_of(&real_dir);
        if staged.is_symlink() {
            fs::remove_file(&staged).map_err(UpgradeError::Io)?;
        } else if staged.is_dir() {
            fs::remove_dir_all(&staged).map_err(UpgradeError::Io)?;
        }
        fs::create_dir(&staged).map_err(UpgradeError::Io)?;
        self.record_swap(Swap::Tree {
            staged: staged.clone(),
            real: real_dir,
        });
        Ok(staged)
    }

    /// Materialize the staged artifact-store as a SYMLINK-FREE real dir for a `publish.sh` shell-out
                                                                                                             
    /// from the staged store), and every other store entry's symlink is REMOVED (the staged hot-path verify
    /// never reads the store; publish writes its own repo's fresh artifacts). With ZERO symlinks remaining, a
    /// `cp "$src" "$STORE/$key"` for ANY key — even one outside the repo's manifest set — lands in the stage,
    /// so it can NEVER follow a symlink into the REAL store before the swap. Returns the staged store path.
    fn symlink_free_store(
        &mut self,
        real_store: &Path,
        source_keys: &std::collections::BTreeSet<String>,
    ) -> Result<PathBuf, UpgradeError> {
        let staged = self.ensure_real_dir(real_store).map_err(UpgradeError::Io)?;
        for entry in fs::read_dir(&staged).map_err(UpgradeError::Io)? {
            let entry = entry.map_err(UpgradeError::Io)?;
            let path = entry.path();
            if !path.is_symlink() {
                continue;
            }
            let target = fs::read_link(&path).map_err(UpgradeError::Io)?;
            fs::remove_file(&path).map_err(UpgradeError::Io)?;
                                                                                                   
                                                                                                      
                                                                                               
                                                                               
            let is_source = entry
                .file_name()
                .to_str()
                .map(|name| match parse_store_name(name) {
                    StoreName::Revision { key, .. } | StoreName::Alias { key } => {
                        source_keys.contains(&key)
                    }
                    StoreName::Foreign => false,
                })
                .unwrap_or(false);
            if is_source {
                fs::copy(&target, &path).map_err(UpgradeError::Io)?;
            }
        }
        Ok(staged)
    }

    /// Record a swap, replacing any prior entry for the same real path (a later step's write wins).
    fn record_swap(&mut self, swap: Swap) {
        let real = swap.real().to_path_buf();
        self.swaps.retain(|s| s.real() != real);
        self.swaps.push(swap);
    }

    /// THE SWAP — the last + shortest step. Move every staged artifact onto its real destination (N renames,
    /// NOT one atomic multi-rename). Runs ONLY after the staged verify is green; consumes the stage so the
    /// temp dir drops once the renames are done. Returns the real paths swapped (the operator's diff surface).
    pub fn swap(self) -> Result<Vec<PathBuf>, UpgradeError> {
        let mut swapped = Vec::with_capacity(self.swaps.len());
        for s in &self.swaps {
            match s {
                Swap::File { staged, real } => {
                    replace_file(staged, real).map_err(UpgradeError::Io)?
                }
                Swap::Tree { staged, real } => {
                    replace_tree(staged, real).map_err(UpgradeError::Io)?
                }
            }
            swapped.push(s.real().to_path_buf());
        }
        Ok(swapped)
    }
}

/// Move `staged` onto `real` (same-dir atomic rename; on a cross-filesystem error, copy into a sibling temp
/// in the target dir then atomic same-dir rename).
fn replace_file(staged: &Path, real: &Path) -> io::Result<()> {
    if let Some(parent) = real.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::rename(staged, real).is_ok() {
        return Ok(());
    }
    let tmp = real.with_extension("market-swap-tmp");
    fs::copy(staged, &tmp)?;
    fs::rename(&tmp, real)
}

/// Replace the real directory `real` with `staged` wholesale: rename the real dir aside (same-dir, atomic),
/// rename the staged dir in (cross-fs copy fallback), drop the aside.
fn replace_tree(staged: &Path, real: &Path) -> io::Result<()> {
    let aside = real.with_extension("market-old");
    let _ = fs::remove_dir_all(&aside);
    if real.exists() {
        fs::rename(real, &aside)?;
    } else if let Some(parent) = real.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::rename(staged, real).is_err() {
        copy_dir_recursive(staged, real)?;
    }
    let _ = fs::remove_dir_all(&aside);
    Ok(())
}

                                                                                                        

/// The side-effecting per-step operations, behind a trait so the atomicity test fakes the (docker/network)
/// builds while exercising the REAL stage + verify + swap. The real impl is [`ShellStepExec`].
pub trait StepExec {
    /// Perform `step`'s effect, directing EVERY write into `stage` (via `stage_write`/`stage_tree`); never a
    /// real path. A returned error aborts the upgrade BEFORE the swap (the trees stay untouched).
    fn exec(&mut self, step: &Step, stage: &mut Stage) -> Result<(), UpgradeError>;
}

/// What `execute` did (printed for the operator; the swap is NOT committed — the diff is theirs to review).
#[derive(Debug)]
pub struct UpgradeReport {
    /// The real paths the swap moved into place.
    pub swapped: Vec<PathBuf>,
}

/// Run `steps` atomically (AC5): every effect into a fresh stage, then `verify` the staged result, then swap.
/// `verify` is injected so the operator path runs the real `market verify` and the test can force a fail; ANY
/// failure (step or verify) returns BEFORE the swap, leaving every real tree + the store untouched.
pub fn execute(
    steps: &[Step],
    layout: &StoreLayout,
    exec: &mut dyn StepExec,
    verify: &dyn Fn(&Stage) -> Result<(), UpgradeError>,
) -> Result<UpgradeReport, UpgradeError> {
    let mut stage = Stage::new(layout)?;
    for step in steps {
        exec.exec(step, &mut stage)?;
    }
    verify(&stage)?;
    let swapped = stage.swap()?;
    Ok(UpgradeReport { swapped })
}

                                                                                                        

                                                                                                             
/// re-implementation): `Publish` runs the `grocer` publisher with the staged `--store`/`--published-out` (no
                                                                                                                                      
/// orchard as their root; `Repin` rewrites the staged `consume-pins.toml` from the staged `published-pins.toml`;
/// `BumpUpstream` writes the staged `pins.toml`. The docker/network legs are operator-exercised (the atomicity
/// machinery is what the build-time test proves).
pub struct ShellStepExec<'a> {
    pub layout: &'a StoreLayout,
    pub manifest: &'a RepoManifest,
    pub consume: &'a PinManifest,
    /// The pinned build-container ref for an `--apks` closure re-resolution (`RefreshApkLock`); required only
    /// for that leg.
    pub apk_container_image: Option<String>,
    /// The build-only handoff dir holding the pre-built binaries — required for a per-binary publish
    /// (`--binary`); grocer reads + ELF-asserts each binary from here. `None` for source/apk/kernel legs.
    pub build_dir: Option<PathBuf>,
    /// Transport for the `--kernel` bump (`BumpUpstream { which: "kernel" }`): injectable so the
    /// produced-bytes gate fakes ONLY the network while the whole verify path runs real. `None` on
    /// runs that never bump — a plan that unexpectedly carries one then fails closed pre-fetch.
    pub kernel_fetcher: Option<&'a dyn recipes_image_builder::Fetcher>,
    /// Transport for the `--rust` bump (`BumpUpstream { which: "rust" }`, Component C): the release
    /// manifest fetcher, injectable like `kernel_fetcher`. `None` on non-rust runs (fail-closed).
    pub rust_fetcher: Option<&'a dyn recipes_image_builder::Fetcher>,
    /// The container rebuilder for the `--rust` cascade (`RebuildContainer`): injectable so the tests +
    /// the produced-bytes gate fake the docker builds. `None` on non-rust runs (fail-closed).
    pub container_builder: Option<&'a dyn ContainerBuilder>,
    /// Set by `RebuildContainer` to the reproducible image digest — the subsequent `--rust` publishes
                                                                                                     
    /// outside a rust cascade (the publishes then use the operator's pre-built `--build-dir` handoff).
    pub rebuilt_digest: Option<String>,
}

/// The result of ONE container build: the runnable image reference + the reproducible content identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltImage {
    /// The `docker run` reference (the `--iidfile` image id). NOTE: the image *config* carries a
    /// per-build `created` timestamp, so this id is NOT stable across builds — it is the RUNNABLE
    /// handle, pinned as `container_digest` for the by-digest per-repo compiles.
    pub image_id: String,
    /// The REPRODUCIBLE content identity — the image's RootFS layer digests (content-addressed). Two
    /// builds of a deterministic Containerfile yield the SAME rootfs even though the image ids differ;
    /// this is what the double-build reproducibility check compares (a drift here = a toolchain/base
                          
    pub rootfs: String,
}

/// The container rebuilder for the `--rust` cascade (§7) — a seam so the atomicity/gate tests fake the
/// docker builds while exercising the REAL stage + digest pin + swap. `build_once` performs ONE
/// `docker build`; `RebuildContainer` calls it TWICE (the second with `no_cache = true` — a genuine
                                                                                           
/// [`BuiltImage::rootfs`] (not the timestamped image id) for the double-build reproducibility check.
pub trait ContainerBuilder {
    fn build_once(
        &self,
        containerfile: &Path,
        context: &Path,
        no_cache: bool,
    ) -> Result<BuiltImage, String>;
}

/// The real docker-shelling rebuilder (operator path + the produced-bytes gate). `docker build
/// --iidfile` captures the runnable image id; `docker inspect …RootFS.Layers` captures the reproducible
/// content identity. `no_cache` forces the second build to re-execute every layer (so the repro check
/// is genuine, not a cache tautology). `SOURCE_DATE_EPOCH` alone does NOT make layers deterministic —
/// layer tars embed file mtimes, which land at wall clock; the `REWRITE_TIMESTAMP_OUTPUT` exporter
/// attr is what clamps them to the epoch (2026-07-23 finding: without it the double-build comparison
/// fails on ANY recipe whose RUN steps write files).
pub struct DockerContainerBuilder {
    pub source_date_epoch: u64,
}

/// The image-exporter argv that makes layer diff-ids deterministic under `SOURCE_DATE_EPOCH`:
/// `rewrite-timestamp=true` clamps layer-tar file mtimes to the epoch; `unpack=false` is MANDATORY —
/// rewrite-timestamp conflicts with the containerd store's default unpack (`docker run` unpacks on
/// demand; `--iidfile` is still written). Preconditions + the HONEST failure chain (audit R1, both
                                                                                                      
/// own builder (pinned below via `--builder default`). A non-containerd daemon rejects `type=image`
/// itself LOUDLY (before this attr is evaluated). A pre-0.13 BuildKit instead ACCEPTS the attr and
/// silently ignores it — no error, mtimes stay wall-clock (empirically proven at v0.12.5) — and the
/// double-build rootfs comparison + the armed gate's epoch-0 probe assert then abort fail-closed.
/// Never a silently-un-rewritten image that PINS; on a too-old BuildKit the symptom is the
/// repro-abort, whose error text names the BuildKit version as the first suspect.
const REWRITE_TIMESTAMP_OUTPUT: &str = "type=image,rewrite-timestamp=true,unpack=false";

impl ContainerBuilder for DockerContainerBuilder {
    fn build_once(
        &self,
        containerfile: &Path,
        context: &Path,
        no_cache: bool,
    ) -> Result<BuiltImage, String> {
        let iid = tempfile::NamedTempFile::new().map_err(|e| format!("iidfile: {e}"))?;
        let mut cmd = Command::new("docker");
        cmd.arg("build")
            .env("SOURCE_DATE_EPOCH", self.source_date_epoch.to_string())
            .arg("--iidfile")
            .arg(iid.path())
            .arg("--build-arg")
            .arg(format!("SOURCE_DATE_EPOCH={}", self.source_date_epoch))
            .arg("--output")
            .arg(REWRITE_TIMESTAMP_OUTPUT)
                                                                                                      
                                                                                                   
                                                                            
            .arg("--builder")
            .arg("default");
        if no_cache {
            cmd.arg("--no-cache");
        }
        let status = cmd
            .arg("-f")
            .arg(containerfile)
            .arg(context)
            .status()
            .map_err(|e| format!("docker build: {e}"))?;
        if !status.success() {
            return Err("docker build failed (see docker output)".into());
        }
        let image_id = fs::read_to_string(iid.path())
            .map_err(|e| format!("read iidfile: {e}"))?
            .trim()
            .to_string();
                                                                                                 
                                                              
        let out = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{.RootFS.Layers}}")
            .arg(&image_id)
            .output()
            .map_err(|e| format!("docker inspect: {e}"))?;
        if !out.status.success() {
            return Err("docker inspect (RootFS) failed".into());
        }
        let rootfs = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(BuiltImage { image_id, rootfs })
    }
}

impl StepExec for ShellStepExec<'_> {
    fn exec(&mut self, step: &Step, stage: &mut Stage) -> Result<(), UpgradeError> {
        match step {
            Step::Publish { repo, binary: _ } => self.publish(repo, stage),
            Step::PublishConfigSubset { repo, key } => self.publish_config_subset(repo, key, stage),
            Step::Vendor => self.vendor(stage),
            Step::RefreshApkLock => self.refresh_apk(stage),
            Step::SyncPins => self.sync_pins(stage),
            Step::RebuildContainer => self.rebuild_container(stage),
            Step::BumpUpstream { which, version } => self.bump_upstream(which, version, stage),
            Step::Repin { keys } => self.repin(keys, stage),
        }
    }
}

impl ShellStepExec<'_> {
    fn step_err(step: &str, detail: impl ToString) -> UpgradeError {
        UpgradeError::StepFailed {
            step: step.to_string(),
            detail: detail.to_string(),
        }
    }

    /// Run `grocer` (the narrow publisher) with the STAGED `--store`/`--published-out` so every byte it
                                                                                                  
    /// `repo-manifest.toml`/`consume-pins.toml` (so it resolves the repo's path to the LIVE source it tars,
    /// and the kinds/keys it cross-checks are the authoritative ones) but WRITES only the two staged paths it
                                                                                                              
    /// incl. ones owned by repos NOT republished this run — is copied in as a real file so the `Vendor` leg
    /// finds them, grocer overwrites its own repo's source keys atomically, and the repo's published store
    /// entries are recorded for the swap.
    fn publish(&self, repo: &str, stage: &mut Stage) -> Result<(), UpgradeError> {
        let repo_owns_binary = self
            .manifest
            .repos
            .get(repo)
            .map(|e| {
                e.artifacts.iter().any(|k| {
                    self.consume.artifacts.get(k).map(|p| p.kind) == Some(ArtifactKind::Binary)
                })
            })
            .unwrap_or(false);
                                                                                                        
                                                                                                   
                                                                                                           
        let _cascade_guard: Option<tempfile::TempDir> =
            match (&self.rebuilt_digest, repo_owns_binary) {
                (Some(digest), true) => Some(self.build_repo_in_container(repo, digest)?),
                _ => None,
            };
        let build_dir: Option<PathBuf> = _cascade_guard
            .as_ref()
            .map(|d| d.path().to_path_buf())
            .or_else(|| self.build_dir.clone());
                                                                                                    
                                                                                                       
                                                                                                          
                                                                
        if repo_owns_binary && build_dir.is_none() {
            return Err(Self::step_err(
                "publish",
                format!(
                    "publishing {repo:?} requires --build-dir <handoff>: it owns binary artifacts and \
                     grocer republishes the whole manifest — run {repo}'s build-only.sh first"
                ),
            ));
        }
                                                                                       
        self.layout
            .repos
            .get(repo)
            .ok_or_else(|| Self::step_err("publish", format!("no path for repo {repo:?}")))?;
        let staged_pub = stage.stage_write(
            &self
                .layout
                .published_pins(repo)
                .expect("repo is in the layout"),
        )?;

                                                                                                               
                                                                                                              
                                                
        let source_keys: std::collections::BTreeSet<String> = self
            .consume
            .artifacts
            .iter()
            .filter(|(_, p)| p.kind == ArtifactKind::Source)
            .map(|(k, _)| k.clone())
            .collect();
        let staged_store = stage.symlink_free_store(&self.layout.store, &source_keys)?;

                                                                                                           
                                                         
        let grocer = Self::grocer_path()?;
        let real_repo_manifest = self.layout.repo_manifest.clone();
        let real_consume_pins = self.layout.orchard_root.join("consume-pins.toml");
        let out = Self::grocer_command(
            &grocer,
            repo,
            &real_repo_manifest,
            &real_consume_pins,
            &staged_store,
            &staged_pub,
                                                                                                          
                                                                                                            
            build_dir.as_deref(),
            false,                                                          
            None,                                                                          
        )
        .output()
        .map_err(|e| Self::step_err(&format!("publish {repo}"), e))?;
        if !out.status.success() {
            return Err(Self::step_err(
                &format!("publish {repo}"),
                String::from_utf8_lossy(&out.stderr),
            ));
        }

                                                                                                               
                                                                                                      
        self.record_published_swaps(repo, &staged_pub, &staged_store, stage)
    }

                                                                                                          
    /// targeted `kind=config` artifact. UNLIKE [`Self::publish`] it NEVER computes `repo_owns_binary` /
    /// requires a `--build-dir` (a config re-pin has no binary to build). It records the SCOPED CAS swap for
    /// this ONE key (the revision-must-land assert unweakened) and BYTE-CHECKS its staged revision against
    /// the just-written pin, so a corrupted staged store entry fails BEFORE the swap. Targeting one key is
    /// the M1 fold: grocer never republishes a SIBLING config, so a sibling ahead of its pin can't red the
    /// staged verify + wedge the leg.
    fn publish_config_subset(
        &self,
        repo: &str,
        key: &str,
        stage: &mut Stage,
    ) -> Result<(), UpgradeError> {
        self.layout.repos.get(repo).ok_or_else(|| {
            Self::step_err("publish-config", format!("no path for repo {repo:?}"))
        })?;
        let staged_pub = stage.stage_write(
            &self
                .layout
                .published_pins(repo)
                .expect("repo is in the layout"),
        )?;
                                                                                                        
                                                                                                           
        let source_keys: std::collections::BTreeSet<String> = self
            .consume
            .artifacts
            .iter()
            .filter(|(_, p)| p.kind == ArtifactKind::Source)
            .map(|(k, _)| k.clone())
            .collect();
        let staged_store = stage.symlink_free_store(&self.layout.store, &source_keys)?;
        let grocer = Self::grocer_path()?;
        let real_repo_manifest = self.layout.repo_manifest.clone();
        let real_consume_pins = self.layout.orchard_root.join("consume-pins.toml");
        let out = Self::grocer_command(
            &grocer,
            repo,
            &real_repo_manifest,
            &real_consume_pins,
            &staged_store,
            &staged_pub,
            None,                                                            
            true,                       
            Some(key),                                                                                   
        )
        .output()
        .map_err(|e| Self::step_err(&format!("publish-config {repo}"), e))?;
        if !out.status.success() {
            return Err(Self::step_err(
                &format!("publish-config {repo}"),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
                                                                                                       
                                                                                                           
                    
        let config_keys = [key.to_string()];
        self.record_published_swaps_scoped(repo, &config_keys, &staged_pub, &staged_store, stage)?;
        self.staged_store_hash_check(&staged_store, &staged_pub, key)?;
        Ok(())
    }

    /// Record the store files a staged publish produced, for the swap — for each manifest key of
                                                                                                     
    /// dual-write transition) AND the `<key>@<sha>` revision, the sha read from the staged
    /// published-pins grocer just wrote. The revision name is CONSTRUCTED (manifest key + pins
    /// sha), never globbed, and re-checked through the ONE name classifier before any join. A pins
    /// entry whose revision file is MISSING from the staged store is a HARD step error — the write
    /// half must never silently drop a revision, or the coexistence guarantee goes undelivered
                                                                                               
    fn record_published_swaps(
        &self,
        repo: &str,
        staged_pub: &Path,
        staged_store: &Path,
        stage: &mut Stage,
    ) -> Result<(), UpgradeError> {
        let Some(entry) = self.manifest.repos.get(repo) else {
            return Ok(());
        };
        let step = format!("publish {repo}");
        for key in &entry.artifacts {
            self.record_one_published_swap(key, &step, staged_pub, staged_store, stage)?;
        }
        Ok(())
    }

    /// Record swaps for EXACTLY `keys` (the config-subset case — grocer published only these) with the
    /// SAME revision-must-land assert as the whole-repo [`Self::record_published_swaps`] (spec §4.6 write
                                                                                      
    fn record_published_swaps_scoped(
        &self,
        repo: &str,
        keys: &[String],
        staged_pub: &Path,
        staged_store: &Path,
        stage: &mut Stage,
    ) -> Result<(), UpgradeError> {
        let step = format!("publish-config {repo}");
        for key in keys {
            self.record_one_published_swap(key, &step, staged_pub, staged_store, stage)?;
        }
        Ok(())
    }

    /// Record the swap for ONE published key — both name shapes (the flat alias + the `<key>@<sha>`
    /// revision, the sha read from the staged published-pins grocer just wrote). The revision name is
    /// CONSTRUCTED (manifest key + pins sha), never globbed, and re-checked through the ONE name classifier
                                                                                                           
                                                                                                           
    /// Shared by the whole-repo + the config-subset recorders, so the subset's assert is identical.
    fn record_one_published_swap(
        &self,
        key: &str,
        step: &str,
        staged_pub: &Path,
        staged_store: &Path,
        stage: &mut Stage,
    ) -> Result<(), UpgradeError> {
        let sha = read_published_sha(staged_pub, key).map_err(|e| Self::step_err(step, e))?;
        let rev = format!("{key}@{sha}");
        if !matches!(parse_store_name(&rev), StoreName::Revision { .. }) {
            return Err(Self::step_err(
                step,
                format!(
                    "published key {key:?} + staged sha does not form a conforming \
                     <key>@<sha> revision name: {rev:?}"
                ),
            ));
        }
                                                                                                           
                                                                                                  
        let staged_key = staged_store.join(key);
        if staged_key.is_file() && !staged_key.is_symlink() {
            stage.record_swap(Swap::File {
                staged: staged_key,
                real: self.layout.store.join(key),
            });
        }
                                                                                 
        let staged_rev = staged_store.join(&rev);
        if staged_rev.is_file() && !staged_rev.is_symlink() {
            stage.record_swap(Swap::File {
                staged: staged_rev,
                real: self.layout.store.join(&rev),
            });
        } else {
            return Err(Self::step_err(
                step,
                format!(
                    "staged store is missing the {rev} revision for published key {key:?} — \
                     refusing to record a flat-only swap (the write half: a revision \
                     must never die with the stage's temp dir)"
                ),
            ));
        }
        Ok(())
    }

    /// The config-subset "staged byte-check" (the explicit verify beyond the hot-path staged `market
    /// verify`): read the `<key>@<sha>` revision grocer just wrote into the STAGED store, re-hash it, and
    /// assert it equals the pinned sha. A corrupted/lying staged config revision fails BEFORE the swap, so
    /// the real store never receives config bytes that don't match the pin the consume-splice records.
    fn staged_store_hash_check(
        &self,
        staged_store: &Path,
        staged_pub: &Path,
        key: &str,
    ) -> Result<(), UpgradeError> {
        let step = "publish-config staged-verify";
        let sha = read_published_sha(staged_pub, key).map_err(|e| Self::step_err(step, e))?;
        let rev = format!("{key}@{sha}");
        if !matches!(parse_store_name(&rev), StoreName::Revision { .. }) {
            return Err(Self::step_err(
                step,
                format!("non-conforming revision name {rev:?} for key {key:?}"),
            ));
        }
        let path = staged_store.join(&rev);
        let bytes = std::fs::read(&path)
            .map_err(|e| Self::step_err(step, format!("read staged {rev}: {e}")))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != sha {
            return Err(Self::step_err(
                step,
                format!("staged store {rev} hashes to {actual}, not the pinned {sha} — refusing"),
            ));
        }
        Ok(())
    }

    /// Locate the `grocer` binary next to the running orchard binary (same workspace target dir) — the
    /// operator and the executor invoke the IDENTICAL binary (no operator-vs-executor drift).
    fn grocer_path() -> Result<PathBuf, UpgradeError> {
        let exe = std::env::current_exe().map_err(UpgradeError::Io)?;
        let dir = exe.parent().ok_or_else(|| {
            UpgradeError::Io(std::io::Error::other("orchard exe has no parent dir"))
        })?;
        Ok(dir.join("grocer"))
    }

    /// Build the `grocer` invocation: destinations are the STAGED store + published-pins; NO `STORE=`/
                                                                                                             
    /// repo also passes the build-only handoff as `--build-dir` so grocer can locate + ELF-assert each
    /// pre-built binary; source/config-only publishes pass `None` (F-2ES-R1-9 — the Arg was inert). A
    /// testable seam. A TARGETED config subset also passes `--config-key <key>` (publish exactly that one
    /// config — the M1 fold). (9 distinct Command inputs — the same builder shape as the dryrun installers'
    /// `#[allow]`; grouping into a struct buys no safety here and the self-tests assert the argv.)
    #[allow(clippy::too_many_arguments)]
    fn grocer_command(
        grocer: &Path,
        repo: &str,
        repo_manifest: &Path,
        consume_pins: &Path,
        store: &Path,
        published_out: &Path,
        build_dir: Option<&Path>,
        only_configs: bool,
        config_key: Option<&str>,
    ) -> Command {
        let mut c = Command::new(grocer);
        c.arg("--repo")
            .arg(repo)
            .arg("--repo-manifest")
            .arg(repo_manifest)
            .arg("--consume-pins")
            .arg(consume_pins)
            .arg("--store")
            .arg(store)
            .arg("--published-out")
            .arg(published_out);
        if let Some(bd) = build_dir {
            c.arg("--build-dir").arg(bd);
        }
        if only_configs {
            c.arg("--only-configs");
        }
        if let Some(k) = config_key {
            c.arg("--config-key").arg(k);
        }
        c
    }

    /// `orchard vendor` run with the staged orchard as its root + the staged store as its input — re-vendors
    /// every source drop into the staged `vendor/`, verifying each store tar's sha against the (already
    /// re-pinned) staged `consume-pins.toml`.
    fn vendor(&self, stage: &mut Stage) -> Result<(), UpgradeError> {
        stage.stage_tree(&self.layout.orchard_root.join("vendor"))?;
        let staged_store = stage.stage_path_of(&self.layout.store);
        let root = stage.verify_root().to_path_buf();
        super::vendor_cmd::vendor(&root, &staged_store).map_err(|e| Self::step_err("vendor", e))?;
        Ok(())
    }

    /// `orchard refresh-apk-lock` run against the staged orchard — re-resolve + dual-verify the apk closure,
    /// rewriting the staged `pinned-apks.toml`.
    fn refresh_apk(&self, stage: &mut Stage) -> Result<(), UpgradeError> {
        let container_image = self.apk_container_image.clone().ok_or_else(|| {
            Self::step_err(
                "refresh-apk-lock",
                "an apk closure re-resolution needs --container-image (the pinned build image)",
            )
        })?;
        stage.stage_write(
            &self
                .layout
                .orchard_root
                .join("crates/image-builder/pinned-apks.toml"),
        )?;
        let opts = super::refresh_apk_lock::RefreshApkLockOpts {
            repo_root: stage.verify_root().to_path_buf(),
            container_image,
        };
        super::refresh_apk_lock::refresh_apk_lock(&opts)
            .map_err(|e| Self::step_err("refresh-apk-lock", e))?;
        Ok(())
    }

    /// `orchard sync-pins` run against the staged orchard — regenerate the format-locked files
    /// (`rust-toolchain.toml` and the `Containerfile` FROM) from the (already bumped) staged `pins.toml`. Both
    /// targets are staged first so `sync_pins`'s `fs::write` creates real staged files instead of following
    /// the read-through symlinks.
    fn sync_pins(&self, stage: &mut Stage) -> Result<(), UpgradeError> {
        stage.stage_write(&self.layout.orchard_root.join("rust-toolchain.toml"))?;
        stage.stage_write(
            &self
                .layout
                .orchard_root
                .join("crates/image-builder/Containerfile"),
        )?;
        let opts = super::sync_pins::SyncPinsOpts {
            repo_root: stage.verify_root().to_path_buf(),
            check: false,
        };
        super::sync_pins::sync_pins(&opts).map_err(|e| Self::step_err("sync-pins", e))?;
        Ok(())
    }

    /// Fetch + PGP-verify the upstream artifact for a new `kernel`/`rust` `version` and write it into
    /// the staged `pins.toml` copies. The KERNEL leg is live (`kernel_bump::bump_kernel` — cashew
    /// verify against the vendored keyring, nothing pinned on any failure); the RUST leg stays
    /// fail-closed until Component C (the rust re-pin) lands — never pin an unverified sum.
    fn bump_upstream(
        &self,
        which: &str,
        version: &str,
        stage: &mut Stage,
    ) -> Result<(), UpgradeError> {
        match which {
            "kernel" => {
                let fetch = self.kernel_fetcher.ok_or_else(|| {
                    Self::step_err(
                        "bump-upstream",
                        "no kernel fetcher configured for this run (internal wiring error) — \
                         nothing fetched, nothing pinned",
                    )
                })?;
                let bump = super::kernel_bump::KernelBump {
                    fetch,
                    now: std::time::SystemTime::now(),
                    tar_ceiling: super::kernel_bump::KERNEL_TAR_CEILING,
                    signer_fprs: super::kernel_bump::KERNEL_ORG_SIGNER_FPRS,
                };
                super::kernel_bump::bump_kernel(&bump, version, self.layout, stage)
            }
            "rust" => {
                let fetch = self.rust_fetcher.ok_or_else(|| {
                    Self::step_err(
                        "bump-upstream",
                        "no rust fetcher configured for this run (internal wiring error) — \
                         nothing fetched, nothing pinned",
                    )
                })?;
                let bump = super::rust_bump::RustBump {
                    fetch,
                    now: std::time::SystemTime::now(),
                    signer_fpr: super::rust_bump::RUST_SIGNER_FPR,
                };
                super::rust_bump::bump_rust(&bump, version, self.layout, stage)
            }
            _ => Err(Self::step_err(
                "bump-upstream",
                format!(
                    "fetching + verifying the upstream signed sum for {which} {version} is not wired \
                     (fail-closed: never pin an unverified sum)"
                ),
            )),
        }
    }

    /// `RebuildContainer` (§7): rebuild the self-assembled build container from the just-synced staged
    /// Containerfile, DOUBLE-build for reproducibility, and pin the resulting image digest as
    /// `[rust].container_digest` in every staged pins.toml. The digest is captured on `self` so the
    /// subsequent `--rust` publishes compile each repo BY DIGEST. A non-reproducible rebuild aborts
    /// pre-swap (a toolchain/base drift surfaced, never silently pinned). The docker builds are a
    /// shell-out (operator path / the produced-bytes gate); the tests fake the `ContainerBuilder`.
    fn rebuild_container(&mut self, stage: &mut Stage) -> Result<(), UpgradeError> {
        let builder = self.container_builder.ok_or_else(|| {
            Self::step_err(
                "rebuild-container",
                "no container builder configured for this run (internal wiring error)",
            )
        })?;
        let containerfile = stage
            .verify_root()
            .join("crates/image-builder/Containerfile");
        let context = stage.verify_root().join("crates/image-builder");
        let b1 = builder
            .build_once(&containerfile, &context, false)
            .map_err(|e| Self::step_err("rebuild-container", e))?;
                                                                                                     
                                                                                                             
        let b2 = builder
            .build_once(&containerfile, &context, true)
            .map_err(|e| Self::step_err("rebuild-container", e))?;
                                                                                       
        if b1.rootfs != b2.rootfs {
            return Err(Self::step_err(
                "rebuild-container",
                format!(
                    "non-reproducible rebuild: rootfs {} != {} — a toolchain/base drift surfaced; \
                     nothing pinned (the double-build reproducibility gate). If the \
                     recipe is clean, check BuildKit >= 0.13: an older buildkit silently ignores \
                     the rewrite-timestamp exporter attr and every rebuild then diverges on layer \
                     mtimes",
                    b1.rootfs, b2.rootfs
                ),
            ));
        }
                                                                                                         
        let digest = b1.image_id;
        let mut targets: Vec<PathBuf> = vec![self.layout.orchard_root.join("pins.toml")];
        targets.extend(self.layout.repos.values().map(|d| d.join("pins.toml")));
        for real in targets {
            let staged = stage.stage_write(&real)?;
            let cur = fs::read_to_string(&staged).map_err(|e| {
                Self::step_err(
                    "rebuild-container",
                    format!("read staged {}: {e}", staged.display()),
                )
            })?;
            let rewritten =
                super::rust_bump::rewrite_container_digest(&cur, &digest).map_err(|e| {
                    Self::step_err("rebuild-container", format!("{}: {e}", real.display()))
                })?;
            fs::write(&staged, rewritten).map_err(UpgradeError::Io)?;
        }
        self.rebuilt_digest = Some(digest);
        Ok(())
    }

    /// The `docker run` that compiles one repo's binaries INSIDE the just-built container, referenced
    /// BY DIGEST (`self.rebuilt_digest` — never a mutable tag, so a concurrent `docker build` elsewhere
                                                                                                        
    /// repo is bind-mounted read-only and the handoff is the writable output the publish then hands to
    /// grocer.
    fn build_only_command(
        image_digest: &str,
        repo_dir: &Path,
        handoff: &Path,
        build_script: &str,
    ) -> Command {
        let mut c = Command::new("docker");
        c.arg("run")
            .arg("--rm")
            .arg("-v")
            .arg(format!("{}:/repo:ro", repo_dir.display()))
            .arg("-v")
            .arg(format!("{}:/out", handoff.display()))
            .arg(image_digest)                                                       
            .arg(format!("/repo/{build_script}"))
            .arg("--out")
            .arg("/out");
        c
    }

    /// Compile one repo's binaries in the rebuilt container BY DIGEST (§7) → a temp handoff dir the
    /// publish hands to grocer. The docker run is the operator path / the produced-bytes gate; the
    /// build-only invocation references the image by its immutable digest, never a mutable tag.
    fn build_repo_in_container(&self, repo: &str, digest: &str) -> Result<TempDir, UpgradeError> {
        let repo_dir = self.layout.repos.get(repo).ok_or_else(|| {
            Self::step_err("build-in-container", format!("no path for repo {repo:?}"))
        })?;
        let handoff = tempfile::tempdir().map_err(UpgradeError::Io)?;
        let out = Self::build_only_command(digest, repo_dir, handoff.path(), "build-only.sh")
            .output()
            .map_err(|e| Self::step_err(&format!("build-in-container {repo}"), e))?;
        if !out.status.success() {
            return Err(Self::step_err(
                &format!("build-in-container {repo}"),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        Ok(handoff)
    }

    /// Rewrite the staged `consume-pins.toml`, setting each `key`'s `sha256` to the value the owning repo's
    /// (staged) `published-pins.toml` now carries. Pure file I/O (no build) — the testable leg.
    fn repin(&self, keys: &[String], stage: &mut Stage) -> Result<(), UpgradeError> {
                                                                               
        let mut new_shas: BTreeMap<&str, String> = BTreeMap::new();
        for key in keys {
            let (repo, _) = self
                .manifest
                .owner_of(key)
                .ok_or_else(|| Self::step_err("re-pin", format!("no owner for {key:?}")))?;
            let pub_path = stage.stage_path_of(
                &self
                    .layout
                    .published_pins(repo)
                    .expect("owner is in the layout"),
            );
            let sha =
                read_published_sha(&pub_path, key).map_err(|e| Self::step_err("re-pin", e))?;
            new_shas.insert(key, sha);
        }
                                                                                                
                                                                                                
                                                                                                    
                                                                                                   
                                                                                 
        let staged_consume =
            stage.stage_write(&self.layout.orchard_root.join("consume-pins.toml"))?;
        let mut text = fs::read_to_string(&staged_consume).map_err(|e| {
            Self::step_err("re-pin", format!("read {}: {e}", staged_consume.display()))
        })?;
        for (key, sha) in &new_shas {
            text = rewrite_consume_sha(&text, key, sha).map_err(|e| Self::step_err("re-pin", e))?;
        }
                                                                                                 
                                                                                        
        let doc: toml::Value = toml::from_str(&text).map_err(|e| {
            Self::step_err("re-pin", format!("surgical rewrite no longer parses: {e}"))
        })?;
        for (key, sha) in &new_shas {
            let landed = doc
                .get("artifacts")
                .and_then(|a| a.get(*key))
                .and_then(|p| p.get("sha256"))
                .and_then(|v| v.as_str());
            if landed != Some(sha.as_str()) {
                return Err(Self::step_err(
                    "re-pin",
                    format!("surgical rewrite did not land artifacts.{key}.sha256"),
                ));
            }
        }
        fs::write(&staged_consume, text).map_err(UpgradeError::Io)?;
        Ok(())
    }
}

/// Surgically rewrite `sha256 = "<hex>"` inside the `[artifacts.<key>]` table of a
/// consume-pins.toml TEXT, preserving every other byte — comments (the file's header is
/// load-bearing trust-model documentation), entry order, spacing, inline notes. Line-anchored
/// matching only: the table header must be exactly `[artifacts.<key>]` on its own (trimmed) line —
/// a COMMENT naming the table never matches (the rfind-comment-trap class). Fail-CLOSED: a
/// missing table, a duplicate table, no live `sha256 =` line inside the table's span, or a
/// non-64-lowercase-hex replacement is an `Err` — never a silent append, resort, or wrong-table
/// write.
fn rewrite_consume_sha(src: &str, key: &str, new_sha: &str) -> Result<String, String> {
    if new_sha.len() != 64
        || !new_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "refusing a malformed replacement sha for {key}: {new_sha:?} (need 64 lowercase hex)"
        ));
    }
                                                                               
    let lines: Vec<&str> = src.split('\n').collect();
    let header = format!("[artifacts.{key}]");
    let headers: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == header)
        .map(|(i, _)| i)
        .collect();
    let start = match headers.as_slice() {
        [] => return Err(format!("consume-pins has no {header} table")),
        [one] => *one,
        _ => {
            return Err(format!(
                "consume-pins has {} {header} tables (ambiguous)",
                headers.len()
            ));
        }
    };
                                                                                                
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| l.trim_start().starts_with('['))
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
                                                                                               
                                                                                                   
                                                                                                  
                                                                                                
                                         
    let is_sha_line = |line: &str| {
        let rest = line.trim_start();
        rest.strip_prefix("sha256")
            .is_some_and(|after| after.trim_start().starts_with('='))
    };
    let mut sha_line: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if is_sha_line(line) {
            if sha_line.is_some() {
                return Err(format!("{header} has multiple sha256 lines (ambiguous)"));
            }
            sha_line = Some(i);
        }
    }
    let i = sha_line.ok_or_else(|| format!("{header} has no sha256 line in its span"))?;
    let line = lines[i];
    let open = line
        .find('"')
        .ok_or_else(|| format!("{header} sha256 line has no quoted value: {line:?}"))?;
    let close_rel = line[open + 1..]
        .find('"')
        .ok_or_else(|| format!("{header} sha256 line has no closing quote: {line:?}"))?;
    let rebuilt = format!(
        "{}{}{}",
        &line[..=open],
        new_sha,
        &line[open + 1 + close_rel..]
    );
    let mut out_lines: Vec<&str> = lines.clone();
    out_lines[i] = &rebuilt;
    Ok(out_lines.join("\n"))
}

/// Read `key`'s sha from a flat `[artifacts] key = "sha"` `published-pins.toml`.
fn read_published_sha(path: &Path, key: &str) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let doc: toml::Value = toml::from_str(&text).map_err(|e| e.to_string())?;
    doc.get("artifacts")
        .and_then(|a| a.get(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{} has no artifacts.{key}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grocer_command_carries_staged_paths_and_no_env_redirect() {
                                                                                                              
                                                                                               
        let cmd = ShellStepExec::grocer_command(
            Path::new("/some/target/grocer"),
            "seed-vault",
            Path::new("/real/orchard/repo-manifest.toml"),
            Path::new("/real/orchard/consume-pins.toml"),
            Path::new("/stage/eco/artifact-store"),
            Path::new("/stage/seed-vault/published-pins.toml"),
            None,
            false,                                                          
            None,                    
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .map(|i| args[i + 1].clone())
        };
        assert_eq!(after("--repo").as_deref(), Some("seed-vault"));
        assert_eq!(
            after("--store").as_deref(),
            Some("/stage/eco/artifact-store"),
            "the store destination must be the STAGED path"
        );
        assert_eq!(
            after("--published-out").as_deref(),
            Some("/stage/seed-vault/published-pins.toml"),
            "the published-pins destination must be the STAGED path"
        );
                                                                                                         
        assert!(
            !args.iter().any(|a| a == "--build-dir"),
            "a source publish must not pass --build-dir"
        );
                                                                                                    
        assert!(
            !args.iter().any(|a| a == "--only-configs"),
            "a whole-repo publish must not pass --only-configs"
        );
        assert!(
            !args.iter().any(|a| a == "--config-key"),
            "a whole-repo publish must not pass --config-key"
        );
                                                                             
        assert_eq!(
            cmd.get_envs().count(),
            0,
            "grocer must be invoked with NO env redirect"
        );
    }

    #[test]
    fn grocer_command_passes_build_dir_for_binary_targets() {
                                                                                                               
                                                                                                           
        let cmd = ShellStepExec::grocer_command(
            Path::new("/some/target/grocer"),
            "fruit-basket",
            Path::new("/real/orchard/repo-manifest.toml"),
            Path::new("/real/orchard/consume-pins.toml"),
            Path::new("/stage/eco/artifact-store"),
            Path::new("/stage/fruit-basket/published-pins.toml"),
            Some(Path::new("/stage/handoff")),
            false,                                                          
            None,                    
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .map(|i| args[i + 1].clone())
        };
        assert_eq!(
            after("--build-dir").as_deref(),
            Some("/stage/handoff"),
            "a binary target's publish must pass the build-only handoff as --build-dir"
        );
    }

    #[test]
    fn grocer_command_sets_only_configs_for_the_config_subset() {
                                                                                                       
                                                                                                           
                                                                                         
        let cmd = ShellStepExec::grocer_command(
            Path::new("/some/target/grocer"),
            "dha",
            Path::new("/real/orchard/repo-manifest.toml"),
            Path::new("/real/orchard/consume-pins.toml"),
            Path::new("/stage/eco/artifact-store"),
            Path::new("/stage/dha/published-pins.toml"),
            None,
            true,                                   
            Some("dha-epa-config"),                                         
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .map(|i| args[i + 1].clone())
        };
        assert!(
            args.iter().any(|a| a == "--only-configs"),
            "the config-subset publish must pass --only-configs, got {args:?}"
        );
        assert_eq!(
            after("--config-key").as_deref(),
            Some("dha-epa-config"),
            "a targeted config subset must pass --config-key <key>, got {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "--build-dir"),
            "a config-subset publish must not pass --build-dir (no binary to build)"
        );
    }

    #[test]
    fn normalize_collapses_dotdot() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(normalize(Path::new("/a/orchard/..")), PathBuf::from("/a"));
    }

    #[test]
    fn relativize_emits_dotdot_to_siblings() {
        assert_eq!(
            relativize(Path::new("/a/eco/orchard"), Path::new("/a/eco/seed-vault")),
            PathBuf::from("../seed-vault")
        );
        assert_eq!(
            relativize(Path::new("/a/eco/orchard"), Path::new("/a/recipes")),
            PathBuf::from("../../recipes")
        );
        assert_eq!(
            relativize(
                Path::new("/a/eco/orchard"),
                Path::new("/a/eco/orchard/vendor/x")
            ),
            PathBuf::from("vendor/x")
        );
    }

    /// Build a minimal real ecosystem (`<base>/eco/orchard` + a sibling) for the overlay tests.
    fn fixture() -> (TempDir, PathBuf, StoreLayout) {
        let base = tempfile::tempdir().unwrap();
        let orchard = base.path().join("eco/orchard");
        fs::create_dir_all(orchard.join("vendor")).unwrap();
        fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
        fs::write(
            crate::deploy::context::manifest_default(&orchard),
            "schema-version = 1\n",
        )
        .unwrap();
        fs::write(orchard.join("vendor/marker"), "v1").unwrap();
        let sibling = base.path().join("eco/seed-vault");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("published-pins.toml"), "orig").unwrap();
        let layout = StoreLayout {
            orchard_root: orchard.clone(),
            store: base.path().join("eco/artifact-store"),
            repo_manifest: crate::deploy::context::manifest_default(&orchard),
            repos: BTreeMap::from([("seed-vault".to_string(), sibling)]),
            cert_trail: None,
        };
        (base, orchard, layout)
    }

    #[test]
    fn overlay_reads_through_unstaged_files_and_copies_vendor() {
        let (_base, orchard, layout) = fixture();
        let stage = Stage::new(&layout).unwrap();
                                                                             
        assert_eq!(
            fs::read_to_string(stage.verify_root().join("consume-pins.toml")).unwrap(),
            "schema-version = 1\n"
        );
                                                                                                    
        let staged_vendor = stage.verify_root().join("vendor");
        assert!(staged_vendor.is_dir() && !staged_vendor.is_symlink());
        assert_eq!(
            fs::read_to_string(staged_vendor.join("marker")).unwrap(),
            "v1"
        );
                                                                             
        assert_eq!(
            fs::read_to_string(
                stage
                    .verify_root()
                    .join("../seed-vault/published-pins.toml")
            )
            .unwrap(),
            "orig"
        );
        let _ = orchard;
    }

    #[test]
    fn stage_write_does_not_touch_the_real_file_until_swap() {
        let (_base, _orchard, layout) = fixture();
        let real = layout.repos["seed-vault"].join("published-pins.toml");
        let mut stage = Stage::new(&layout).unwrap();
        let staged = stage.stage_write(&real).unwrap();
        fs::write(&staged, "NEW").unwrap();
                                                                              
        assert_eq!(fs::read_to_string(&real).unwrap(), "orig");
        assert_eq!(fs::read_to_string(&staged).unwrap(), "NEW");
                                    
        let swapped = stage.swap().unwrap();
        assert_eq!(swapped, vec![real.clone()]);
        assert_eq!(fs::read_to_string(&real).unwrap(), "NEW");
    }

    #[test]
    fn stage_tree_replaces_a_directory_wholesale() {
        let (_base, orchard, layout) = fixture();
        let real_vendor = orchard.join("vendor");
        fs::write(real_vendor.join("stale"), "old").unwrap();
        let mut stage = Stage::new(&layout).unwrap();
        let staged_vendor = stage.stage_tree(&real_vendor).unwrap();
        fs::write(staged_vendor.join("fresh"), "new").unwrap();
        stage.swap().unwrap();
                                                                                         
        assert_eq!(
            fs::read_to_string(real_vendor.join("fresh")).unwrap(),
            "new"
        );
        assert!(!real_vendor.join("stale").exists());
    }

    #[test]
    fn stage_write_preserves_the_original_content_for_read_modify_write() {
                                                                                                             
                                                                                             
        let (_base, _orchard, layout) = fixture();
        let real = layout.repos["seed-vault"].join("published-pins.toml");                
        let mut stage = Stage::new(&layout).unwrap();
        let staged = stage.stage_write(&real).unwrap();
        assert_eq!(
            fs::read_to_string(&staged).unwrap(),
            "orig",
            "the staged path must hold the current content for a read-after-stage"
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "orig", "real untouched");
    }

    #[test]
    fn symlink_free_store_copies_sources_and_removes_others() {
                                                                                                            
                                                                                                          
        let base = tempfile::tempdir().unwrap();
        let orchard = base.path().join("eco/orchard");
        fs::create_dir_all(orchard.join("vendor")).unwrap();
        fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
        fs::write(
            crate::deploy::context::manifest_default(&orchard),
            "schema-version = 1\n",
        )
        .unwrap();
        let store = base.path().join("eco/artifact-store");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("grape-src"), b"SRC").unwrap();                
        fs::write(store.join("fb-acme"), b"BIN").unwrap();            
        let layout = StoreLayout {
            repo_manifest: crate::deploy::context::manifest_default(&orchard),
            orchard_root: orchard,
            store: store.clone(),
            repos: BTreeMap::new(),
            cert_trail: None,
        };
        let mut stage = Stage::new(&layout).unwrap();
        let source_keys: std::collections::BTreeSet<String> =
            ["grape-src".to_string()].into_iter().collect();
        let staged_store = stage.symlink_free_store(&store, &source_keys).unwrap();
        for entry in fs::read_dir(&staged_store).unwrap() {
            let p = entry.unwrap().path();
            assert!(
                !p.is_symlink(),
                "no symlink may remain in the staged store: {p:?}"
            );
        }
        assert_eq!(
            fs::read(staged_store.join("grape-src")).unwrap(),
            b"SRC",
            "source copied"
        );
        assert!(!staged_store.join("fb-acme").exists(), "binary removed");
        assert_eq!(
            fs::read(store.join("fb-acme")).unwrap(),
            b"BIN",
            "real store untouched"
        );
    }

    #[test]
    fn symlink_free_store_keeps_source_revisions_and_aliases() {
                                                                                                   
                                                                                             
                                                                
        let base = tempfile::tempdir().unwrap();
        let orchard = base.path().join("eco/orchard");
        fs::create_dir_all(orchard.join("vendor")).unwrap();
        fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
        fs::write(
            crate::deploy::context::manifest_default(&orchard),
            "schema-version = 1\n",
        )
        .unwrap();
        let store = base.path().join("eco/artifact-store");
        fs::create_dir_all(&store).unwrap();
        let sha_a = "a".repeat(64);
        let sha_b = "b".repeat(64);
        fs::write(store.join(format!("grape-src@{sha_a}")), b"SRC-REV").unwrap();                            
        fs::write(store.join("grape-src"), b"SRC").unwrap();                         
        fs::write(store.join(format!("box-init@{sha_b}")), b"BINREV").unwrap();                               
        fs::write(store.join("junk@bad@name"), b"JUNK").unwrap();                       
        let layout = StoreLayout {
            repo_manifest: crate::deploy::context::manifest_default(&orchard),
            orchard_root: orchard,
            store: store.clone(),
            repos: BTreeMap::new(),
            cert_trail: None,
        };
        let mut stage = Stage::new(&layout).unwrap();
        let source_keys: std::collections::BTreeSet<String> =
            ["grape-src".to_string()].into_iter().collect();
        let staged_store = stage.symlink_free_store(&store, &source_keys).unwrap();
        for entry in fs::read_dir(&staged_store).unwrap() {
            let p = entry.unwrap().path();
            assert!(
                !p.is_symlink(),
                "no symlink may remain in the staged store: {p:?}"
            );
        }
        assert_eq!(
            fs::read(staged_store.join(format!("grape-src@{sha_a}"))).unwrap(),
            b"SRC-REV",
            "source revision copied"
        );
        assert_eq!(
            fs::read(staged_store.join("grape-src")).unwrap(),
            b"SRC",
            "source alias copied"
        );
        assert!(
            !staged_store.join(format!("box-init@{sha_b}")).exists(),
            "binary revision removed"
        );
        assert!(
            !staged_store.join("junk@bad@name").exists(),
            "foreign name removed"
        );
        assert_eq!(
            fs::read(store.join(format!("box-init@{sha_b}"))).unwrap(),
            b"BINREV",
            "real store untouched"
        );
    }

    /// Build the staged store + staged published-pins the way the publish step leaves them
    /// (writing the files directly — these tests exercise the RECORD loop, not grocer), for a
    /// one-key seed-vault manifest. Returns everything `record_published_swaps` consumes.
    fn record_fixture(
        sha: &str,
    ) -> (
        TempDir,
        StoreLayout,
        RepoManifest,
        PinManifest,
        Stage,
        PathBuf,
        PathBuf,
    ) {
        let (base, _orchard, layout) = fixture();
        fs::create_dir_all(&layout.store).unwrap();
        let manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n",
        )
        .unwrap();
        let consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{sha}\"\nkind = \"source\"\n"
        ))
        .unwrap();
        let mut stage = Stage::new(&layout).unwrap();
        let staged_pub = stage
            .stage_write(&layout.published_pins("seed-vault").unwrap())
            .unwrap();
        fs::write(
            &staged_pub,
            format!("schema-version = 1\n[artifacts]\ngrape-src = \"{sha}\"\n"),
        )
        .unwrap();
        let source_keys: std::collections::BTreeSet<String> =
            ["grape-src".to_string()].into_iter().collect();
        let staged_store = stage
            .symlink_free_store(&layout.store, &source_keys)
            .unwrap();
        (
            base,
            layout,
            manifest,
            consume,
            stage,
            staged_pub,
            staged_store,
        )
    }

    #[test]
    fn publish_swap_records_revision_and_alias() {
                                                                                                  
                                                                                           
                                                                                                
                                                             
        let sha_a = "a".repeat(64);
        let (_base, layout, manifest, consume, mut stage, staged_pub, staged_store) =
            record_fixture(&sha_a);
                                                                          
        fs::write(staged_store.join(format!("grape-src@{sha_a}")), b"REV-A").unwrap();
        fs::write(staged_store.join("grape-src"), b"REV-A").unwrap();
        let exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        };
        exec.record_published_swaps("seed-vault", &staged_pub, &staged_store, &mut stage)
            .unwrap();
        let file_swap_reals: Vec<PathBuf> = stage
            .swaps
            .iter()
            .filter_map(|s| match s {
                Swap::File { real, .. } => Some(real.clone()),
                Swap::Tree { .. } => None,
            })
            .collect();
        assert!(
            file_swap_reals.contains(&layout.store.join(format!("grape-src@{sha_a}"))),
            "the @sha revision pair must be recorded as a File swap: {file_swap_reals:?}"
        );
        assert!(
            file_swap_reals.contains(&layout.store.join("grape-src")),
            "the flat alias pair must be recorded as a File swap: {file_swap_reals:?}"
        );
    }

    #[test]
    fn missing_staged_revision_is_a_hard_step_error() {
                                                                                                   
                                                                                                  
                                                              
        let sha_a = "a".repeat(64);
        let (_base, layout, manifest, consume, mut stage, staged_pub, staged_store) =
            record_fixture(&sha_a);
                                                                                           
        fs::write(staged_store.join("grape-src"), b"REV-A").unwrap();
        let exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        };
        let err = exec
            .record_published_swaps("seed-vault", &staged_pub, &staged_store, &mut stage)
            .unwrap_err();
        assert!(
            err.to_string().contains("revision"),
            "the error must name the missing revision, got {err:?}"
        );
    }

    #[test]
    fn scoped_recorder_records_only_config_keys_tolerating_absent_binary_revisions() {
                                                                                                           
                                                                                                 
                                                                                                          
        let z = "0".repeat(64);
        let cfg_sha = "c".repeat(64);
        let (_base, _orchard, layout) = fixture();
        fs::create_dir_all(&layout.store).unwrap();
        let manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"thebin\", \"cfg\"]\n",
        )
        .unwrap();
        let consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.thebin]\nsha256 = \"{z}\"\nkind = \"binary\"\n[artifacts.cfg]\nsha256 = \"{cfg_sha}\"\nkind = \"config\"\n"
        ))
        .unwrap();
        let mut stage = Stage::new(&layout).unwrap();
        let staged_pub = stage
            .stage_write(&layout.published_pins("seed-vault").unwrap())
            .unwrap();
                                                                                                       
                                                                                                     
        fs::write(
            &staged_pub,
            format!("schema-version = 1\n[artifacts]\nthebin = \"{z}\"\ncfg = \"{cfg_sha}\"\n"),
        )
        .unwrap();
        let staged_store = stage
            .symlink_free_store(&layout.store, &std::collections::BTreeSet::new())
            .unwrap();
        fs::write(staged_store.join(format!("cfg@{cfg_sha}")), b"CFG").unwrap();
        fs::write(staged_store.join("cfg"), b"CFG").unwrap();
        let exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        };
        exec.record_published_swaps_scoped(
            "seed-vault",
            &["cfg".to_string()],
            &staged_pub,
            &staged_store,
            &mut stage,
        )
        .expect("the scoped recorder must succeed despite the absent binary revision");
        let reals: Vec<PathBuf> = stage
            .swaps
            .iter()
            .filter_map(|s| match s {
                Swap::File { real, .. } => Some(real.clone()),
                Swap::Tree { .. } => None,
            })
            .collect();
        assert!(
            reals.contains(&layout.store.join(format!("cfg@{cfg_sha}"))),
            "the config revision swap must be recorded: {reals:?}"
        );
        assert!(
            reals.contains(&layout.store.join("cfg")),
            "the config alias swap must be recorded: {reals:?}"
        );
        assert!(
            !reals.iter().any(|p| p.to_string_lossy().contains("thebin")),
            "the binary key must NOT be recorded by the scoped recorder: {reals:?}"
        );
    }

    #[test]
    fn staged_store_hash_check_refuses_a_corrupted_config_revision() {
                                                                                                          
                                                                                                       
                                  
        let cfg_sha = "c".repeat(64);                                            
        let (_base, _orchard, layout) = fixture();
        fs::create_dir_all(&layout.store).unwrap();
        let manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"cfg\"]\n",
        )
        .unwrap();
        let consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.cfg]\nsha256 = \"{cfg_sha}\"\nkind = \"config\"\n"
        ))
        .unwrap();
        let mut stage = Stage::new(&layout).unwrap();
        let staged_pub = stage
            .stage_write(&layout.published_pins("seed-vault").unwrap())
            .unwrap();
        fs::write(
            &staged_pub,
            format!("schema-version = 1\n[artifacts]\ncfg = \"{cfg_sha}\"\n"),
        )
        .unwrap();
        let staged_store = stage
            .symlink_free_store(&layout.store, &std::collections::BTreeSet::new())
            .unwrap();
                                                                                                          
        fs::write(
            staged_store.join(format!("cfg@{cfg_sha}")),
            b"NOT-THE-PINNED-BYTES",
        )
        .unwrap();
        let exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        };
        let err = exec
            .staged_store_hash_check(&staged_store, &staged_pub, "cfg")
            .unwrap_err();
        let m = err.to_string();
        assert!(
            m.contains("hashes to") && m.contains("refusing"),
            "the byte-check must name the sha mismatch + refuse, got {err:?}"
        );
    }

    #[test]
    fn build_dir_required_iff_the_repo_owns_binaries() {
                                                                                                             
                                                                                                           
                                                                                                        
                                                                                                         
                                                                                  
        let (_base, _orchard, layout) = fixture();
        let z = "a".repeat(64);

                                                                                                      
        let mixed_manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"../fruit-basket\"\nartifacts = [\"rambutan-src\", \"fb-acme\"]\n",
        )
        .unwrap();
        let mixed_consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.rambutan-src]\nsha256 = \"{z}\"\nkind = \"source\"\n[artifacts.fb-acme]\nsha256 = \"{z}\"\nkind = \"binary\"\n"
        ))
        .unwrap();
        for binary in [Some("fb-acme".to_string()), None] {
            let mut exec = ShellStepExec {
                layout: &layout,
                manifest: &mixed_manifest,
                consume: &mixed_consume,
                apk_container_image: None,
                build_dir: None,
                kernel_fetcher: None,
                rust_fetcher: None,
                container_builder: None,
                rebuilt_digest: None,
            };
            let mut stage = Stage::new(&layout).unwrap();
            let err = exec
                .exec(
                    &Step::Publish {
                        repo: "fruit-basket".into(),
                        binary,
                    },
                    &mut stage,
                )
                .unwrap_err();
            assert!(
                matches!(err, UpgradeError::StepFailed { .. })
                    && err.to_string().contains("--build-dir"),
                "a publish of a binary-owning repo without --build-dir must fail closed naming it, got {err:?}"
            );
        }

                                                                                                              
                                                                                     
        let src_manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n",
        )
        .unwrap();
        let src_consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{z}\"\nkind = \"source\"\n"
        ))
        .unwrap();
        let mut exec = ShellStepExec {
            layout: &layout,
            manifest: &src_manifest,
            consume: &src_consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        };
        let mut stage = Stage::new(&layout).unwrap();
        if let Err(e) = exec.exec(
            &Step::Publish {
                repo: "seed-vault".into(),
                binary: None,
            },
            &mut stage,
        ) {
            assert!(
                !e.to_string().contains("--build-dir"),
                "a source-only repo must NOT trip the --build-dir guard, got {e:?}"
            );
        }
    }

    /// A fake [`ContainerBuilder`]: returns queued `(image_id, rootfs)` pairs (the last repeats), so a
    /// green build yields the SAME rootfs twice and a mismatch corpus yields two — no docker in `make
    /// verify`.
    struct FakeBuilder {
        seq: std::cell::RefCell<Vec<(String, String)>>,
    }
    impl ContainerBuilder for FakeBuilder {
        fn build_once(
            &self,
            _cf: &Path,
            _ctx: &Path,
            _no_cache: bool,
        ) -> Result<BuiltImage, String> {
            let mut s = self.seq.borrow_mut();
            let (image_id, rootfs) = if s.len() > 1 {
                s.remove(0)
            } else {
                s[0].clone()
            };
            Ok(BuiltImage { image_id, rootfs })
        }
    }

    fn rust_eco() -> (TempDir, PathBuf, StoreLayout, RepoManifest, PinManifest) {
        let (base, orchard, layout) = fixture();
                                                                                                        
        let pins = "[rust]\nversion = \"1.96.0\"\ncontainer_digest = \"sha256:old\"\n";
        fs::write(orchard.join("pins.toml"), pins).unwrap();
        for dir in layout.repos.values() {
            fs::write(dir.join("pins.toml"), pins).unwrap();
        }
        let manifest = RepoManifest::from_toml_str(
            "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n",
        )
        .unwrap();
        let z = "a".repeat(64);
        let consume = PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{z}\"\nkind = \"source\"\n"
        ))
        .unwrap();
        (base, orchard, layout, manifest, consume)
    }

    #[test]
    fn rebuild_container_pins_the_reproducible_digest() {
        let (_base, orchard, layout, manifest, consume) = rust_eco();
        let fake = FakeBuilder {
            seq: std::cell::RefCell::new(vec![("sha256:reproducible".into(), "rootfs-A".into())]),
        };
        let mut exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: Some(&fake),
            rebuilt_digest: None,
        };
        let mut stage = Stage::new(&layout).unwrap();
        exec.exec(&Step::RebuildContainer, &mut stage).unwrap();
                                                                                                            
        let staged_pins =
            fs::read_to_string(stage.stage_path_of(&orchard.join("pins.toml"))).unwrap();
        assert!(
            staged_pins.contains("container_digest = \"sha256:reproducible\""),
            "the rebuilt digest must be pinned, got: {staged_pins}"
        );
        assert_eq!(exec.rebuilt_digest.as_deref(), Some("sha256:reproducible"));
                                             
        assert!(
            fs::read_to_string(orchard.join("pins.toml"))
                .unwrap()
                .contains("sha256:old")
        );
    }

    #[test]
    fn rebuild_container_rejects_a_non_reproducible_build() {
        let (_base, orchard, layout, manifest, consume) = rust_eco();
        let fake = FakeBuilder {
            seq: std::cell::RefCell::new(vec![
                ("sha256:aaa".into(), "rootfs-A".into()),
                ("sha256:bbb".into(), "rootfs-B".into()),
            ]),
        };
        let mut exec = ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: Some(&fake),
            rebuilt_digest: None,
        };
        let mut stage = Stage::new(&layout).unwrap();
        let err = exec.exec(&Step::RebuildContainer, &mut stage).unwrap_err();
        assert!(err.to_string().contains("non-reproducible"), "got: {err}");
        assert!(
            exec.rebuilt_digest.is_none(),
            "a failed rebuild pins nothing"
        );
        assert!(
            fs::read_to_string(orchard.join("pins.toml"))
                .unwrap()
                .contains("sha256:old")
        );
    }

    #[test]
    fn build_only_command_references_the_image_by_digest() {
                                                                                                  
                                                                                             
        let cmd = ShellStepExec::build_only_command(
            "sha256:deadbeef",
            Path::new("/real/fruit-basket"),
            Path::new("/tmp/handoff"),
            "build-only.sh",
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.contains(&"sha256:deadbeef".to_string()),
            "the run target must be the image DIGEST: {args:?}"
        );
        assert!(
            !args
                .iter()
                .any(|a| a.contains("recipes-imgbuild") || a.contains(":dev")),
            "never a mutable tag: {args:?}"
        );
        assert!(args.iter().any(|a| a.contains("build-only.sh")));
    }

                                                                                      

    fn consume_fixture(grape_sha: &str, box_sha: &str) -> String {
        format!(
            "# HEADER — load-bearing trust-model docs (F-3b-R1-4): this manifest is the UN-HASHED\n\
             # ROOT of the verify chain; integrity rests on git review. See [artifacts.grape-src].\n\
             schema-version = 1\n\
             \n\
             # binaries first (hand-chosen order — the rewrite must not resort it)\n\
             [artifacts.box-init]\n\
             kind = \"binary\"\n\
             sha256 = \"{box_sha}\"\n\
             \n\
             [artifacts.grape-src]\n\
             kind = \"source\"\n\
             sha256 = \"{grape_sha}\"  # seed-vault drop\n"
        )
    }

    #[test]
    fn repin_rewrite_is_surgical_byte_preserving() {
        let old = "a".repeat(64);
        let keep = "b".repeat(64);
        let new = "c".repeat(64);
        let src = consume_fixture(&old, &keep);
        let out = rewrite_consume_sha(&src, "grape-src", &new).unwrap();
                                                                                           
                                                                           
        assert_eq!(out, src.replace(&old, &new));
                                                                                               
                                                                                               
        assert!(out.contains("See [artifacts.grape-src]."));
        assert!(out.contains(&format!("sha256 = \"{new}\"  # seed-vault drop")));
                                               
        assert!(out.contains(&keep));
    }

    #[test]
    fn repin_rewrite_fails_closed() {
        let sha = "a".repeat(64);
        let good = consume_fixture(&sha, &"b".repeat(64));
        let new = "c".repeat(64);
                                              
        assert!(rewrite_consume_sha(&good, "no-such-key", &new).is_err());
                                                                 
        assert!(rewrite_consume_sha(&good, "grape-src", "beef").is_err());
        assert!(rewrite_consume_sha(&good, "grape-src", &"Z".repeat(64)).is_err());
                                                  
        let dup = format!("{good}\n[artifacts.grape-src]\nkind = \"source\"\nsha256 = \"{sha}\"\n");
        assert!(rewrite_consume_sha(&dup, "grape-src", &new).is_err());
                                                                                          
        let no_sha = "schema-version = 1\n[artifacts.grape-src]\nkind = \"source\"\n# sha256 = \"dead\"\n\n[artifacts.other]\nsha256 = \"{}\"\n";
        let no_sha = no_sha.replace("{}", &sha);
        assert!(
            rewrite_consume_sha(&no_sha, "grape-src", &new).is_err(),
            "must not fall through to ANOTHER table's sha line"
        );
                                                                                                      
                                               
        assert!(no_sha.contains(&sha));
    }

    #[test]
    fn repin_rewrite_output_still_parses_and_carries_the_new_sha() {
        let old = "a".repeat(64);
        let new = "c".repeat(64);
        let out = rewrite_consume_sha(&consume_fixture(&old, &"b".repeat(64)), "grape-src", &new)
            .unwrap();
        let doc: toml::Value = toml::from_str(&out).expect("surgical output still parses");
        assert_eq!(
            doc["artifacts"]["grape-src"]["sha256"].as_str().unwrap(),
            new
        );
    }

    #[test]
    fn repin_rewrite_selector_is_key_bounded_not_prefix_matched() {
                                                                                                 
                                                                                               
                                                                                          
        let old = "a".repeat(64);
        let new = "c".repeat(64);
        let with_decoys = format!(
            "schema-version = 1\n\
             [artifacts.grape-src]\n\
             kind = \"source\"\n\
             sha256sum = \"{old}\"\n\
             sha256_old = \"{old}\"\n\
             sha256 = \"{old}\"\n"
        );
        let out = rewrite_consume_sha(&with_decoys, "grape-src", &new).unwrap();
        assert!(
            out.contains(&format!("sha256sum = \"{old}\""))
                && out.contains(&format!("sha256_old = \"{old}\"")),
            "decoy keys must be untouched: {out}"
        );
        assert!(out.contains(&format!("sha256 = \"{new}\"")), "{out}");
        let only_decoy = format!(
            "schema-version = 1\n[artifacts.grape-src]\nkind = \"source\"\nsha256sum = \"{old}\"\n"
        );
        assert!(
            rewrite_consume_sha(&only_decoy, "grape-src", &new).is_err(),
            "a decoy-only span must fail closed, never splice the decoy"
        );
    }
}
