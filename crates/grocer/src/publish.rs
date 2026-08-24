                                                                                                              
//! `published-pins.toml` — writing ONLY to the explicit `--store`/`--published-out` paths it is handed.
//!
//! Increment 1 = source drops + config (verbatim copy); increment 2 adds `kind=binary` — read from
//! `--build-dir`, ELF/linkage-asserted (`assert_elf`), and stored as the RAW ELF bytes.
//! The artifact's handling is dispatched on the AUTHORITATIVE kind from `consume-pins` (NOT the manifest's
//! self-declaration — `cross_check` has already proven they agree), so a manifest can never drive the wrong
//! handling.

use std::path::{Path, PathBuf};

use clap::Parser;
use sha2::{Digest, Sha256};

use recipes_image_builder::artifact_store::DirStore;
use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest};
use recipes_image_builder::repo_manifest::RepoManifest;
use recipes_image_builder::vendor::deterministic_source_tar;

use crate::crosscheck;
use crate::elf_assert::{assert_elf, ElfError};
use crate::publish_manifest::{ManifestError, PublishArtifact, PublishManifest};

/// `grocer` — publish pre-built artifacts into the sha256 pin store, only to the explicit handed paths.
#[derive(Parser, Debug)]
#[command(
    name = "grocer",
    about = "Narrow pin-store publisher (writes only --store/--published-out)."
)]
pub struct Args {
    /// The publish recipe. Defaults to `<repo path>/publish-manifest.toml` (resolved via `--repo`).
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// The owning repo whose artifacts to publish (a key in `--repo-manifest`).
    #[arg(long)]
    pub repo: String,
    /// `repo-manifest.toml` — the authoritative owner->key map (its dir is the orchard root the repo paths
    /// are relative to).
    #[arg(long)]
    pub repo_manifest: PathBuf,
    /// `consume-pins.toml` — the authoritative key->kind map (the kind cross-check authority).
    #[arg(long)]
    pub consume_pins: PathBuf,
    /// The handoff dir holding pre-built binaries (required iff the manifest has a `binary` artifact —
    /// increment 2; unused for source/config).
    #[arg(long)]
    pub build_dir: Option<PathBuf>,
    /// The artifact store dir to write `<store>/<key>` into.
    #[arg(long)]
    pub store: PathBuf,
    /// The `published-pins.toml` to write (one atomic write, last).
    #[arg(long)]
    pub published_out: PathBuf,
                                                                                                          
    /// be git-TRACKED, and `published-pins.toml` is READ-MERGE-WRITTEN (the config records spliced/appended,
    /// every non-config record byte-preserved) instead of freshly regenerated. Default = the whole-repo publish.
    #[arg(long)]
    pub only_configs: bool,
    /// Restrict a config-subset publish to the ONE named `kind=config` key (the `market upgrade --config
    /// <key>` leg): only this config is re-derived + spliced; EVERY other config record is byte-preserved
    /// like the non-config records — so grocer never republishes a SIBLING config that's ahead of its pin
    /// (the M1 fold). Requires `--only-configs`. Absent = publish ALL configs (the enrollment path).
    #[arg(long, requires = "only_configs")]
    pub config_key: Option<String>,
}

/// What subset of the repo's manifest a publish covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishScope {
    /// The whole manifest — produce + store + freshly (re)write published-pins for EVERY artifact
    /// (today's default path, unchanged).
    Whole,
    /// Only the `kind=config` artifacts — tracked-source-checked, stored (CAS dual-write), and
    /// read-merge-written into the existing published-pins (non-config records byte-preserved). A narrow
                                                                               
    ConfigSubset,
}

#[derive(Debug, thiserror::Error)]
pub enum GrocerError {
    #[error("repo {0:?} is not in repo-manifest.toml")]
    UnknownRepo(String),
    #[error("io at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("publish-manifest source {0:?} has no file-name component")]
    BadSourceShape(String),
    #[error(
        "artifact {key:?} is kind=binary but no --build-dir was given (required to locate the pre-built ELF)"
    )]
    MissingBuildDir { key: String },
    #[error("artifact {key:?} failed the ELF/linkage assert: {source}")]
    Elf {
        key: String,
        #[source]
        source: ElfError,
    },
    #[error(transparent)]
    RepoManifest(#[from] recipes_image_builder::repo_manifest::RepoManifestError),
    #[error(transparent)]
    PinManifest(#[from] recipes_image_builder::pin_manifest::PinManifestError),
    #[error(transparent)]
    Manifest(#[from] crate::publish_manifest::ManifestError),
    #[error(transparent)]
    Cross(#[from] crate::crosscheck::CrossError),
    #[error(transparent)]
    Vendor(#[from] recipes_image_builder::vendor::VendorError),
    #[error(transparent)]
    Store(#[from] recipes_image_builder::artifact_store::ArtifactStoreError),
    #[error(
        "config-subset publish needs an existing published-pins at {path} to merge into (absent/unreadable) — run a whole-repo publish first"
    )]
    MissingPublishedPins { path: String },
    #[error(
        "config-subset publish: the existing published-pins has NO record for non-config key {key:?} — refusing to emit a pins file missing a required record (run a whole-repo publish first)"
    )]
    PublishedPinsMissingRecord { key: String },
    #[error(
        "config-subset publish: key {key:?} matches more than one line in published-pins (malformed) — refusing"
    )]
    DuplicatePublishedPinLine { key: String },
    #[error(
        "--config-key {0:?} is not a kind=config artifact of this repo's manifest — a targeted config-subset publishes exactly one config key"
    )]
    ConfigKeyNotConfig(String),
}

impl GrocerError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        GrocerError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Publish every artifact the repo's publish-manifest declares. Writes ONLY `<store>/<key>` (via the
/// symlink-safe `DirStore::put`) and `--published-out` (one atomic write, after every byte is in the store).
pub fn run(args: Args) -> Result<(), GrocerError> {
    let repo_manifest = RepoManifest::load(&args.repo_manifest)?;
    let consume = PinManifest::load(&args.consume_pins)?;

    let entry = repo_manifest
        .repos
        .get(&args.repo)
        .ok_or_else(|| GrocerError::UnknownRepo(args.repo.clone()))?;
                                                                                                       
    let orchard_root = args
        .repo_manifest
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let repo_root = orchard_root.join(&entry.path);

    let manifest_path = args
        .manifest
        .clone()
        .unwrap_or_else(|| repo_root.join("publish-manifest.toml"));
    let manifest_text =
        std::fs::read_to_string(&manifest_path).map_err(|e| GrocerError::io(&manifest_path, e))?;
    let manifest = PublishManifest::from_toml_str(&manifest_text)?;

                                                                                                          
                                                                                                    
    crosscheck::cross_check(&manifest, &args.repo, &repo_manifest, &consume)?;

    let scope = if args.only_configs {
        PublishScope::ConfigSubset
    } else {
        PublishScope::Whole
    };

                                                                                                            
                                                                                                         
                                                                                                        
                                                                                                      
                                                                                             
    let target_config = args.config_key.as_deref();
    if let Some(t) = target_config {
        let is_config_key = manifest.artifact.iter().any(|a| {
            a.key.as_str() == t
                && consume.artifacts.get(&a.key).map(|p| p.kind) == Some(ArtifactKind::Config)
        });
        if !is_config_key {
            return Err(GrocerError::ConfigKeyNotConfig(t.to_string()));
        }
    }

                                                                                              
                                                                                                      
                                                                                                        
                                                                                                       
                                                                                                  
                                      
    if matches!(scope, PublishScope::ConfigSubset) {
        assert_config_pins_mergeable(
            &args.published_out,
            &preserved_keys(&manifest, &consume, target_config),
        )?;
    }

                                                                                                         
                                                                                                          
                                                                                                          
                                                                                                     
                                           
    let mut staged: Vec<(String, Vec<u8>, String)> = Vec::with_capacity(manifest.artifact.len());
    for a in &manifest.artifact {
        crosscheck::sanitize_source(&a.source)?;
                                                                                                     
        let kind = consume
            .artifacts
            .get(&a.key)
            .expect("cross_check verified every key is in consume-pins")
            .kind;
                                                                                                   
                                                                                                           
                                                                                                          
                                                                                                  
        if matches!(scope, PublishScope::ConfigSubset) {
            if kind != ArtifactKind::Config {
                continue;
            }
            if matches!(target_config, Some(t) if a.key.as_str() != t) {
                continue;
            }
        }
        let bytes = match kind {
            ArtifactKind::Source => {
                let crate_dir = repo_root.join(&a.source);
                crosscheck::assert_no_untracked(&crate_dir)?;
                                                                                                               
                let src = Path::new(&a.source);
                let parent = src.parent().unwrap_or_else(|| Path::new(""));
                let entry_name = src
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| GrocerError::BadSourceShape(a.source.clone()))?;
                deterministic_source_tar(&repo_root.join(parent), entry_name, true)?
            }
            ArtifactKind::Config => {
                                                                                                            
                                                                                                          
                                                                                        
                if matches!(scope, PublishScope::ConfigSubset) {
                    crosscheck::assert_tracked_source(&repo_root, &a.key, &a.source)?;
                }
                let p = repo_root.join(&a.source);
                std::fs::read(&p).map_err(|e| GrocerError::io(&p, e))?
            }
            ArtifactKind::Binary => produce_binary(a, args.build_dir.as_deref())?,
        };
        let sha = hex::encode(Sha256::digest(&bytes));
        staged.push((a.key.clone(), bytes, sha));
    }

                                                                                                          
    let store = DirStore::new(&args.store);
    let mut pins: Vec<(String, String)> = Vec::with_capacity(staged.len());
    for (key, bytes, sha) in &staged {
        store.put(key, bytes)?;
        pins.push((key.clone(), sha.clone()));
    }

    match scope {
                                                                                                         
        PublishScope::Whole => write_published_pins(&args.published_out, &pins),
                                                                                                         
                                                                                                              
                                         
        PublishScope::ConfigSubset => merge_config_pins(
            &args.published_out,
            &pins,
            &preserved_keys(&manifest, &consume, target_config),
        ),
    }
}

                                                                                                        
/// key still has a record (a subset publish must never DROP a binary/source record), then splice each
/// config key's line (or APPEND a new config key), byte-preserving every other line. One atomic write,
/// last — like [`write_published_pins`]. `config_pins` are the just-produced `(key, sha)` config records.
fn merge_config_pins(
    out: &Path,
    config_pins: &[(String, String)],
    non_config_keys: &[&str],
) -> Result<(), GrocerError> {
                                                                                                         
                                                                                                    
                                                     
    let mut text = assert_config_pins_mergeable(out, non_config_keys)?;
    for (key, sha) in config_pins {
        text = splice_or_append_pin(text, key, sha)?;
    }
    atomic_write_pins(out, &text)
}

/// The config-subset published-pins MERGE preconditions, factored so they can be asserted BEFORE any
/// store write (L-1) AND re-used by [`merge_config_pins`]: the file must exist + parse, and carry a
/// record for every non-config manifest key (a subset publish must never DROP a binary/source record —
/// that would break the consume↔published agreement the whole carve-out relies on). Returns the existing
/// pins text (for the splice).
fn assert_config_pins_mergeable(
    out: &Path,
    non_config_keys: &[&str],
) -> Result<String, GrocerError> {
    let existing = std::fs::read_to_string(out).map_err(|_| GrocerError::MissingPublishedPins {
        path: out.display().to_string(),
    })?;
    for key in non_config_keys {
        if pin_line_count(&existing, key) == 0 {
            return Err(GrocerError::PublishedPinsMissingRecord {
                key: (*key).to_string(),
            });
        }
    }
    Ok(existing)
}

/// The manifest keys a config subset must byte-PRESERVE (never re-derive this run) — the records whose
/// completeness is asserted before any write, and which `merge_config_pins` leaves untouched. For an
/// ALL-configs subset that's every non-config key; for a TARGETED subset (`--config-key <t>`) it is every
/// key EXCEPT `t` — the non-configs AND every sibling config (the M1 fold: a sibling is preserved, not
/// republished, so its pin never moves). In manifest order. Shared by the pre-Phase-1 precheck + the
/// Phase-2 merge (L-1).
fn preserved_keys<'a>(
    manifest: &'a PublishManifest,
    consume: &PinManifest,
    target_config: Option<&str>,
) -> Vec<&'a str> {
    manifest
        .artifact
        .iter()
        .filter(|a| match target_config {
            Some(t) => a.key.as_str() != t,
            None => consume.artifacts.get(&a.key).map(|p| p.kind) != Some(ArtifactKind::Config),
        })
        .map(|a| a.key.as_str())
        .collect()
}

/// How many `<key> = "…"` lines the pins text carries (the ` = "` delimiter after the key makes this an
/// exact whole-key match — `dha` never matches `dha-orchestrator = "…"`).
fn pin_line_count(text: &str, key: &str) -> usize {
    let anchor = format!("{key} = \"");
    text.lines().filter(|l| l.starts_with(&anchor)).count()
}

/// Splice a config key's record to `sha` if it has EXACTLY ONE existing line (byte-preserving all other
/// lines), or APPEND it (a first publish of a new config key) if it has none; >1 match is malformed →
/// refuse. published-pins is grocer-generated (`\n` line endings, canonical `key = "sha"` lines).
fn splice_or_append_pin(text: String, key: &str, sha: &str) -> Result<String, GrocerError> {
    let anchor = format!("{key} = \"");
    let matched: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with(&anchor))
        .map(|(i, _)| i)
        .collect();
    let new_line = format!("{key} = \"{sha}\"");
    match matched.len() {
        0 => {
                                                                                                    
            let mut t = text;
            if !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&new_line);
            t.push('\n');
            Ok(t)
        }
        1 => {
            let had_trailing_nl = text.ends_with('\n');
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            lines[matched[0]] = new_line;
            let mut s = lines.join("\n");
            if had_trailing_nl {
                s.push('\n');
            }
            Ok(s)
        }
        _ => Err(GrocerError::DuplicatePublishedPinLine {
            key: key.to_string(),
        }),
    }
}

/// Atomically write `content` to `out` — a temp file in the destination dir, then `rename` — so a crash
/// leaves either the old pins or the new, never a half-written file. Shared by the whole-repo (fresh) and
/// the config-subset (merged) pins emitters.
fn atomic_write_pins(out: &Path, content: &str) -> Result<(), GrocerError> {
    let dir = out.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| GrocerError::io(dir, e))?;
    let tmp = tempfile::Builder::new()
        .prefix(".published-pins-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|e| GrocerError::io(dir, e))?;
    std::fs::write(tmp.path(), content).map_err(|e| GrocerError::io(tmp.path(), e))?;
    tmp.persist(out)
        .map_err(|e| GrocerError::io(out, e.error))?;
    Ok(())
}

/// Produce a `kind=binary` artifact's bytes: read the pre-built ELF from `--build-dir` and assert its
                                                                                                        
/// Fail-closed on a missing `--build-dir`, an unreadable file, or any ELF/linkage mismatch — all before any
/// store write (the Phase-1 caller buffers the bytes; nothing is written until every artifact validates).
fn produce_binary(a: &PublishArtifact, build_dir: Option<&Path>) -> Result<Vec<u8>, GrocerError> {
    let build_dir = build_dir.ok_or_else(|| GrocerError::MissingBuildDir { key: a.key.clone() })?;
                                                                                                              
    let bin_path = build_dir.join(&a.source);
    let bytes = std::fs::read(&bin_path).map_err(|e| GrocerError::io(&bin_path, e))?;
                                                                                                           
    let linkage = a
        .linkage
        .ok_or_else(|| ManifestError::BinaryNeedsLinkage { key: a.key.clone() })?;
    assert_elf(&bytes, linkage.into()).map_err(|source| GrocerError::Elf {
        key: a.key.clone(),
        source,
    })?;
    Ok(bytes)
}

/// The publish-manifest's parsed link shape → the ELF asserter's linkage kind.
impl From<crate::publish_manifest::Linkage> for crate::elf_assert::Linkage {
    fn from(l: crate::publish_manifest::Linkage) -> Self {
        match l {
            crate::publish_manifest::Linkage::Dynamic => Self::Dynamic,
            crate::publish_manifest::Linkage::Static => Self::Static,
        }
    }
}

/// Emit `published-pins.toml` (the flat `[artifacts] key = "sha"` map the §3a-1 provenance check reads) in
/// ONE atomic write — a temp file in the destination dir, then `rename` over the target — so a crash leaves
/// either the old pins or the new, never a half-written file.
fn write_published_pins(out: &Path, pins: &[(String, String)]) -> Result<(), GrocerError> {
    let mut s = String::from(
        "# Published artifact pins — GENERATED by grocer. Do not edit by hand (re-publish to regenerate).\n\
         schema-version = 1\n\n[artifacts]\n",
    );
    for (key, sha) in pins {
        s.push_str(key);
        s.push_str(" = \"");
        s.push_str(sha);
        s.push_str("\"\n");
    }
    atomic_write_pins(out, &s)
}
