//! `market store` — the worktree-aware reference scan + `status`/`prune`/`migrate` (spec
//! 2026-07-08-market-content-addressed-store-design.md, Component 2). The CAS layout (Task 1-4)
//! is already safe-by-construction; these are advisory/maintenance-only surfaces — never on the
//! `market verify` HOT_PATH, never able to make a read unsafe (every read still goes through
//! `fetch_verified`'s re-hash).
//!
                                                                                                 
//! `published-pins.toml`, each read across EVERY `git worktree list` checkout of that repo (not
//! just its manifest-resolved primary) — the 2026-07-07 dha incident was exactly a second
//! checkout's publish the primary-only scan would have missed. A plain directory COPY (not a git
//! worktree) is NOT enumerable this way; `render_status` names that blind spot explicitly.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use recipes_image_builder::artifact_store::{StoreName, parse_store_name};
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;

#[derive(Debug, thiserror::Error)]
pub enum StoreAdminError {
    #[error("read store dir {path}: {source}")]
    ReadDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("git -C {repo} worktree list --porcelain: {detail}")]
    Git { repo: String, detail: String },
    #[error("store io at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// One checkout of a repo, from `git worktree list --porcelain` (the primary checkout is always
/// the first entry git reports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    pub path: PathBuf,
    /// The porcelain `prunable` attribute — stale worktree metadata (the target dir is gone but
    /// git still lists it). A prunable entry's pins can never be trusted current; `scan_store`
    /// refuses on it rather than silently excluding it (fail-honest, not fail-open).
    pub prunable: bool,
}

/// Every checkout of `repo` (`git -C <repo> worktree list --porcelain`), primary first.
pub fn worktree_checkouts(repo: &Path) -> Result<Vec<WorktreeEntry>, StoreAdminError> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|e| StoreAdminError::Git {
            repo: repo.display().to_string(),
            detail: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(StoreAdminError::Git {
            repo: repo.display().to_string(),
            detail: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut entries = Vec::new();
    let mut cur: Option<(PathBuf, bool)> = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            if let Some((path, prunable)) = cur.take() {
                entries.push(WorktreeEntry { path, prunable });
            }
            cur = Some((PathBuf::from(p), false));
        } else if line == "prunable" || line.starts_with("prunable ") {
            if let Some((_, prunable)) = cur.as_mut() {
                *prunable = true;
            }
        } else if line.is_empty()
            && let Some((path, prunable)) = cur.take()
        {
            entries.push(WorktreeEntry { path, prunable });
        }
    }
    if let Some((path, prunable)) = cur.take() {
        entries.push(WorktreeEntry { path, prunable });
    }
    Ok(entries)
}

/// Read every `key -> sha` pair from a flat `[artifacts] key = "sha"` `published-pins.toml`
/// (generalizes `market_exec::read_published_sha`, which reads one key, to the whole table — the
                                                                                                 
/// value is a HARD error (never silently dropped) — a dropped key would classify that key's store
/// revision UNREFERENCED, the dangerous direction (a referenced blob becoming a prune candidate).
fn read_published_all(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let doc: toml::Value = toml::from_str(&text).map_err(|e| e.to_string())?;
    let table = doc
        .get("artifacts")
        .and_then(|v| v.as_table())
        .ok_or_else(|| format!("{} has no [artifacts] table", path.display()))?;
    let mut out = BTreeMap::new();
    for (k, v) in table {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{}: artifacts.{k} is not a string", path.display()))?;
        out.insert(k.clone(), s.to_string());
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionEntry {
    pub key: String,
    pub sha: String,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct StoreScan {
    pub referenced: Vec<RevisionEntry>,
    pub unreferenced: Vec<RevisionEntry>,
    pub aliases: Vec<String>,
    pub foreign: Vec<String>,
    /// Why a prune must refuse (empty = the scan is complete): absent repos, unreadable pins,
    /// prunable worktree entries — each line names the concrete remedy.
    pub refusals: Vec<String>,
    pub scanned_checkouts: Vec<PathBuf>,
}

const PRUNABLE_REMEDY: &str = "a stale git-worktree entry (run `git worktree prune` there to clear it before pruning the store)";

/// The §4.2 reference scan: orchard consume-pins + every manifest repo's published-pins, across
/// the manifest-resolved checkout PLUS every `git worktree list` checkout of it. Fail-HONEST:
/// every problem lands in `refusals` (the scan keeps going with what it COULD read) rather than
/// being silently skipped or aborting the whole report.
pub fn scan_store(
    store: &Path,
    manifest: &RepoManifest,
    orchard_root: &Path,
) -> Result<StoreScan, StoreAdminError> {
    let mut refusals = Vec::new();
    let mut scanned_checkouts = Vec::new();
    let mut referenced: HashSet<(String, String)> = HashSet::new();

                                                                    
    for wt in worktree_checkouts(orchard_root)? {
        if wt.prunable {
            refusals.push(format!("{}: {PRUNABLE_REMEDY}", wt.path.display()));
            continue;
        }
        let pins_path = wt.path.join("consume-pins.toml");
        match PinManifest::load(&pins_path) {
            Ok(pins) => {
                for (key, pin) in &pins.artifacts {
                    referenced.insert((key.clone(), pin.sha256.clone()));
                }
                scanned_checkouts.push(wt.path);
            }
            Err(e) => refusals.push(format!(
                "{}: unreadable consume-pins ({e})",
                pins_path.display()
            )),
        }
    }

                                                                             
    for name in manifest.repos.keys() {
        let Some(repo_path) = manifest.repo_path(name, orchard_root) else {
            continue;
        };
        if !repo_path.exists() {
            refusals.push(format!(
                "{name}: repo not present at {}",
                repo_path.display()
            ));
            continue;
        }
        let checkouts = match worktree_checkouts(&repo_path) {
            Ok(c) => c,
            Err(e) => {
                refusals.push(format!(
                    "{name}: git worktree list failed at {}: {e}",
                    repo_path.display()
                ));
                continue;
            }
        };
        for wt in checkouts {
            if wt.prunable {
                refusals.push(format!("{}: {PRUNABLE_REMEDY}", wt.path.display()));
                continue;
            }
            let pins_path = wt.path.join("published-pins.toml");
            match read_published_all(&pins_path) {
                Ok(all) => {
                    referenced.extend(all);
                    scanned_checkouts.push(wt.path);
                }
                Err(e) => refusals.push(format!(
                    "{}: unreadable published-pins ({e})",
                    pins_path.display()
                )),
            }
        }
    }

                               
    let mut referenced_entries = Vec::new();
    let mut unreferenced_entries = Vec::new();
    let mut aliases = Vec::new();
    let mut foreign = Vec::new();
    let read_dir = fs::read_dir(store).map_err(|e| StoreAdminError::ReadDir {
        path: store.display().to_string(),
        source: e,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|e| StoreAdminError::ReadDir {
            path: store.display().to_string(),
            source: e,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        match parse_store_name(&name) {
            StoreName::Revision { key, sha } => {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let entry = RevisionEntry {
                    key: key.clone(),
                    sha: sha.clone(),
                    size,
                };
                if referenced.contains(&(key, sha)) {
                    referenced_entries.push(entry);
                } else {
                    unreferenced_entries.push(entry);
                }
            }
            StoreName::Alias { key } => aliases.push(key),
            StoreName::Foreign => foreign.push(name),
        }
    }
    referenced_entries
        .sort_by(|a, b| (a.key.as_str(), a.sha.as_str()).cmp(&(b.key.as_str(), b.sha.as_str())));
    unreferenced_entries
        .sort_by(|a, b| (a.key.as_str(), a.sha.as_str()).cmp(&(b.key.as_str(), b.sha.as_str())));
    aliases.sort();
    foreign.sort();

    Ok(StoreScan {
        referenced: referenced_entries,
        unreferenced: unreferenced_entries,
        aliases,
        foreign,
        refusals,
        scanned_checkouts,
    })
}

/// `9679232` → `"9.2 MiB"` — the operator-report size form (B/KiB/MiB/GiB, one decimal).
fn fmt_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.1} MiB", b / MIB)
    } else {
        format!("{:.1} GiB", b / GIB)
    }
}

/// Human-readable report, self-describing: WHICH store was scanned and how many checkouts fed
/// the reference set (an operator flipping `$FRUIT_ARTIFACT_STORE` between stores must see which
/// one answered), then counts + sizes per bucket, every refusal (the reason a prune would
/// refuse), and the blind-spot note (a plain directory copy of a repo is invisible to the scan).
pub fn render_status(scan: &StoreScan, store: &Path, all: bool, full: bool) -> String {
                                                                                                       
                                                                                                   
                                                                                                    
    let mut out = String::new();
    out.push_str(&format!("store: {}\n", store.display()));
    out.push_str(&format!(
        "scanned checkouts: {} (consume-pins + published-pins across every git worktree)\n",
        scan.scanned_checkouts.len()
    ));
                                                                                                 
                                                                                               
                                                                                                 
                                                                        
    let mut pooled: Vec<String> = scan.unreferenced.iter().map(|e| e.sha.clone()).collect();
    if all {
        pooled.extend(scan.referenced.iter().map(|e| e.sha.clone()));
    }
    let abbrevs = super::report::abbrev_digests(&pooled, full);
    let abbrev_of: std::collections::HashMap<String, String> =
        pooled.into_iter().zip(abbrevs).collect();
                                                                                                       
                                                                                   
    let itemize_revs = |entries: &[RevisionEntry]| -> String {
        let cells: Vec<(String, String)> = entries
            .iter()
            .map(|e| {
                let a = abbrev_of.get(&e.sha).map(String::as_str).unwrap_or(&e.sha);
                (format!("{}@{}", e.key, a), fmt_size(e.size))
            })
            .collect();
        let w = cells.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let mut s = String::new();
        for (k, sz) in &cells {
            s.push_str(&format!("  {k:<w$}  ({sz})\n"));
        }
        s
    };
    out.push_str(&format!(
        "referenced revisions: {}\n",
        scan.referenced.len()
    ));
    if all {
        out.push_str(&itemize_revs(&scan.referenced));
    }
                                                                    
    out.push_str(&format!(
        "unreferenced revisions: {}\n",
        scan.unreferenced.len()
    ));
    out.push_str(&itemize_revs(&scan.unreferenced));
    out.push_str(&format!("aliases (flat, legacy): {}\n", scan.aliases.len()));
    if all {
        for a in &scan.aliases {
            out.push_str(&format!("  {a}\n"));
        }
    }
                                                        
    out.push_str(&format!("foreign entries: {}\n", scan.foreign.len()));
    for f in &scan.foreign {
        out.push_str(&format!("  {f}\n"));
    }
                                                                                   
    if scan.refusals.is_empty() {
        out.push_str("scan complete: no refusals\n");
    } else {
        out.push_str(&format!(
            "refusals ({}) — `market store prune` WILL REFUSE until these clear:\n",
            scan.refusals.len()
        ));
        for r in &scan.refusals {
            out.push_str(&format!("  {r}\n"));
        }
    }
    out.push_str(
        "note: a plain COPY of a repo (not a git worktree) cannot be enumerated — its pins are \
         invisible to this scan; keep-all is the safe posture around such copies.\n",
    );
    out
}

/// The prune report, operator-shaped: the store, the candidates WITH the reclaimable size (the
/// question prune answers), and — on a `--delete` run — the deleted/failed partition, every
/// failure with its reason. Same shape whether it deleted, dry-ran, or REFUSED (reportfix-R1
/// Info-1: the refusal opens with the same `store:` header as every success path).
pub fn render_prune(report: &PruneReport, delete: bool, store: &Path, full: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("store: {}\n", store.display()));
    if let Some(reason) = &report.refused {
        out.push_str(&format!("market store prune: REFUSED — {reason}\n"));
        return out;
    }
    if report.candidates.is_empty() {
        out.push_str("nothing to prune (0 unreferenced revisions)\n");
        return out;
    }
    let total: u64 = report.candidates.iter().map(|c| c.size).sum();
    out.push_str(&format!(
        "candidates ({}, {}):\n",
        report.candidates.len(),
        fmt_size(total)
    ));
                                                                                                 
                                                                                                        
                                                                              
    let abbrev = super::report::abbrev_digests(
        &report
            .candidates
            .iter()
            .map(|c| c.sha.clone())
            .collect::<Vec<_>>(),
        full,
    );
    let cells: Vec<(String, String)> = report
        .candidates
        .iter()
        .zip(abbrev.iter())
        .map(|(c, a)| (format!("{}@{}", c.key, a), fmt_size(c.size)))
        .collect();
    let w = cells.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, sz) in &cells {
        out.push_str(&format!("  {k:<w$}  ({sz})\n"));
    }
    if delete {
        out.push_str(&format!("deleted ({}):\n", report.deleted.len()));
        for d in &report.deleted {
            out.push_str(&format!("  {d}\n"));
        }
        if !report.failed.is_empty() {
            out.push_str(&format!("failed ({}):\n", report.failed.len()));
            for f in &report.failed {
                out.push_str(&format!("  {f}\n"));
            }
        }
    } else {
        out.push_str("(dry run — nothing deleted; pass --delete to remove the candidates above)\n");
    }
    out
}

/// The migrate report, operator-shaped: the store, the one-line tally, and every skipped alias
/// named with its reason (nothing declines silently).
pub fn render_migrate(report: &MigrateReport, store: &Path) -> String {
    let mut out = String::new();
    out.push_str(&format!("store: {}\n", store.display()));
    out.push_str(&format!(
        "migrate: linked {}, already-present {}, skipped {}\n",
        report.linked,
        report.already,
        report.skipped.len()
    ));
    if !report.skipped.is_empty() {
        out.push_str(&format!("skipped ({}):\n", report.skipped.len()));
        for s in &report.skipped {
            out.push_str(&format!("  {s}\n"));
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct PruneReport {
    pub candidates: Vec<RevisionEntry>,
    pub deleted: Vec<String>,
    /// Every candidate NOT deleted on a `--delete` run, each with its reason ("vanished since
    /// the scan", "not a regular file", "remove_file failed: …"). `deleted` + `failed` partition
    /// `candidates` exactly — a mutating verb never declines silently (the reportfix pass of the
    /// Gate-B carry-forward Infos). Always empty on a dry run.
    pub failed: Vec<String>,
    /// `Some(reason)` iff the whole prune refused to run (the scan was incomplete) — set
    /// regardless of `delete`, since a dry run should tell the operator a real run would refuse.
    pub refused: Option<String>,
}

                                                                                                 
/// `delete=false` PRINTS candidates only (the flag-less default IS the dry run — comfort-cycle
/// shape). REFUSES outright — deletes nothing, `refused: Some(..)` — when `scan.refusals` is
/// non-empty: an incomplete scan cannot prove a revision is truly unreferenced. Deletes IFF a
/// candidate is a conforming `<key>@<sha>` Revision (re-checked here, not trusted from `scan`)
/// AND a regular file (no-follow stat — never deletes through a symlink). Never touches aliases
/// (while `DUAL_WRITE_FLAT_ALIAS` holds), dotfiles/temps, or foreign names — those never appear
/// in `scan.unreferenced` to begin with.
pub fn prune(store: &Path, scan: &StoreScan, delete: bool) -> Result<PruneReport, StoreAdminError> {
    if !scan.refusals.is_empty() {
        return Ok(PruneReport {
            candidates: Vec::new(),
            deleted: Vec::new(),
            failed: Vec::new(),
            refused: Some(format!(
                "the reference scan is incomplete ({} refusal(s) — run `market store status` to \
                 see them); refusing to prune until they clear",
                scan.refusals.len()
            )),
        });
    }
    let candidates = scan.unreferenced.clone();
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    if delete {
        for e in &candidates {
            let name = format!("{}@{}", e.key, e.sha);
            if !matches!(parse_store_name(&name), StoreName::Revision { .. }) {
                failed.push(format!(
                    "{name}: not a conforming revision name — left in place"
                ));
                continue;
            }
            let path = store.join(&name);
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    failed.push(format!(
                        "{name}: vanished since the scan (nothing to delete)"
                    ));
                    continue;
                }
                Err(e) => {
                    failed.push(format!("{name}: stat failed: {e}"));
                    continue;
                }
            };
            if !meta.is_file() {
                failed.push(format!(
                    "{name}: not a regular file (a symlink?) — left in place; remove it by hand if intended"
                ));
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => deleted.push(name),
                Err(e) => failed.push(format!("{name}: remove_file failed: {e}")),
            }
        }
    }
    Ok(PruneReport {
        candidates,
        deleted,
        failed,
        refused: None,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrateReport {
    pub linked: usize,
    pub already: usize,
    /// Every alias NOT migrated, each with its reason (not a regular file / unreadable /
    /// revision name occupied) — named, never a silent skip or a bare count.
    pub skipped: Vec<String>,
}

/// EXDEV (`errno` 18) — the store and a hardlink target could sit on different filesystems (an
/// operator-configured `$FRUIT_ARTIFACT_STORE` on another mount); `migrate` falls back to a copy
/// only for exactly this error, never masking a genuine failure.
const EXDEV: i32 = 18;

/// Hardlink (copy fallback on EXDEV) each flat `Alias` blob to its `<key>@sha256(bytes)` revision
/// name, if that revision is absent. Idempotent (a second run finds the revisions already
/// present); keeps every flat (the dual-write transition is unaffected); a symlinked flat is
/// refused via a no-follow stat BEFORE any read — a NAMED skip, never followed. Every alias not
/// migrated lands in `MigrateReport::skipped` with its reason.
pub fn migrate(store: &Path) -> Result<MigrateReport, StoreAdminError> {
    use sha2::{Digest, Sha256};
    let mut report = MigrateReport::default();
    let read_dir = fs::read_dir(store).map_err(|e| StoreAdminError::ReadDir {
        path: store.display().to_string(),
        source: e,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|e| StoreAdminError::ReadDir {
            path: store.display().to_string(),
            source: e,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let StoreName::Alias { key } = parse_store_name(&name) else {
            continue;
        };
        let path = store.join(&name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                report.skipped.push(format!("{name}: stat failed: {e}"));
                continue;
            }
        };
        if !meta.is_file() {
            report.skipped.push(format!(
                "{name}: not a regular file (a symlink?) — never followed"
            ));
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                report.skipped.push(format!("{name}: read failed: {e}"));
                continue;
            }
        };
        let sha = hex::encode(Sha256::digest(&bytes));
        let rev_name = format!("{key}@{sha}");
        let rev_path = store.join(&rev_name);
                                                                                        
                                                                                            
                                                                                     
        match fs::symlink_metadata(&rev_path) {
            Ok(m) if m.is_file() => {
                report.already += 1;
                continue;
            }
            Ok(_) => {
                report.skipped.push(format!(
                    "{rev_name}: revision name occupied by a non-regular file — not migrated; see `market store status`/`prune`"
                ));
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}                       
            Err(e) => {
                report.skipped.push(format!("{rev_name}: stat failed: {e}"));
                continue;
            }
        }
        match fs::hard_link(&path, &rev_path) {
            Ok(()) => report.linked += 1,
            Err(e) if e.raw_os_error() == Some(EXDEV) => {
                fs::copy(&path, &rev_path).map_err(|e| StoreAdminError::Io {
                    path: rev_path.display().to_string(),
                    source: e,
                })?;
                report.linked += 1;
            }
            Err(e) => {
                return Err(StoreAdminError::Io {
                    path: rev_path.display().to_string(),
                    source: e,
                });
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(repo: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A real-tempdir git repo (mirrors `git_commit.rs::test_repo`): local user config +
    /// gpg-sign/maintenance off, self-contained.
    fn test_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        run_git(dir.path(), &["init", "-q"]);
        run_git(dir.path(), &["config", "user.name", "store-admin-test"]);
        run_git(
            dir.path(),
            &["config", "user.email", "store-admin-test@example.invalid"],
        );
        run_git(dir.path(), &["config", "commit.gpgsign", "false"]);
        run_git(dir.path(), &["config", "maintenance.auto", "false"]);
        run_git(dir.path(), &["config", "gc.auto", "0"]);
        std::fs::write(dir.path().join("README"), "seed\n").unwrap();
        run_git(dir.path(), &["add", "README"]);
        run_git(dir.path(), &["commit", "-q", "-m", "seed"]);
        dir
    }

    fn sha_of(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn worktree_checkouts_enumerates_added_worktrees() {
        let repo = test_repo();
        let wt_dir = repo.path().parent().unwrap().join("wt2");
        run_git(
            repo.path(),
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "b2",
                wt_dir.to_str().unwrap(),
            ],
        );
        let entries = worktree_checkouts(repo.path()).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].path, repo.path());
        assert!(!entries[0].prunable);
        assert_eq!(entries[1].path, wt_dir);
        assert!(!entries[1].prunable);
        std::fs::remove_dir_all(&wt_dir).ok();
    }

    #[test]
    fn worktree_checkouts_flags_prunable_entries() {
        let repo = test_repo();
        let wt_dir = repo.path().parent().unwrap().join("wt-stale");
        run_git(
            repo.path(),
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "b-stale",
                wt_dir.to_str().unwrap(),
            ],
        );
        std::fs::remove_dir_all(&wt_dir).unwrap();
        let entries = worktree_checkouts(repo.path()).unwrap();
        let stale = entries
            .iter()
            .find(|e| e.path == wt_dir)
            .expect("stale entry still listed");
        assert!(stale.prunable);
    }

    #[test]
    fn parse_store_name_still_the_shared_classifier() {
                                                                                                  
                                       
        let sha = "a".repeat(64);
        assert_eq!(
            parse_store_name(&format!("grape-src@{sha}")),
            StoreName::Revision {
                key: "grape-src".into(),
                sha
            }
        );
    }

                                                                                                
    /// `sha_main`, plus a git WORKTREE of it on a branch whose published-pins pins `sha_dha`; the
    /// store holds both revisions. Both must classify REFERENCED.
    #[test]
    fn scan_classifies_the_divergent_worktree_as_referenced() {
        let orchard = test_repo();
        let fb = test_repo();
        let bytes_main = b"MAIN-BYTES";
        let bytes_dha = b"DHA-BYTES";
        let sha_main = sha_of(bytes_main);
        let sha_dha = sha_of(bytes_dha);
        std::fs::write(
            fb.path().join("published-pins.toml"),
            format!("[artifacts]\nfb-manifest-src = \"{sha_main}\"\n"),
        )
        .unwrap();
        run_git(fb.path(), &["add", "published-pins.toml"]);
        run_git(fb.path(), &["commit", "-q", "-m", "pin"]);

        let fb_wt_parent = tempfile::tempdir().unwrap();
        let fb_wt = fb_wt_parent.path().join("fb-dha");
        run_git(
            fb.path(),
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "dha",
                fb_wt.to_str().unwrap(),
            ],
        );
        std::fs::write(
            fb_wt.join("published-pins.toml"),
            format!("[artifacts]\nfb-manifest-src = \"{sha_dha}\"\n"),
        )
        .unwrap();

        std::fs::write(
            orchard.path().join("consume-pins.toml"),
            "schema-version = 1\n[artifacts]\n",
        )
        .unwrap();

        let store = tempfile::tempdir().unwrap();
        std::fs::write(
            store.path().join(format!("fb-manifest-src@{sha_main}")),
            bytes_main,
        )
        .unwrap();
        std::fs::write(
            store.path().join(format!("fb-manifest-src@{sha_dha}")),
            bytes_dha,
        )
        .unwrap();

        let manifest_toml = format!(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"{}\"\nartifacts = [\"fb-manifest-src\"]\n",
            fb.path().display()
        );
        let manifest = RepoManifest::from_toml_str(&manifest_toml).unwrap();

        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(scan.refusals.is_empty(), "{:?}", scan.refusals);
        let refd: HashSet<&str> = scan.referenced.iter().map(|e| e.sha.as_str()).collect();
        assert!(refd.contains(sha_main.as_str()), "{scan:?}");
        assert!(refd.contains(sha_dha.as_str()), "{scan:?}");
        assert!(scan.unreferenced.is_empty(), "{:?}", scan.unreferenced);
        std::fs::remove_dir_all(&fb_wt).ok();
    }

    #[test]
    fn scan_is_fail_honest() {
        let orchard = test_repo();
        std::fs::write(
            orchard.path().join("consume-pins.toml"),
            "schema-version = 1\n[artifacts]\n",
        )
        .unwrap();
        let store = tempfile::tempdir().unwrap();

                                       
        let manifest_toml = "schema-version = 1\n[repos.ghost]\npath = \"/nonexistent/ghost-repo\"\nartifacts = [\"ghost-src\"]\n";
        let manifest = RepoManifest::from_toml_str(manifest_toml).unwrap();
        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(
            scan.refusals.iter().any(|r| r.contains("ghost")),
            "{:?}",
            scan.refusals
        );

                                                                     
        let fb = test_repo();                                          
        let manifest_toml = format!(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"{}\"\nartifacts = [\"fb-manifest-src\"]\n",
            fb.path().display()
        );
        let manifest = RepoManifest::from_toml_str(&manifest_toml).unwrap();
        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(
            scan.refusals
                .iter()
                .any(|r| r.contains("published-pins") && r.contains("unreadable")),
            "{:?}",
            scan.refusals
        );

                                         
        let fb2 = test_repo();
        std::fs::write(fb2.path().join("published-pins.toml"), "[artifacts]\n").unwrap();
        run_git(fb2.path(), &["add", "published-pins.toml"]);
        run_git(fb2.path(), &["commit", "-q", "-m", "pin"]);
        let wt = fb2.path().parent().unwrap().join("fb2-stale");
        run_git(
            fb2.path(),
            &["worktree", "add", "-q", "-b", "stale", wt.to_str().unwrap()],
        );
        std::fs::remove_dir_all(&wt).unwrap();
        let manifest_toml = format!(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"{}\"\nartifacts = [\"fb-manifest-src\"]\n",
            fb2.path().display()
        );
        let manifest = RepoManifest::from_toml_str(&manifest_toml).unwrap();
        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(
            scan.refusals
                .iter()
                .any(|r| r.contains("git worktree prune")),
            "{:?}",
            scan.refusals
        );
    }

                                                                                                
    /// dropped key would classify its store revision UNREFERENCED (the dangerous direction).
    #[test]
    fn scan_refuses_a_non_string_published_pin_value() {
        let orchard = test_repo();
        std::fs::write(
            orchard.path().join("consume-pins.toml"),
            "schema-version = 1\n[artifacts]\n",
        )
        .unwrap();
        let fb = test_repo();
        std::fs::write(
            fb.path().join("published-pins.toml"),
            "[artifacts]\nfb-manifest-src = 42\n",
        )
        .unwrap();
        run_git(fb.path(), &["add", "published-pins.toml"]);
        run_git(fb.path(), &["commit", "-q", "-m", "pin"]);
        let manifest_toml = format!(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"{}\"\nartifacts = [\"fb-manifest-src\"]\n",
            fb.path().display()
        );
        let manifest = RepoManifest::from_toml_str(&manifest_toml).unwrap();
        let store = tempfile::tempdir().unwrap();
        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(
            scan.refusals.iter().any(|r| r.contains("not a string")),
            "{:?}",
            scan.refusals
        );
    }

    #[test]
    fn render_status_names_the_blind_spot() {
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![],
            aliases: vec![],
            foreign: vec![],
            refusals: vec!["repo x: unreadable pins".into()],
            scanned_checkouts: vec![],
        };
        let out = render_status(&scan, Path::new("/data/store"), false, false);
        assert!(out.contains("plain COPY of a repo"), "{out}");
        assert!(out.contains("repo x: unreadable pins"), "{out}");
    }

    fn healthy_refs(n: usize) -> Vec<RevisionEntry> {
        (0..n)
            .map(|i| RevisionEntry {
                key: format!("k{i}"),
                sha: sha_of(format!("r{i}").as_bytes()),
                size: 10,
            })
            .collect()
    }

    #[test]
    fn healthy_status_collapses_referenced_and_aliases_to_counts() {
                                                                                                      
        let scan = StoreScan {
            referenced: healthy_refs(39),
            unreferenced: vec![],
            aliases: (0..39).map(|i| format!("a{i}")).collect(),
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let out = render_status(&scan, Path::new("/store"), false, false);
        assert!(out.contains("referenced revisions: 39"), "{out}");
        assert!(
            !out.contains('@'),
            "no per-entry revision lines in the healthy default: {out}"
        );
        assert!(out.contains("aliases (flat, legacy): 39"), "{out}");
    }

    #[test]
    fn abbrev_is_disambiguated_across_the_referenced_unreferenced_boundary() {
                                                                                                      
                                                                                                     
                                                                                                    
        let a = format!("{}{}", "a".repeat(12), "1".repeat(52));
        let b = format!("{}{}", "a".repeat(12), "2".repeat(52));
        let scan = StoreScan {
            referenced: vec![RevisionEntry {
                key: "kr".into(),
                sha: a,
                size: 10,
            }],
            unreferenced: vec![RevisionEntry {
                key: "ku".into(),
                sha: b,
                size: 5,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let out = render_status(&scan, Path::new("/store"), true, false);
        let abbrev_after = |needle: &str| -> String {
            out.lines()
                .find(|l| l.contains(needle))
                .and_then(|l| l.split('@').nth(1))
                .and_then(|t| t.split_whitespace().next())
                .unwrap()
                .to_string()
        };
        let kr = abbrev_after("kr@");
        let ku = abbrev_after("ku@");
        assert_ne!(
            kr, ku,
            "distinct shas must render distinctly across categories: {out}"
        );
        assert!(kr.len() > 12, "extended past the shared 12-prefix: {kr}");
    }

    #[test]
    fn unreferenced_always_itemizes_even_in_default() {
                                                                                
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha_of(b"U"),
                size: 5,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let out = render_status(&scan, Path::new("/store"), false, false);
        assert!(out.contains("unreferenced revisions: 1"), "{out}");
        assert!(
            out.contains('@'),
            "the unreferenced revision itemizes: {out}"
        );
    }

    #[test]
    fn all_itemizes_referenced() {
                                                         
        let scan = StoreScan {
            referenced: healthy_refs(39),
            unreferenced: vec![],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let out = render_status(&scan, Path::new("/store"), true, false);
        assert!(
            out.matches('@').count() >= 39,
            "--all itemizes referenced: {out}"
        );
    }

    #[test]
    fn prune_without_delete_prints_only() {
        let store = tempfile::tempdir().unwrap();
        let sha = sha_of(b"UNREF");
        std::fs::write(store.path().join(format!("k@{sha}")), b"UNREF").unwrap();
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha.clone(),
                size: 5,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let report = prune(store.path(), &scan, false).unwrap();
        assert!(report.refused.is_none());
        assert!(report.deleted.is_empty());
        assert_eq!(report.candidates.len(), 1);
        assert!(store.path().join(format!("k@{sha}")).exists());
    }

    #[test]
    fn prune_refuses_on_incomplete_scan() {
        let store = tempfile::tempdir().unwrap();
        let sha = sha_of(b"UNREF");
        std::fs::write(store.path().join(format!("k@{sha}")), b"UNREF").unwrap();
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha.clone(),
                size: 5,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec!["some-repo: unreadable pins".into()],
            scanned_checkouts: vec![],
        };
        let report = prune(store.path(), &scan, true).unwrap();
        assert!(report.refused.is_some(), "{report:?}");
        assert!(report.deleted.is_empty());
        assert!(store.path().join(format!("k@{sha}")).exists());
    }

    #[test]
    fn prune_deletes_only_conforming_unreferenced() {
        let store = tempfile::tempdir().unwrap();
        let sha_unref = sha_of(b"UNREF");
        let sha_ref = sha_of(b"REF");
        std::fs::write(store.path().join(format!("k@{sha_unref}")), b"UNREF").unwrap();
        std::fs::write(store.path().join(format!("k@{sha_ref}")), b"REF").unwrap();
        std::fs::write(store.path().join("k"), b"ALIAS").unwrap();
        std::fs::write(store.path().join(".put-x.tmp"), b"TMP").unwrap();
        std::fs::write(store.path().join("junk@bad@name"), b"FOREIGN").unwrap();
        let scan = StoreScan {
            referenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha_ref.clone(),
                size: 3,
            }],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha_unref.clone(),
                size: 5,
            }],
            aliases: vec!["k".into()],
            foreign: vec![".put-x.tmp".into(), "junk@bad@name".into()],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let report = prune(store.path(), &scan, true).unwrap();
        assert!(report.refused.is_none());
        assert_eq!(report.deleted, vec![format!("k@{sha_unref}")]);
        assert!(!store.path().join(format!("k@{sha_unref}")).exists());
        assert!(store.path().join(format!("k@{sha_ref}")).exists());
        assert!(store.path().join("k").exists());
        assert!(store.path().join(".put-x.tmp").exists());
        assert!(store.path().join("junk@bad@name").exists());
    }

                                                                                          
    /// referenced (Task 5), and MUST survive a `prune(delete: true)` (Task 6) — the incident
    /// cannot recur as a deletion either.
    #[test]
    fn divergent_worktree_pin_survives_prune() {
        let orchard = test_repo();
        let fb = test_repo();
        let bytes_main = b"MAIN-BYTES";
        let bytes_dha = b"DHA-BYTES";
        let sha_main = sha_of(bytes_main);
        let sha_dha = sha_of(bytes_dha);
        std::fs::write(
            fb.path().join("published-pins.toml"),
            format!("[artifacts]\nfb-manifest-src = \"{sha_main}\"\n"),
        )
        .unwrap();
        run_git(fb.path(), &["add", "published-pins.toml"]);
        run_git(fb.path(), &["commit", "-q", "-m", "pin"]);

        let fb_wt_parent = tempfile::tempdir().unwrap();
        let fb_wt = fb_wt_parent.path().join("fb-dha");
        run_git(
            fb.path(),
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "dha",
                fb_wt.to_str().unwrap(),
            ],
        );
        std::fs::write(
            fb_wt.join("published-pins.toml"),
            format!("[artifacts]\nfb-manifest-src = \"{sha_dha}\"\n"),
        )
        .unwrap();

        std::fs::write(
            orchard.path().join("consume-pins.toml"),
            "schema-version = 1\n[artifacts]\n",
        )
        .unwrap();

        let store = tempfile::tempdir().unwrap();
        std::fs::write(
            store.path().join(format!("fb-manifest-src@{sha_main}")),
            bytes_main,
        )
        .unwrap();
        std::fs::write(
            store.path().join(format!("fb-manifest-src@{sha_dha}")),
            bytes_dha,
        )
        .unwrap();

        let manifest_toml = format!(
            "schema-version = 1\n[repos.fruit-basket]\npath = \"{}\"\nartifacts = [\"fb-manifest-src\"]\n",
            fb.path().display()
        );
        let manifest = RepoManifest::from_toml_str(&manifest_toml).unwrap();

        let scan = scan_store(store.path(), &manifest, orchard.path()).unwrap();
        assert!(scan.refusals.is_empty(), "{:?}", scan.refusals);
        let report = prune(store.path(), &scan, true).unwrap();
        assert!(report.refused.is_none());
        assert!(report.deleted.is_empty(), "{:?}", report.deleted);
        assert!(
            store
                .path()
                .join(format!("fb-manifest-src@{sha_dha}"))
                .exists()
        );
        assert!(
            store
                .path()
                .join(format!("fb-manifest-src@{sha_main}"))
                .exists()
        );
    }

    #[test]
    fn migrate_links_flats_idempotently() {
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("grape-src"), b"GRAPE-BYTES").unwrap();
        let sha = sha_of(b"GRAPE-BYTES");
        let report = migrate(store.path()).unwrap();
        assert_eq!(
            report,
            MigrateReport {
                linked: 1,
                already: 0,
                skipped: vec![]
            }
        );
        let rev_path = store.path().join(format!("grape-src@{sha}"));
        assert!(rev_path.exists());
        assert!(store.path().join("grape-src").exists());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(&rev_path).unwrap().ino(),
            std::fs::metadata(store.path().join("grape-src"))
                .unwrap()
                .ino(),
            "migrate must hardlink, not copy, on the same filesystem"
        );

                                                 
        let report2 = migrate(store.path()).unwrap();
        assert_eq!(
            report2,
            MigrateReport {
                linked: 0,
                already: 1,
                skipped: vec![]
            }
        );

                                                                               
        let target = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(target.path(), b"ELSEWHERE").unwrap();
        std::os::unix::fs::symlink(target.path(), store.path().join("sym-key")).unwrap();
        let report3 = migrate(store.path()).unwrap();
        assert_eq!(report3.skipped.len(), 1, "{report3:?}");
        assert!(
            report3.skipped[0].contains("sym-key")
                && report3.skipped[0].contains("not a regular file"),
            "the skip must name the entry and the reason: {report3:?}"
        );
        assert!(
            !store
                .path()
                .join(format!(
                    "sym-key@{}",
                    sha_of(std::fs::read(target.path()).unwrap().as_slice())
                ))
                .exists(),
            "must never follow the symlink to create a revision"
        );
    }

                                                                                           
    /// declines to do may be silent. `deleted` + `failed` partition the candidate set EXACTLY.
    #[test]
    fn prune_names_a_symlink_candidate_and_still_deletes_the_rest() {
        let store = tempfile::tempdir().unwrap();
        let sha_file = sha_of(b"DELETABLE");
        std::fs::write(store.path().join(format!("k@{sha_file}")), b"DELETABLE").unwrap();
                                                                                            
        let target = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(target.path(), b"ELSEWHERE").unwrap();
        let sha_sym = "c".repeat(64);
        std::os::unix::fs::symlink(target.path(), store.path().join(format!("k@{sha_sym}")))
            .unwrap();
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![
                RevisionEntry {
                    key: "k".into(),
                    sha: sha_file.clone(),
                    size: 9,
                },
                RevisionEntry {
                    key: "k".into(),
                    sha: sha_sym.clone(),
                    size: 9,
                },
            ],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let report = prune(store.path(), &scan, true).unwrap();
        assert_eq!(report.deleted, vec![format!("k@{sha_file}")]);
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(
            report.failed[0].contains(&format!("k@{sha_sym}"))
                && report.failed[0].contains("not a regular file"),
            "the skip must name the entry and the reason: {report:?}"
        );
        assert_eq!(
            report.deleted.len() + report.failed.len(),
            report.candidates.len(),
            "deleted + failed must partition the candidates: {report:?}"
        );
                                                                            
        assert!(
            store
                .path()
                .join(format!("k@{sha_sym}"))
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(target.path()).unwrap(), b"ELSEWHERE");
    }

    #[test]
    fn prune_names_a_vanished_candidate() {
                                                                                       
        let store = tempfile::tempdir().unwrap();
        let sha = sha_of(b"GONE");
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha.clone(),
                size: 4,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
        let report = prune(store.path(), &scan, true).unwrap();
        assert!(report.deleted.is_empty());
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(
            report.failed[0].contains(&format!("k@{sha}")) && report.failed[0].contains("vanished"),
            "{report:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prune_names_a_failed_remove_and_leaves_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let store = tempfile::tempdir().unwrap();
        let sha = sha_of(b"LOCKED");
        let name = format!("k@{sha}");
        std::fs::write(store.path().join(&name), b"LOCKED").unwrap();
        let scan = StoreScan {
            referenced: vec![],
            unreferenced: vec![RevisionEntry {
                key: "k".into(),
                sha: sha.clone(),
                size: 6,
            }],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![],
        };
                                                                                                     
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let report = prune(store.path(), &scan, true).unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(report.deleted.is_empty(), "{report:?}");
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(
            report.failed[0].contains(&name) && report.failed[0].contains("remove_file failed"),
            "{report:?}"
        );
        assert!(store.path().join(&name).exists(), "file must survive");
    }

    #[cfg(unix)]
    #[test]
    fn migrate_names_an_unreadable_alias_and_links_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("ok-key"), b"OK").unwrap();
        std::fs::write(store.path().join("locked"), b"LOCKED").unwrap();
        std::fs::set_permissions(
            store.path().join("locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let report = migrate(store.path()).unwrap();
        assert_eq!(report.linked, 1, "{report:?}");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(
            report.skipped[0].contains("locked") && report.skipped[0].contains("read failed"),
            "{report:?}"
        );
                                                             
        let leaked: Vec<_> = std::fs::read_dir(store.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("locked@"))
            .collect();
        assert!(leaked.is_empty(), "{leaked:?}");
    }

    #[test]
    fn migrate_names_an_occupied_revision_name_without_erroring() {
                                                                                               
                                                                                                   
                                                         
        let store = tempfile::tempdir().unwrap();
        std::fs::write(store.path().join("k"), b"BYTES").unwrap();
        let sha = sha_of(b"BYTES");
        std::os::unix::fs::symlink("/nonexistent-target", store.path().join(format!("k@{sha}")))
            .unwrap();
        let report = migrate(store.path()).expect("occupied name must not hard-error");
        assert_eq!(report.linked, 0, "{report:?}");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(
            report.skipped[0].contains(&format!("k@{sha}"))
                && report.skipped[0].contains("occupied"),
            "{report:?}"
        );
    }

    #[test]
    fn fmt_size_humanizes() {
        assert_eq!(fmt_size(0), "0 B");
        assert_eq!(fmt_size(742), "742 B");
        assert_eq!(fmt_size(1024), "1.0 KiB");
        assert_eq!(fmt_size(9_679_232), "9.2 MiB");
        assert_eq!(fmt_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn render_status_names_the_store_and_scanned_checkouts() {
        let scan = StoreScan {
            referenced: vec![RevisionEntry {
                key: "k".into(),
                sha: "a".repeat(64),
                size: 9_679_232,
            }],
            unreferenced: vec![],
            aliases: vec![],
            foreign: vec![],
            refusals: vec![],
            scanned_checkouts: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
        };
                                                                                                     
                                      
        let out = render_status(&scan, Path::new("/data/store"), true, false);
        assert!(out.contains("store: /data/store"), "{out}");
        assert!(out.contains("scanned checkouts: 2"), "{out}");
        assert!(out.contains("9.2 MiB"), "sizes are humanized: {out}");
    }

    #[test]
    fn render_prune_refused_carries_the_store_header() {
                                                                                                
                                                          
        let refused = PruneReport {
            candidates: vec![],
            deleted: vec![],
            failed: vec![],
            refused: Some("the reference scan is incomplete (2 refusal(s))".into()),
        };
        let out = render_prune(&refused, true, Path::new("/data/store"), false);
        assert!(out.contains("store: /data/store"), "{out}");
        assert!(out.contains("REFUSED"), "{out}");
        assert!(out.contains("scan is incomplete"), "{out}");
        assert!(
            !out.contains("candidates"),
            "no candidate section on a refusal: {out}"
        );
    }

    fn one_candidate() -> PruneReport {
        PruneReport {
            candidates: vec![RevisionEntry {
                key: "k".into(),
                sha: "a".repeat(64),
                size: 5,
            }],
            deleted: vec![],
            failed: vec![],
            refused: None,
        }
    }

    #[test]
    fn prune_candidates_show_abbreviated_digests_by_default() {
                                                                                             
        let out = render_prune(&one_candidate(), false, Path::new("/store"), false);
        assert!(
            !out.contains(&"a".repeat(64)),
            "abbreviated by default: {out}"
        );
        assert!(
            out.contains(&"a".repeat(12)),
            "shows the 12-hex abbreviation: {out}"
        );
    }

    #[test]
    fn prune_full_restores_64_hex() {
                                                     
        let out = render_prune(&one_candidate(), false, Path::new("/store"), true);
        assert!(out.contains(&"a".repeat(64)), "--full shows 64-hex: {out}");
    }

    #[test]
    fn render_prune_shows_store_sizes_failures_and_dry_run_hint() {
        let entry = |sha: String, size: u64| RevisionEntry {
            key: "k".into(),
            sha,
            size,
        };
        let dry = PruneReport {
            candidates: vec![entry("a".repeat(64), 9_679_232), entry("b".repeat(64), 742)],
            deleted: vec![],
            failed: vec![],
            refused: None,
        };
        let out = render_prune(&dry, false, Path::new("/data/store"), false);
        assert!(out.contains("store: /data/store"), "{out}");
        assert!(
            out.contains("candidates (2, 9.2 MiB)"),
            "the header totals the reclaimable size: {out}"
        );
        assert!(out.contains("dry run"), "{out}");

        let ran = PruneReport {
            candidates: vec![entry("a".repeat(64), 9)],
            deleted: vec![],
            failed: vec![format!("k@{}: remove_file failed: denied", "a".repeat(64))],
            refused: None,
        };
        let out = render_prune(&ran, true, Path::new("/data/store"), false);
        assert!(out.contains("failed (1):"), "{out}");
        assert!(out.contains("remove_file failed"), "{out}");
        assert!(!out.contains("dry run"), "{out}");

        let empty = PruneReport {
            candidates: vec![],
            deleted: vec![],
            failed: vec![],
            refused: None,
        };
        let out = render_prune(&empty, false, Path::new("/data/store"), false);
        assert!(out.contains("nothing to prune"), "{out}");
    }

    #[test]
    fn render_migrate_names_the_store_and_skips() {
        let report = MigrateReport {
            linked: 2,
            already: 1,
            skipped: vec!["sym-key: not a regular file (symlink) — never followed".into()],
        };
        let out = render_migrate(&report, Path::new("/data/store"));
        assert!(out.contains("store: /data/store"), "{out}");
        assert!(out.contains("linked 2"), "{out}");
        assert!(out.contains("already-present 1"), "{out}");
        assert!(out.contains("skipped (1):"), "{out}");
        assert!(out.contains("sym-key"), "{out}");
    }
}
