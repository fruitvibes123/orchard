                                                                                            
//!
//! Three pieces, each independently testable:
//! - [`GitCommit`] — the git seam. Production [`ShellGit`] stages and commits PATHSPEC-SCOPED
//!   (`git -C <repo> add -- <paths>` then `git -C <repo> commit -F <msgfile> -- <paths>`), so a
                                                                                            
//!   message goes through a temp file, never a shell line (backtick-safe).
                                                                                                 
//!   IFF under `orchard_root`; a path under a known sibling repo root is PRINTED (its ready
//!   `git -C … commit` command); everything else — store blobs, the cert trail, any unmatched
//!   root — is EXCLUDED from both. Longest-prefix over LEXICALLY NORMALIZED paths: layout roots
//!   are built by joins like `<orchard>/../fruit-basket`, so an un-normalized `starts_with`
//!   would classify a SIBLING path as under-orchard (fail OPEN into an auto-commit). One
//!   normalizer for the whole crate: `market_exec::normalize`.
//! - [`plan_commit`] — partitions an `UpgradeReport::swapped` list three ways for the authorize
//!   gate (Task 6).
//!
//! The seam never decides WHETHER to commit — consent lives in the CLI's authorize gate; this
//! module only makes "commit exactly these paths in exactly this repo" a scoped, testable call.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::market_exec::{StoreLayout, normalize};

/// Commit-seam options. `no_verify` passes `--no-verify` (pre-commit and commit-msg are bypassed).
/// Market's seam; the ceremony commits through `ceremony::gate_commit` instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitOpts {
    pub no_verify: bool,
}

/// The commit seam: production = [`ShellGit`]; tests use a recording fake.
pub trait GitCommit {
    fn commit(
        &self,
        repo: &Path,
        paths: &[PathBuf],
        message: &str,
        opts: CommitOpts,
    ) -> Result<(), GitError>;
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git {op} in {repo}: {detail}")]
    Command {
        op: &'static str,
        repo: String,
        detail: String,
    },
    #[error("commit message tempfile: {0}")]
    Io(#[from] std::io::Error),
}

/// Real git, pathspec-scoped. `add -- <paths>` stages ONLY the swapped paths;
/// `commit -F <msgfile> -- <paths>` bounds the commit to exactly those paths even if the index
/// already held unrelated staged entries (git commits the pathspec'd state and leaves the rest
/// of the index as it was).
pub struct ShellGit;

impl ShellGit {
    fn run(repo: &Path, op: &'static str, args: &[&std::ffi::OsStr]) -> Result<(), GitError> {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .map_err(|e| GitError::Command {
                op,
                repo: repo.display().to_string(),
                detail: format!("spawn git: {e}"),
            })?;
        if !out.status.success() {
            return Err(GitError::Command {
                op,
                repo: repo.display().to_string(),
                detail: format!(
                    "{}\n{}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(())
    }
}

impl GitCommit for ShellGit {
    fn commit(
        &self,
        repo: &Path,
        paths: &[PathBuf],
        message: &str,
        opts: CommitOpts,
    ) -> Result<(), GitError> {
                                                                                                
                                                                              
        let mut msgfile = tempfile::NamedTempFile::new()?;
        msgfile.write_all(message.as_bytes())?;
        msgfile.flush()?;

        let mut add_args: Vec<&std::ffi::OsStr> = vec!["add".as_ref(), "--".as_ref()];
        add_args.extend(paths.iter().map(|p| p.as_os_str()));
        Self::run(repo, "add", &add_args)?;

        let mut commit_args: Vec<&std::ffi::OsStr> = vec!["commit".as_ref()];
        if opts.no_verify {
            commit_args.push("--no-verify".as_ref());
        }
        commit_args.extend(["-F".as_ref(), msgfile.path().as_os_str(), "--".as_ref()]);
        commit_args.extend(paths.iter().map(|p| p.as_os_str()));
        Self::run(repo, "commit", &commit_args)
    }
}

                                            
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bucket {
    /// Under `orchard_root`: committed by market (on an explicit consent only — Task 6).
    CommitOrchard,
    /// Under a known sibling repo root: market PRINTS the ready `git -C <root> commit` command
    /// (never runs it — the cross-repo-auto-commit prohibition). Carries (repo name, repo root).
    PrintSibling(String, PathBuf),
    /// Everything else: store blobs (bound by their committed pins, not a git target), the cert
    /// trail, and ANY path matching no known root — fail-closed, never committed, never printed.
    Exclude,
}

/// Classify one swapped path against the layout's known roots — longest NORMALIZED prefix wins,
                                                                    
pub fn bucket_of(path: &Path, layout: &StoreLayout) -> Bucket {
    let p = normalize(path);
                                                                                              
                                                                                           
    let mut best: Option<(usize, Bucket)> = None;
    let mut consider = |root: &Path, bucket: Bucket| {
        let root = normalize(root);
        if p.starts_with(&root) {
            let depth = root.components().count();
            if best.as_ref().is_none_or(|(d, _)| depth > *d) {
                best = Some((depth, bucket));
            }
        }
    };
    consider(&layout.orchard_root, Bucket::CommitOrchard);
    for (name, root) in &layout.repos {
        consider(root, Bucket::PrintSibling(name.clone(), root.clone()));
    }
    consider(&layout.store, Bucket::Exclude);
    if let Some(trail) = &layout.cert_trail {
        consider(trail, Bucket::Exclude);
    }
    best.map(|(_, b)| b).unwrap_or(Bucket::Exclude)
}

/// The three-way partition of `UpgradeReport::swapped` the authorize gate drives (Task 6).
/// Paths are NORMALIZED on the way in (they arrive layout-derived, `..`-bearing).
#[derive(Debug, Default)]
pub struct CommitPlan {
    /// Orchard paths — the only ones market may commit (on explicit consent).
    pub orchard: Vec<PathBuf>,
    /// repo name -> (repo root, its swapped paths) — printed as ready commands, never run.
    pub siblings: BTreeMap<String, (PathBuf, Vec<PathBuf>)>,
    /// Store blobs / cert trail / unmatched — neither committed nor printed as a git target.
    pub excluded: Vec<PathBuf>,
}

pub fn plan_commit(swapped: &[PathBuf], layout: &StoreLayout) -> CommitPlan {
    let mut plan = CommitPlan::default();
    for path in swapped {
        let p = normalize(path);
        match bucket_of(path, layout) {
            Bucket::CommitOrchard => plan.orchard.push(p),
            Bucket::PrintSibling(name, root) => {
                plan.siblings
                    .entry(name)
                    .or_insert_with(|| (normalize(&root), Vec::new()))
                    .1
                    .push(p);
            }
            Bucket::Exclude => plan.excluded.push(p),
        }
    }
    plan
}

                                                                                        

                                                                                                 
/// at PARSE (clap `conflicts_with`); the precedence here backstops it anyway (opt-out wins).
#[derive(Debug, Clone, Copy, Default)]
pub struct UpgradeFlags {
    /// `--commit` / `--yes`: pre-authorized — the ONLY non-interactive commit path.
    pub commit: bool,
    /// `--no-commit`: never commit, print the ready command (beats everything).
    pub no_commit: bool,
    /// `--dry-run`: never reaches the gate today (the CLI returns before execute), kept in the
    /// matrix as defense in depth — if wiring ever changes, dry-run still means PrintOnly.
    pub dry_run: bool,
}

                                                                                         
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Commit,
    EditThenCommit,
    PrintOnly,
}

                                                                                            
/// consent): `--no-commit`/`--dry-run` → PrintOnly (explicit opt-out beats even `--commit`);
/// `--commit`/`--yes` → Commit (any TTY state — the operator/CI asked by flag); interactive TTY →
/// the caller's prompt decides (`y`→Commit, `e`→EditThenCommit, anything else→PrintOnly, default
/// N); headless (no flag, not a TTY: CI/cron/pipe) → PrintOnly. The prompt closure runs ONLY on
/// the interactive branch.
pub fn consent_from(flags: &UpgradeFlags, is_tty: bool, prompt: impl FnOnce() -> char) -> Consent {
    if flags.no_commit || flags.dry_run {
        return Consent::PrintOnly;
    }
    if flags.commit {
        return Consent::Commit;
    }
    if !is_tty {
        return Consent::PrintOnly;
    }
    match prompt().to_ascii_lowercase() {
        'y' => Consent::Commit,
        'e' => Consent::EditThenCommit,
        _ => Consent::PrintOnly,
    }
}

                                                                                                 
/// sha deltas read from git-HEAD-vs-on-disk of `orchard_paths` — NEVER from the advisory drift
                                                                                           
/// unparsable/undiffable file degrades to its basename in the subject — composing a message can
/// never block the (already-swapped, already-verified) upgrade.
pub fn compose_message(
    target: &super::market_upgrade::Target,
    orchard_root: &Path,
    orchard_paths: &[PathBuf],
) -> String {
    use super::market_upgrade::Target;
    let mut deltas: Vec<String> = Vec::new();
    let mut plain_files: Vec<String> = Vec::new();
    for path in orchard_paths {
        let basename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        match pin_deltas(orchard_root, path) {
            Some(d) if !d.is_empty() => deltas.extend(d),
            _ => plain_files.push(basename),
        }
    }

    let leg = match target {
        Target::Source(_) => "source",
        Target::Binary(_) => "binary",
        Target::Config(_) => "config",
        Target::Apks => "apks",
        Target::Kernel(_) => "kernel",
        Target::Rust(_) => "rust",
        Target::All => "all",
    };
    let subject = match target {
        Target::Kernel(v) => {
            format!("pin(kernel): bump to linux-{v} (PGP-verified; four-way pins.toml)")
        }
        Target::Rust(v) => {
            format!("pin(rust): bump to {v} (release-manifest-verified; container re-pinned)")
        }
        _ if deltas.is_empty() && plain_files.is_empty() => format!("pin({leg}): re-pin"),
        _ if deltas.is_empty() => format!("pin({leg}): re-pin — {}", plain_files.join(", ")),
        _ if deltas.len() <= 3 => format!("pin({leg}): re-pin — {}", deltas.join(", ")),
        _ => format!("pin({leg}): re-pin — {} pins moved", deltas.len()),
    };

    let mut msg = subject;
    if !deltas.is_empty() {
        msg.push_str("\n\n");
        for d in &deltas {
            msg.push_str(&format!("- {d}\n"));
        }
    }
    if !plain_files.is_empty() && !deltas.is_empty() {
        msg.push_str(&format!("\nalso swapped: {}\n", plain_files.join(", ")));
    }
    msg
}

/// The per-file delta lines, read from the AUTHENTICATED sources only: git-HEAD (old) vs the
/// on-disk swapped file (new). `None` = undiffable (untracked / unreadable / unparsable) — the
/// caller degrades to the basename. Never an error.
fn pin_deltas(repo_root: &Path, path: &Path) -> Option<Vec<String>> {
    let p = normalize(path);
    let rel = p.strip_prefix(normalize(repo_root)).ok()?.to_path_buf();
    let old = git_show_head(repo_root, &rel)?;
    let new = std::fs::read_to_string(&p).ok()?;
    match rel.file_name()?.to_str()? {
        "pinned-apks.toml" => apk_version_deltas(&old, &new),
        "pins.toml" | "consume-pins.toml" | "published-pins.toml" => {
            toml_string_leaf_deltas(&old, &new)
        }
        _ => None,
    }
}

/// `git -C <repo> show HEAD:<rel>` — the OLD (authenticated, committed) file content.
fn git_show_head(repo: &Path, rel: &Path) -> Option<String> {
    let spec = format!("HEAD:{}", rel.display());
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show", &spec])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// name → version diffs of a `pinned-apks.toml` pair (packages + build_inputs, name-keyed).
fn apk_version_deltas(old: &str, new: &str) -> Option<Vec<String>> {
    use recipes_image_builder::PinnedApks;
    fn versions(text: &str) -> Option<BTreeMap<String, String>> {
        let lock = PinnedApks::from_toml_str(text).ok()?;
        Some(
            lock.build_inputs
                .iter()
                .chain(lock.packages.iter())
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect(),
        )
    }
    let o = versions(old)?;
    let n = versions(new)?;
    let mut out = Vec::new();
    for (name, ov) in &o {
        match n.get(name) {
            Some(nv) if nv != ov => out.push(format!("{name} {ov}\u{2192}{nv}")),
            Some(_) => {}
            None => out.push(format!("{name} (dropped)")),
        }
    }
    for (name, nv) in &n {
        if !o.contains_key(name) {
            out.push(format!("{name} +{nv}"));
        }
    }
    Some(out)
}

/// Generic string-leaf diff of two TOML documents (dotted-path keyed) — covers `pins.toml`
/// version bumps and `consume-pins`/`published-pins` sha re-pins in one shape. 64-hex values
/// are shortened to 12 chars for the message.
fn toml_string_leaf_deltas(old: &str, new: &str) -> Option<Vec<String>> {
    fn leaves(v: &toml::Value, prefix: &str, out: &mut BTreeMap<String, String>) {
        match v {
            toml::Value::String(s) => {
                out.insert(prefix.to_string(), s.clone());
            }
            toml::Value::Table(t) => {
                for (k, val) in t {
                    let p = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    leaves(val, &p, out);
                }
            }
            _ => {}
        }
    }
    fn short(s: &str) -> String {
        let hexish = s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        if hexish {
            format!("{}\u{2026}", &s[..12])
        } else {
            s.to_string()
        }
    }
    let o: toml::Value = old.parse().ok()?;
    let n: toml::Value = new.parse().ok()?;
    let mut om = BTreeMap::new();
    let mut nm = BTreeMap::new();
    leaves(&o, "", &mut om);
    leaves(&n, "", &mut nm);
    let mut out = Vec::new();
    for (k, ov) in &om {
        match nm.get(k) {
            Some(nv) if nv != ov => out.push(format!("{k} {}\u{2192}{}", short(ov), short(nv))),
            _ => {}
        }
    }
    for (k, nv) in &nm {
        if !om.contains_key(k) {
            out.push(format!("{k} +{}", short(nv)));
        }
    }
    Some(out)
}

                                                                                                
/// operator eyeballs before consenting. The composed-message deltas alone under-inform: a rewrite
/// that changes NO parsed value (drive-observed: the Repin step's comment/format churn on
/// `consume-pins.toml`) is invisible in the deltas but LOUD in the stat. Fail-soft: `None` on any
/// git error (the print is advisory; consent still rests with the operator).
pub fn diff_stat(repo: &Path, paths: &[PathBuf]) -> Option<String> {
    let mut args: Vec<&std::ffi::OsStr> = vec!["diff".as_ref(), "--stat".as_ref(), "--".as_ref()];
    args.extend(paths.iter().map(|p| p.as_os_str()));
                                                                                                    
                                                                                                   
                                            
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("-c")
        .arg("diff.autoRefreshIndex=false")
        .args(&args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// The outcome of an interactive message edit. `Aborted` carries the four abort gestures (no
/// editor configured, spawn failure, non-zero exit, empty-after-trim) as one typed value both
                                                                                                   
                       
#[derive(Debug, PartialEq, Eq)]
pub enum EditOutcome {
    Edited(String),
    Aborted,
}

/// Run `editor` on `initial` (via a temp file). The `$EDITOR` read lives in the CLI; this takes it
/// as a parameter for testability.
pub fn edit_message_with(editor: Option<&std::ffi::OsStr>, initial: &str) -> EditOutcome {
    let Some(editor) = editor else {
        return EditOutcome::Aborted;
    };
    if editor.is_empty() {
        return EditOutcome::Aborted;
    }
    let Ok(mut f) = tempfile::NamedTempFile::new() else {
        return EditOutcome::Aborted;
    };
    if f.write_all(initial.as_bytes()).is_err() || f.flush().is_err() {
        return EditOutcome::Aborted;
    }
                                                                                                  
                                                                                               
    let Ok(status) = Command::new(editor).arg(f.path()).status() else {
        return EditOutcome::Aborted;
    };
    if !status.success() {
        return EditOutcome::Aborted;
    }
    let Ok(edited) = std::fs::read_to_string(f.path()) else {
        return EditOutcome::Aborted;
    };
    let trimmed = edited.trim();
    if trimmed.is_empty() {
        EditOutcome::Aborted
    } else {
        EditOutcome::Edited(trimmed.to_string())
    }
}

/// The ready-to-run command printed on every non-commit path (and for every sibling): add +
/// commit, pathspec-scoped, message from the persisted file — exactly what [`ShellGit`] would
/// run, so hand-running it reproduces market's commit byte-for-byte.
pub fn render_ready_command(repo: &Path, msgfile: &Path, paths: &[PathBuf]) -> String {
    let list = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "git -C {r} add -- {list} && git -C {r} commit -F {m} -- {list}",
        r = repo.display(),
        m = msgfile.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout shaped exactly like production: sibling + store roots built by `..`-joins off the
    /// orchard root (resolve_layout's lexical join), UN-normalized on purpose.
    fn layout() -> StoreLayout {
        let orchard = PathBuf::from("/eco/orchard");
        StoreLayout {
            store: crate::deploy::context::store_default(&orchard),
            repo_manifest: crate::deploy::context::manifest_default(&orchard),
            repos: BTreeMap::from([
                ("fruit-basket".to_string(), orchard.join("../fruit-basket")),
                ("recipes".to_string(), orchard.join("../../recipes")),
            ]),
            cert_trail: Some(orchard.join("../../cookbook/trail")),
            orchard_root: orchard,
        }
    }

    #[test]
    fn bucket_of_is_a_fail_closed_allowlist() {
        let l = layout();
        assert_eq!(
            bucket_of(Path::new("/eco/orchard/consume-pins.toml"), &l),
            Bucket::CommitOrchard
        );
        assert_eq!(
            bucket_of(
                Path::new("/eco/orchard/crates/image-builder/pinned-apks.toml"),
                &l
            ),
            Bucket::CommitOrchard
        );
        match bucket_of(Path::new("/eco/fruit-basket/published-pins.toml"), &l) {
            Bucket::PrintSibling(name, _) => assert_eq!(name, "fruit-basket"),
            other => panic!("sibling path must print, got {other:?}"),
        }
        assert_eq!(
            bucket_of(Path::new("/eco/artifact-store/fb-manifest-src"), &l),
            Bucket::Exclude,
            "store blobs are never a git target"
        );
        assert_eq!(
            bucket_of(Path::new("/cookbook/trail/x/cert.md"), &l),
            Bucket::Exclude,
            "the cert trail is read-only to market"
        );
        assert_eq!(
            bucket_of(Path::new("/tmp/unrelated"), &l),
            Bucket::Exclude,
            "an unmatched root NEVER falls open into a commit"
        );
    }

    #[test]
    fn embedded_dotdot_cannot_fail_open_into_commit_orchard() {
                                                                                           
                                                                                                 
                                                                                       
        let l = layout();
        let sneaky = Path::new("/eco/orchard/../fruit-basket/published-pins.toml");
        match bucket_of(sneaky, &l) {
            Bucket::PrintSibling(name, _) => assert_eq!(name, "fruit-basket"),
            other => {
                panic!("a ..-bearing sibling path must classify as the SIBLING, got {other:?}")
            }
        }
        let sneaky_store = Path::new("/eco/orchard/../artifact-store/blob");
        assert_eq!(bucket_of(sneaky_store, &l), Bucket::Exclude);
    }

    #[test]
    fn longest_prefix_wins_for_nested_roots() {
                                                                                                
                                                                                                  
        let orchard = PathBuf::from("/eco/orchard");
        let l = StoreLayout {
            store: orchard.join("local-store"),
            repo_manifest: crate::deploy::context::manifest_default(&orchard),
            repos: BTreeMap::new(),
            cert_trail: None,
            orchard_root: orchard,
        };
        assert_eq!(
            bucket_of(Path::new("/eco/orchard/local-store/blob"), &l),
            Bucket::Exclude
        );
        assert_eq!(
            bucket_of(Path::new("/eco/orchard/consume-pins.toml"), &l),
            Bucket::CommitOrchard
        );
    }

    #[test]
    fn plan_commit_partitions_three_ways() {
        let l = layout();
        let swapped = vec![
            PathBuf::from("/eco/orchard/consume-pins.toml"),
            PathBuf::from("/eco/orchard/../fruit-basket/published-pins.toml"),
            PathBuf::from("/eco/orchard/../artifact-store/fb-manifest-src"),
        ];
        let plan = plan_commit(&swapped, &l);
        assert_eq!(
            plan.orchard,
            vec![PathBuf::from("/eco/orchard/consume-pins.toml")]
        );
        assert_eq!(plan.siblings.len(), 1);
        let (root, paths) = &plan.siblings["fruit-basket"];
        assert_eq!(
            root,
            Path::new("/eco/fruit-basket"),
            "root arrives normalized"
        );
        assert_eq!(
            paths,
            &vec![PathBuf::from("/eco/fruit-basket/published-pins.toml")]
        );
        assert_eq!(
            plan.excluded,
            vec![PathBuf::from("/eco/artifact-store/fb-manifest-src")]
        );
    }

    /// A real-tempdir git repo for the ShellGit probes: initialized with local user config +
    /// gpg-sign/maintenance off (self-contained; the grocer AC-G1 flake lesson).
    fn test_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "-q"]);
        run(&["config", "user.name", "market-test"]);
        run(&["config", "user.email", "market-test@example.invalid"]);
        run(&["config", "commit.gpgsign", "false"]);
        run(&["config", "maintenance.auto", "false"]);
        run(&["config", "gc.auto", "0"]);
        std::fs::write(dir.path().join("README"), "seed\n").unwrap();
        run(&["add", "README"]);
        run(&["commit", "-q", "-m", "seed"]);
        dir
    }

    fn git_stdout(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn shell_git_pathspec_scopes_the_commit() {
        let repo = test_repo();
                                                                                          
        std::fs::write(
            repo.path().join("unrelated.txt"),
            "operator's half-done work\n",
        )
        .unwrap();
        git_stdout(repo.path(), &["add", "unrelated.txt"]);
                                           
        std::fs::write(repo.path().join("consume-pins.toml"), "pin = \"new\"\n").unwrap();

        let msg = "pin(apks): re-pin — `linux-virt` 6.18.36-r0\u{2192}6.18.38-r0";
        ShellGit
            .commit(
                repo.path(),
                &[repo.path().join("consume-pins.toml")],
                msg,
                CommitOpts::default(),
            )
            .unwrap();

        let files = git_stdout(repo.path(), &["show", "--name-only", "--format=", "HEAD"]);
        assert!(files.contains("consume-pins.toml"), "{files}");
        assert!(
            !files.contains("unrelated.txt"),
            "the pre-staged unrelated file must NOT be swept into market's commit: {files}"
        );
                                                                                     
        let status = git_stdout(repo.path(), &["status", "--porcelain"]);
        assert!(status.contains("unrelated.txt"), "{status}");
                                                                                     
        let logged = git_stdout(repo.path(), &["log", "-1", "--format=%B"]);
        assert_eq!(logged.trim_end(), msg);
    }

                                                                                                
    /// directions are read from real git — a hook that exits 1 refuses the `false` call, and the
    /// `true` call commits over the same live hook. Measured on git 2.55.0.
    #[test]
    fn shell_git_runs_the_hosts_hooks_unless_no_verify_is_set() {
        use std::os::unix::fs::PermissionsExt as _;
        let repo = test_repo();
        let hook = repo.path().join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = repo.path().join("consume-pins.toml");

        std::fs::write(&target, "pin = \"one\"\n").unwrap();
        let err = ShellGit
            .commit(
                repo.path(),
                std::slice::from_ref(&target),
                "hooked",
                CommitOpts::default(),
            )
            .unwrap_err();
        assert!(
            matches!(&err, GitError::Command { op, .. } if *op == "commit"),
            "the hook's refusal surfaces as the commit step's error: {err}"
        );
        let head_before = git_stdout(repo.path(), &["rev-parse", "HEAD"]);

        ShellGit
            .commit(
                repo.path(),
                &[target],
                "unhooked",
                CommitOpts { no_verify: true },
            )
            .unwrap();
        assert_ne!(
            head_before,
            git_stdout(repo.path(), &["rev-parse", "HEAD"]),
            "the same commit lands once the hook is skipped"
        );
        let files = git_stdout(repo.path(), &["show", "--name-only", "--format=", "HEAD"]);
        assert!(files.contains("consume-pins.toml"), "{files}");
    }

    #[test]
    fn shell_git_fails_closed_outside_a_repo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x"), "y").unwrap();
        let err = ShellGit
            .commit(
                dir.path(),
                &[dir.path().join("x")],
                "msg",
                CommitOpts::default(),
            )
            .unwrap_err();
        assert!(matches!(err, GitError::Command { .. }), "{err}");
    }

                                           

    #[test]
    fn consent_matrix() {
        let no_prompt = || panic!("the prompt must not run on this branch");
                                                                          
        let f = UpgradeFlags {
            no_commit: true,
            commit: false,
            dry_run: false,
        };
        assert_eq!(consent_from(&f, true, no_prompt), Consent::PrintOnly);
                                                                                        
        let f = UpgradeFlags {
            dry_run: true,
            ..Default::default()
        };
        assert_eq!(consent_from(&f, true, no_prompt), Consent::PrintOnly);
                                                                       
        let f = UpgradeFlags {
            commit: true,
            ..Default::default()
        };
        assert_eq!(consent_from(&f, true, no_prompt), Consent::Commit);
        assert_eq!(consent_from(&f, false, no_prompt), Consent::Commit);
                                                                                    
        let f = UpgradeFlags {
            commit: true,
            no_commit: true,
            ..Default::default()
        };
        assert_eq!(consent_from(&f, true, no_prompt), Consent::PrintOnly);
                                                                                       
        let f = UpgradeFlags::default();
        assert_eq!(consent_from(&f, false, no_prompt), Consent::PrintOnly);
                                                      
        assert_eq!(consent_from(&f, true, || 'y'), Consent::Commit);
        assert_eq!(consent_from(&f, true, || 'Y'), Consent::Commit);
        assert_eq!(consent_from(&f, true, || 'e'), Consent::EditThenCommit);
        assert_eq!(consent_from(&f, true, || 'N'), Consent::PrintOnly);
        assert_eq!(consent_from(&f, true, || '\n'), Consent::PrintOnly);
        assert_eq!(consent_from(&f, true, || 'x'), Consent::PrintOnly);
    }

    #[test]
    fn compose_message_from_pins_not_report() {
                                                                                                
                                                                                                 
                                                                 
        let repo = test_repo();
        let lockdir = repo.path().join("crates/image-builder");
        std::fs::create_dir_all(&lockdir).unwrap();
        let old = "alpine_version = \"3.23\"\n\
             [[package]]\nname = \"haproxy\"\nversion = \"3.2.19-r0\"\nsha256 = \"aa\"\nsigning_key = \"k\"\n\
             [[build_input]]\nname = \"linux-virt\"\nversion = \"6.18.36-r0\"\nsha256 = \"bb\"\nsigning_key = \"k\"\n";
        std::fs::write(lockdir.join("pinned-apks.toml"), old).unwrap();
        git_stdout(repo.path(), &["add", "."]);
        git_stdout(repo.path(), &["commit", "-q", "-m", "old lock"]);
        let new = old
            .replace("6.18.36-r0", "6.18.38-r0")
            .replace("3.2.19-r0", "3.2.21-r0");
        std::fs::write(lockdir.join("pinned-apks.toml"), new).unwrap();

        let msg = compose_message(
            &super::super::market_upgrade::Target::Apks,
            repo.path(),
            &[repo.path().join("crates/image-builder/pinned-apks.toml")],
        );
        assert!(msg.starts_with("pin(apks):"), "leg-named subject: {msg}");
        assert!(
            msg.contains("linux-virt 6.18.36-r0\u{2192}6.18.38-r0"),
            "the build_input delta, from the pin file: {msg}"
        );
        assert!(
            msg.contains("haproxy 3.2.19-r0\u{2192}3.2.21-r0"),
            "the runtime delta too: {msg}"
        );
    }

    #[test]
    fn compose_message_degrades_to_basenames_fail_soft() {
                                                                                           
        let repo = test_repo();
        std::fs::write(repo.path().join("weird.bin"), b"\x00").unwrap();
        let msg = compose_message(
            &super::super::market_upgrade::Target::Apks,
            repo.path(),
            &[repo.path().join("weird.bin")],
        );
        assert!(msg.contains("weird.bin"), "{msg}");
    }

    #[test]
    fn edit_abort_is_none_never_a_default_commit() {
                                                  
        assert_eq!(edit_message_with(None, "initial"), EditOutcome::Aborted);
                                             
        assert_eq!(
            edit_message_with(Some(std::ffi::OsStr::new("false")), "initial"),
            EditOutcome::Aborted
        );
                                                                                 
        let empty_editor = editor_script("printf '' > \"$1\"\n");
        assert_eq!(
            edit_message_with(Some(empty_editor.as_os_str()), "initial"),
            EditOutcome::Aborted
        );
                                              
        let rewriter = editor_script("printf 'edited message' > \"$1\"\n");
        assert_eq!(
            edit_message_with(Some(rewriter.as_os_str()), "initial"),
            EditOutcome::Edited("edited message".to_string())
        );
    }

    /// A throwaway executable "editor": a shell script receiving the msgfile as $1.
    fn editor_script(body: &str) -> tempfile::TempPath {
        use std::os::unix::fs::PermissionsExt as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(format!("#!/bin/sh\n{body}").as_bytes())
            .unwrap();
        f.flush().unwrap();
        let path = f.into_temp_path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                                                                                                
                                                                                              
                                                                                              
                                                                                               
                                                                                                
                                                                     
        for _ in 0..100 {
            if std::process::Command::new(&path)
                .arg("/dev/null")
                .status()
                .is_ok()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        path
    }

    #[test]
    fn ready_command_reproduces_shell_git() {
        let cmd = render_ready_command(
            Path::new("/eco/orchard"),
            Path::new("/tmp/msg.txt"),
            &[PathBuf::from("/eco/orchard/consume-pins.toml")],
        );
        assert!(
            cmd.contains("git -C /eco/orchard add -- /eco/orchard/consume-pins.toml"),
            "{cmd}"
        );
        assert!(
            cmd.contains(
                "git -C /eco/orchard commit -F /tmp/msg.txt -- /eco/orchard/consume-pins.toml"
            ),
            "{cmd}"
        );
    }

    #[test]
    fn diff_stat_shows_unparsed_churn_and_is_fail_soft() {
        let repo = test_repo();
                                                                                             
                                                
        std::fs::write(repo.path().join("README"), "seed rewritten wholesale\n").unwrap();
        let stat = diff_stat(repo.path(), &[repo.path().join("README")]).expect("a stat");
        assert!(stat.contains("README"), "{stat}");
                                                
        assert_eq!(
            diff_stat(repo.path(), &[repo.path().join("missing-or-clean")]),
            None
        );
                                                          
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(diff_stat(dir.path(), &[dir.path().join("x")]), None);
    }
}
