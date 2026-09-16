                                                                                                  
//! every checkout shape — main, branch worktree, detached worktree — plus the reflogs-off and
//! post-gc states. Drives the REAL `watch_paths` (included from `build_watch_paths.rs`, the same
//! file `build.rs` includes). The independent oracle is the probe record (cookbook
                                                                                               
//! each arm: snapshot the candidate files, commit, diff, and assert the watch set intersects the
//! moved set (that intersection is what makes cargo rerun the script).
//!
//! The reflogs-off fixture sets `core.logAllRefUpdates=false` BEFORE its first commit and asserts
//! `logs/HEAD` does NOT exist — setting it later does not stop reflog writes, which would make
                                           

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

include!("../build_watch_paths.rs");

                                                                                                   

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@x")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@x")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    std::fs::create_dir_all(dir).expect("mkdir repo");
    git(dir, &["init", "-q", "-b", "main"]);
    commit(dir, "1");
}

fn commit(dir: &Path, content: &str) {
    std::fs::write(dir.join("f"), content).expect("write f");
    git(dir, &["add", "f"]);
    git(dir, &["commit", "-qm", "c"]);
}

/// Lexical `..`-collapse so the commondir-relative paths `watch_paths` emits compare against
/// independently constructed expectations (an assertion aid, not the oracle — the oracle is the
/// live moved-file diff below).
fn normalize(p: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::ParentDir if matches!(out.last(), Some(Component::Normal(_))) => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out.iter().collect()
}

fn normset(paths: &[PathBuf]) -> BTreeSet<PathBuf> {
    paths.iter().map(|p| normalize(p)).collect()
}

/// Content snapshot of candidate files (absent = None), keyed by normalized path.
fn snapshot(paths: &[PathBuf]) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    paths
        .iter()
        .map(|p| (normalize(p), std::fs::read(p).ok()))
        .collect()
}

/// The files whose content changed (or that appeared/vanished) between two snapshots.
fn moved(
    before: &[(PathBuf, Option<Vec<u8>>)],
    after: &[(PathBuf, Option<Vec<u8>>)],
) -> BTreeSet<PathBuf> {
    before
        .iter()
        .zip(after)
        .filter(|((p1, b), (p2, a))| {
            assert_eq!(p1, p2);
            b != a
        })
        .map(|((p, _), _)| p.clone())
        .collect()
}

/// Every candidate path a commit could plausibly move (the probe's candidate set) for a gitdir +
/// commondir + branch. The oracle diff runs over these.
fn candidates(gitdir: &Path, commondir: &Path, branch: Option<&str>) -> Vec<PathBuf> {
    let mut v = vec![
        gitdir.join("HEAD"),
        gitdir.join("logs/HEAD"),
        commondir.join("packed-refs"),
    ];
    if let Some(b) = branch {
        v.push(commondir.join("refs/heads").join(b));
    }
    v
}

fn assert_no_reflog_watched(ws: &[PathBuf]) {
    assert!(
        ws.iter().all(|p| !p.ends_with("logs/HEAD")),
        "logs/HEAD must never be in the watch set (absent under core.logAllRefUpdates=false): {ws:?}"
    );
}

/// The load-bearing property: at least one WATCHED file moved on the commit — that intersection
/// is what makes cargo rerun the build script and re-embed the sha.
fn assert_rerun_fires(ws: &[PathBuf], moved: &BTreeSet<PathBuf>) {
    let wsn = normset(ws);
    assert!(
        wsn.intersection(moved).next().is_some(),
        "no watched file moved on the commit — the rerun would not fire.\nwatched: {wsn:?}\nmoved: {moved:?}"
    );
}

                                                                                                   

#[test]
fn main_checkout_commit_lands_in_the_watch_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    let gitdir = repo.join(".git");

    let ws = watch_paths(&gitdir);
    assert_eq!(
        normset(&ws),
        normset(&[
            gitdir.join("HEAD"),
            gitdir.join("refs/heads/main"),
            gitdir.join("packed-refs"),
        ]),
        "designed watch set for a main checkout"
    );
    assert_no_reflog_watched(&ws);

    let cand = candidates(&gitdir, &gitdir, Some("main"));
    let before = snapshot(&cand);
    commit(&repo, "2");
    let m = moved(&before, &snapshot(&cand));
                                                                      
    assert!(
        m.contains(&normalize(&gitdir.join("refs/heads/main"))),
        "{m:?}"
    );
    assert_rerun_fires(&ws, &m);
}

#[test]
fn branch_worktree_commit_lands_in_the_watch_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    let wt = tmp.path().join("wt");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "wb",
            wt.to_str().expect("utf8"),
        ],
    );

    let dot_git = wt.join(".git");
    assert!(dot_git.is_file(), "a worktree's .git is a gitfile");
                                                                                        
    let gitdir = repo.join(".git/worktrees/wt");
    let commondir = repo.join(".git");

    let ws = watch_paths(&dot_git);
    assert_eq!(
        normset(&ws),
        normset(&[
            gitdir.join("HEAD"),
            commondir.join("refs/heads/wb"),
            commondir.join("packed-refs"),
        ]),
        "designed watch set for a branch worktree (ref + packed-refs live in the COMMON dir)"
    );
    assert_no_reflog_watched(&ws);

    let cand = candidates(&gitdir, &commondir, Some("wb"));
    let before = snapshot(&cand);
    commit(&wt, "2");
    let m = moved(&before, &snapshot(&cand));
                                                                                                     
                                                                  
    assert!(
        m.contains(&normalize(&commondir.join("refs/heads/wb"))),
        "{m:?}"
    );
    assert!(!m.contains(&normalize(&gitdir.join("HEAD"))), "{m:?}");
    assert_rerun_fires(&ws, &m);
}

#[test]
fn detached_worktree_commit_lands_in_the_watch_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    let det = tmp.path().join("det");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            det.to_str().expect("utf8"),
        ],
    );

    let dot_git = det.join(".git");
    let gitdir = repo.join(".git/worktrees/det");
    let commondir = repo.join(".git");

    let ws = watch_paths(&dot_git);
                                                          
    assert_eq!(
        normset(&ws),
        normset(&[gitdir.join("HEAD"), commondir.join("packed-refs")]),
        "designed watch set for a detached worktree"
    );
    assert_no_reflog_watched(&ws);

    let cand = candidates(&gitdir, &commondir, None);
    let before = snapshot(&cand);
    commit(&det, "2");
    let m = moved(&before, &snapshot(&cand));
                                                                    
    assert!(m.contains(&normalize(&gitdir.join("HEAD"))), "{m:?}");
    assert_rerun_fires(&ws, &m);
}

#[test]
fn reflogs_off_commit_lands_in_the_watch_set() {
                                                                                                  
                                                       
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "core.logAllRefUpdates", "false"]);
    commit(&repo, "1");
    let gitdir = repo.join(".git");
    assert!(
        !gitdir.join("logs/HEAD").exists(),
        "non-vacuity: the reflog must not exist in this fixture"
    );

    let ws = watch_paths(&gitdir);
    assert_no_reflog_watched(&ws);
    let cand = candidates(&gitdir, &gitdir, Some("main"));
    let before = snapshot(&cand);
    commit(&repo, "2");
    let m = moved(&before, &snapshot(&cand));
                                                                                                  
    assert_eq!(
        m,
        BTreeSet::from([normalize(&gitdir.join("refs/heads/main"))]),
        "reflogs-off commit moves exactly the branch ref"
    );
    assert_rerun_fires(&ws, &m);
}

#[test]
fn post_gc_commit_lands_in_the_watch_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    let gitdir = repo.join(".git");
    git(&repo, &["gc", "-q", "--prune=now"]);
    assert!(
        !gitdir.join("refs/heads/main").exists(),
        "non-vacuity: gc must pack the loose ref away"
    );

                                                                                                    
                                                                          
    let ws = watch_paths(&gitdir);
    assert!(
        normset(&ws).contains(&normalize(&gitdir.join("refs/heads/main"))),
        "the packed-away ref path stays watched: {ws:?}"
    );

    let cand = candidates(&gitdir, &gitdir, Some("main"));
    let before = snapshot(&cand);
    commit(&repo, "2");
    let m = moved(&before, &snapshot(&cand));
                                                                                     
    assert!(
        m.contains(&normalize(&gitdir.join("refs/heads/main"))),
        "{m:?}"
    );
    assert!(
        !m.contains(&normalize(&gitdir.join("packed-refs"))),
        "{m:?}"
    );
    assert_rerun_fires(&ws, &m);
}

#[test]
fn no_git_yields_an_empty_watch_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    assert!(watch_paths(&tmp.path().join("nope/.git")).is_empty());
}

                                                                                                   

/// A commit in a branch WORKTREE (the shape the pre-fix watch missed) re-embeds the sha on the
/// next `cargo build` with no `touch`. Uses a scratch crate whose build.rs includes the REAL
/// `build_watch_paths.rs`. Not in `make verify` (it runs cargo builds); run once at dev and
/// record the output (plan Task 2).
#[test]
#[ignore = "runs two cargo builds of a scratch crate; run once at dev, output recorded in the dev log"]
fn e2e_worktree_commit_reembeds_the_sha_without_touch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    init_repo(&repo);
                                                                                       
                                                                                                
                                                                                               
                                                                                                  
                                                                      
    git(&repo, &["pack-refs", "--all"]);
    let wt = tmp.path().join("wt");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "wb",
            wt.to_str().expect("utf8"),
        ],
    );

                                                                                              
                                                                             
    let krate = wt.join("krate");
    std::fs::create_dir_all(krate.join("src")).expect("mk crate");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("build_watch_paths.rs"),
        krate.join("build_watch_paths.rs"),
    )
    .expect("copy the real watch-path fn");
    std::fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n",
    )
    .expect("write manifest");
    std::fs::write(
        krate.join("build.rs"),
        r#"use std::path::Path;
use std::process::Command;
include!("build_watch_paths.rs");
fn main() {
    let sha = Command::new("git").args(["rev-parse", "HEAD"]).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=PROBE_SHA={sha}");
    for p in watch_paths(Path::new("../.git")) {
        println!("cargo:rerun-if-changed={}", p.display());
    }
}
"#,
    )
    .expect("write build.rs");
    std::fs::write(
        krate.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"PROBE_SHA\")); }\n",
    )
    .expect("write main.rs");

    let target = tmp.path().join("target");
    let run = |label: &str| -> String {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(&cargo)
            .current_dir(&krate)
            .env("CARGO_TARGET_DIR", &target)
            .args(["run", "-q"])
            .output()
            .expect("cargo run");
        assert!(
            out.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };

    let sha1 = run("build 1");
                                                                                  
    git(&wt, &["add", "-A"]);
    git(&wt, &["commit", "-qm", "move HEAD"]);
    let sha2 = run("build 2");
    let head = {
        let out = Command::new("git")
            .current_dir(&wt)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("rev-parse");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_ne!(sha1, sha2, "the embed must move with the commit");
    assert_eq!(sha2, head, "the re-embedded sha is the new HEAD");
}
