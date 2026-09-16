//! §3.3's divergence compare, driven at `prepare`. The window between classification and
//! construction has no actor the runner exposes (no git command in it fires a hook, and the
//! executor, prompt and editor seams all sit outside it), so the arms drive the construction entry
//! point directly: the test performs the worktree write BETWEEN the real `classify_and_witness` call
//! and the real `prepare` call, which is the production sequence with the window's actor supplied.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::super::records::DeclaredPathName;
use super::{ceremony_git, prepare};
use crate::ceremony::records::{
    ContentState, DirtClass, PathWitness, RunRecords, classify_and_witness, finalize_path_record,
    open_path_record,
};
use crate::ceremony::refusal::Refusal;

const DECLARED: &str = "vendor/x.tar.xz";

/// §1.6 belt: every command `ceremony_git` builds carries `GIT_NO_LAZY_FETCH=1`, so no git the run
/// spawns fetches from a promisor remote. Grounded (pF3_2, git 2.55.0): `GIT_NO_LAZY_FETCH=1`
/// makes `rev-parse HEAD^{tree}` / `read-tree HEAD` on a `tree:0` clone exit 128 with no fetch.
#[test]
fn ceremony_git_carries_the_no_lazy_fetch_belt() {
    let cmd = ceremony_git(Path::new("/tmp/x"));
    let set = cmd
        .get_envs()
        .any(|(k, v)| k == "GIT_NO_LAZY_FETCH" && v == Some("1".as_ref()));
    assert!(set, "ceremony_git does not set GIT_NO_LAZY_FETCH=1");
}

fn git(root: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// A real checkout with `DECLARED` committed, plus a records handle bound to it.
fn checkout(tmp: &Path, name: &str) -> (PathBuf, PathBuf, RunRecords) {
    let root = tmp.join(name);
    std::fs::create_dir_all(root.join("vendor")).expect("mk vendor");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "true"],
    ] {
        git(&root, &args);
    }
    std::fs::write(root.join(DECLARED), "committed\n").expect("w");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "baseline"]);
    let rec = RunRecords::open_dir(&tmp.join(format!("{name}.d")), "run-1")
        .expect("records")
        .with_checkout(&root);
    let path = root.join(DECLARED);
    (root, path, rec)
}

/// Record `bytes` at `path` as this run's write, then take the witness the gate's classification
/// would take. Panics unless the path classifies as this run's recorded content.
fn record_then_classify(rec: &mut RunRecords, path: &Path, bytes: &[u8]) -> PathWitness {
    let tok = open_path_record(rec, path).expect("open");
    std::fs::write(path, bytes).expect("this run's write");
    finalize_path_record(rec, tok).expect("finalize");
    let (class, witness) = classify_and_witness(rec, path);
    assert_eq!(
        class,
        DirtClass::CleanOrRecorded,
        "the fixture is not speakable"
    );
    witness.expect("a speakable class carries a witness")
}

/// Record an ABSENCE at `path` (the ceremony's write removed it) and take its witness.
fn record_removal_then_classify(rec: &mut RunRecords, path: &Path) -> PathWitness {
    let tok = open_path_record(rec, path).expect("open");
    std::fs::remove_file(path).expect("this run's removal");
    finalize_path_record(rec, tok).expect("finalize");
    let (class, witness) = classify_and_witness(rec, path);
    assert_eq!(
        class,
        DirtClass::CleanOrRecorded,
        "the fixture is not speakable"
    );
    let w = witness.expect("a speakable class carries a witness");
    assert_eq!(
        w.post,
        ContentState::Absent,
        "the witness is not a recorded absence"
    );
    w
}

fn owed_one() -> Vec<(DeclaredPathName, DirtClass)> {
    vec![(DeclaredPathName::new(DECLARED), DirtClass::CleanOrRecorded)]
}

fn witnesses_of(w: PathWitness) -> BTreeMap<DeclaredPathName, PathWitness> {
    BTreeMap::from([(DeclaredPathName::new(DECLARED), w)])
}

/// The refusal id `prepare` answered with, or a panic naming what it answered instead.
fn refusal_id(
    root: &Path,
    rec: &RunRecords,
    owed: &[(DeclaredPathName, DirtClass)],
    witnesses: &BTreeMap<DeclaredPathName, PathWitness>,
) -> String {
    match prepare(root, rec.dir(), rec, owed, witnesses) {
        Ok(_) => panic!("the construction accepted a diverged path"),
        Err(e) => e
            .downcast_ref::<Refusal>()
            .unwrap_or_else(|| panic!("expected a typed Refusal, got: {e}"))
            .id
            .token()
            .to_string(),
    }
}

                                                                                                
/// refuses" is total over `ContentState`. Four divergences are driven — new bytes, a mode-only flip,
/// a recorded absence that is present again, and a recorded presence that is gone — and each refuses
                                                                                                  
#[test]
fn every_divergence_between_classification_and_construction_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");

                                   
    let (root, path, mut rec) = checkout(tmp.path(), "bytes");
    let w = record_then_classify(&mut rec, &path, b"recorded\n");
    std::fs::write(&path, b"written in the window\n").expect("the window's write");
    assert_eq!(
        refusal_id(&root, &rec, &owed_one(), &witnesses_of(w)),
        "gate-content-moved",
        "new bytes in the window"
    );

                                                                                            
    let (root, path, mut rec) = checkout(tmp.path(), "mode");
    let w = record_then_classify(&mut rec, &path, b"recorded\n");
    match &w.post {
        ContentState::Sha256 { exec, .. } => {
            assert!(
                !exec,
                "the witness starts non-exec, so the flip is the only change"
            )
        }
        other => panic!("a regular file records a Sha256 post, got {other:?}"),
    }
    let mut perm = std::fs::metadata(&path).expect("stat").permissions();
    perm.set_mode(perm.mode() | 0o111);
    std::fs::set_permissions(&path, perm).expect("chmod +x");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        b"recorded\n",
        "arm sanity: the bytes did not change, only the mode"
    );
    assert_eq!(
        refusal_id(&root, &rec, &owed_one(), &witnesses_of(w)),
        "gate-content-moved",
        "a mode-only flip in the window"
    );

                                                                    
    let (root, path, mut rec) = checkout(tmp.path(), "back");
    let w = record_removal_then_classify(&mut rec, &path);
    std::fs::write(&path, b"restored in the window\n").expect("the window's write");
    assert_eq!(
        refusal_id(&root, &rec, &owed_one(), &witnesses_of(w)),
        "gate-content-moved",
        "a recorded absence present again"
    );

                                                            
    let (root, path, mut rec) = checkout(tmp.path(), "gone");
    let w = record_then_classify(&mut rec, &path, b"recorded\n");
    std::fs::remove_file(&path).expect("the window's removal");
    assert_eq!(
        refusal_id(&root, &rec, &owed_one(), &witnesses_of(w)),
        "gate-content-moved",
        "a recorded presence gone at construction"
    );
}

/// The compare's other direction: with NO write in the window the construction proceeds, so the four
/// refusals above are the divergence's doing and not a construction that always refuses. The
/// controls cover both `ContentState` variants.
#[test]
fn an_unchanged_path_constructs_its_tree() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let (root, path, mut rec) = checkout(tmp.path(), "clean-present");
    let w = record_then_classify(&mut rec, &path, b"recorded\n");
    prepare(&root, rec.dir(), &rec, &owed_one(), &witnesses_of(w))
        .expect("an unchanged present path constructs");

    let (root, path, mut rec) = checkout(tmp.path(), "clean-absent");
    let w = record_removal_then_classify(&mut rec, &path);
    prepare(&root, rec.dir(), &rec, &owed_one(), &witnesses_of(w))
        .expect("an unchanged recorded absence constructs");
}

/// delta v3.4 §1.3 / floor row A'2: the in-progress guard's own reading of a `--git-path` answer
/// outside UTF-8 is `git-state-unreadable`. Driven at `refuse_if_in_progress`, which is where the
/// reading lives: through the whole gate the §3.0 contract check refuses first over the same
/// fixture (`runner.rs` calls it before this guard), so this leg has no integration route.
///
/// What it claims: over a linked worktree whose MAIN repository path holds byte 0xFF, with a
/// `rebase-merge` marker planted, `refuse_if_in_progress` returns `git-state-unreadable` whose
/// detail names `rev-parse --git-path` and carries the escaped sample; and over an ASCII-pathed
/// main worktree with the same marker it returns `partial-commit-blocked`. What it does NOT claim:
/// anything about the order in which the gate reaches this guard. Blind spot, named: a linked
/// worktree is the only shape where `--git-path` answers an absolute path, so a main worktree
/// cannot drive the decode failure at all.
#[test]
fn the_in_progress_guard_refuses_a_non_utf8_git_path_answer() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    use super::refuse_if_in_progress;

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut nm = b"main".to_vec();
    nm.push(0xff);
    let main = tmp.path().join(PathBuf::from(OsString::from_vec(nm)));
    std::fs::create_dir_all(&main).expect("mk main");
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git(&main, &args);
    }
    std::fs::write(main.join("a.txt"), "a\n").expect("w");
    git(&main, &["add", "-A"]);
    git(&main, &["commit", "-qm", "baseline"]);
    git(&main, &["branch", "wt"]);
    let linked = tmp.path().join("linked");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            linked.to_str().expect("the linked path is utf8"),
            "wt",
        ],
    );
    let wt_git_dir = main.join(".git").join("worktrees").join("linked");
    std::fs::create_dir_all(wt_git_dir.join("rebase-merge")).expect("plant rebase-merge");

                                                                                                   
                                                                                          
    let answer = git(&linked, &["rev-parse", "--git-path", "rebase-merge"]);
    assert!(
        answer.contains('\u{fffd}'),
        "arm sanity: the --git-path answer carries no byte outside UTF-8: {answer:?}"
    );

    let refusal = refuse_if_in_progress(&linked).expect_err("a non-UTF-8 answer refuses");
    assert_eq!(
        refusal.id.token(),
        "git-state-unreadable",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("`git rev-parse --git-path` emitted bytes outside UTF-8")
            && refusal.detail.contains("\\xff"),
        "the detail does not name the --git-path read and its escaped sample: {}",
        refusal.detail
    );

                                                                                                
    let ascii = tmp.path().join("ascii");
    std::fs::create_dir_all(&ascii).expect("mk ascii");
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git(&ascii, &args);
    }
    std::fs::create_dir_all(ascii.join(".git/rebase-merge")).expect("plant rebase-merge");
    let control = refuse_if_in_progress(&ascii).expect_err("an in-progress marker refuses");
    assert_eq!(
        control.id.token(),
        "partial-commit-blocked",
        "{}",
        control.detail
    );
}
