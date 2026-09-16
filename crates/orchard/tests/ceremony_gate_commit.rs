//! R16 constructed-commit floor arms (design v3 §3.0-§3.11). Every arm drives `run_ceremony` over a
//! real checkout and reads its oracle from `git` itself.

#[path = "ceremony_gate_commit/fixture.rs"]
mod fixture;

use std::path::Path;

use fixture::*;
use orchard::ceremony::records::RunRecords;

/// The §3.0 cures, as hand literals. Deriving them from `RepoFormCondition::cure()` would compare
/// the mechanism against itself: a rotation of two arm bodies rotates both sides and passes
                                                     
const CURE_REPLACE_REFS: &str = "the ceremony does not commit onto replaced history; remove or \
     finish the replacement (`git replace -d <ref>`), then re-run";
const CURE_GRAFTS: &str = "remove the grafts file (git deprecates grafts; `git replace \
     --convert-graft-file` converts them, which this check also refuses), then re-run";
const CURE_SHALLOW: &str = "the ceremony refuses a shallow clone; unshallow it (`git fetch \
     --unshallow`), then re-run";

/// The §3.1 cures, as hand literals, same reason.
const CURE_MERGE: &str = "finish the merge (`git merge --continue`) or abort it (`git merge \
     --abort`), then re-run";
const CURE_CHERRY_PICK: &str = "finish the cherry-pick (`git cherry-pick --continue`) or abort it \
     (`git cherry-pick --abort` / `--quit`), then re-run";
const CURE_REVERT: &str = "finish the revert (`git revert --continue`) or abort it (`git revert \
     --abort` / `--quit`), then re-run";
const CURE_REBASE: &str = "finish the rebase (`git rebase --continue`) or abort it (`git rebase \
     --abort`), then re-run";
const CURE_AM: &str = "finish the am (`git am --continue`) or abort it (`git am --abort`), then \
     re-run";
const CURE_BISECT: &str = "end the bisect (`git bisect reset`), then re-run";

                                                                                                     

                                                                                                  
/// prompt, carrying its own condition's cure, with HEAD unmoved. The cures are hand literals, so a
/// rotation of two arm bodies reds the two legs that disagree.
#[test]
fn each_unmodelled_repository_form_refuses_before_the_prompt_with_its_own_cure() {
    type Break = fn(&Path);
    let replace_ref: Break = |root| {
                                                                      
        std::fs::write(root.join("replace-bait.txt"), "one\n").expect("w");
        git_out(root, &["add", "--", "replace-bait.txt"]);
        git_out(root, &["commit", "-qm", "c1"]);
        std::fs::write(root.join("replace-bait.txt"), "two\n").expect("w");
        git_out(root, &["commit", "-qam", "c2"]);
        let c1 = git_out(root, &["rev-parse", "HEAD~1"]);
        let c2 = git_out(root, &["rev-parse", "HEAD"]);
        git_out(root, &["replace", &c1, &c2]);
    };
    let grafts: Break = |root| {
        let head = git_out(root, &["rev-parse", "HEAD"]);
        std::fs::create_dir_all(root.join(".git/info")).expect("mk info");
        std::fs::write(root.join(".git/info/grafts"), format!("{head}\n")).expect("w");
    };
    let shallow: Break = |root| {
        std::fs::write(root.join(".git/shallow"), "").expect("w");
    };

    let cures = [CURE_REPLACE_REFS, CURE_GRAFTS, CURE_SHALLOW];
    assert_eq!(
        cures
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        cures.len(),
        "three git-asked conditions, three distinct routes"
    );
    for (label, cure, brk) in [
        ("replace ref", CURE_REPLACE_REFS, replace_ref),
        ("grafts file", CURE_GRAFTS, grafts),
        ("shallow clone", CURE_SHALLOW, shallow),
    ] {
        let (fx, mut records, admitted, i, profile) = gate_fixture();
        let owed = dirty_the_declared_pair(&fx, &mut records);
        brk(&fx.root);
        let head_before = git_head(&fx.root);
                                                                                                   
                                             
        assert_eq!(owed.len(), 2, "{label}: two declared paths are owed");
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "repository-form-unmodelled",
            "{label}: {}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            cure,
            "{label}: the cure is the one this condition selects"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{label}: HEAD moved under a §3.0 refusal"
        );
    }
}

/// §3.0's fail-closed edge: an unknown extension at `core.repositoryformatversion = 1` makes git
/// ignore the git dir, so the FIRST §3.0 read (`for-each-ref refs/replace/`) fails and the gate stops
/// with `git-state-unreadable` rather than reaching the typed condition. The arm re-measures git's own
/// answer at that read before asserting.
#[test]
fn an_unknown_extension_at_format_version_1_stops_fail_closed_at_the_first_read() {
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    let head_before = git_head(&fx.root);
    git_out(&fx.root, &["config", "core.repositoryformatversion", "1"]);
    git_out(&fx.root, &["config", "extensions.somefuture", "1"]);
                                                                            
    let (ok, _, stderr) = git_try(
        &fx.root,
        &[
            "--no-replace-objects",
            "for-each-ref",
            "--count=1",
            "--format=%(refname)",
            "refs/replace/",
        ],
    );
    assert!(!ok, "git accepted the ignored git dir");
    assert!(
        stderr.contains("unknown repository extension"),
        "git's own reason moved: {stderr}"
    );
    let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
    assert_eq!(run.refusal().id.token(), "git-state-unreadable");
                                                                           
    git_out(
        &fx.root,
        &[
            "config",
            "--file",
            ".git/config",
            "--unset",
            "extensions.somefuture",
        ],
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a refusal"
    );
}

/// §3.0's modelled set is not a blanket refusal: a `sha256` object format and a `reftable` ref
/// storage both pass every read and the gate commits. The sha256 leg also drives the `<zero-oid>`
/// length rule of §3.4 (the removal record's zero oid is as long as the repository's object id).
#[test]
fn a_modelled_object_format_and_ref_backend_pass_the_contract_check_and_commit() {
    for (label, init_extra) in [
        ("sha256 objects", vec!["--object-format=sha256"]),
        ("reftable refs", vec!["--ref-format=reftable"]),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_opts(&init_extra, |_| {});
        let owed = dirty_the_declared_pair(&fx, &mut records);
                                                                                           
        let ext = git_out(
            &fx.root,
            &["config", "--local", "--get-regexp", r"^extensions\."],
        );
        assert!(!ext.is_empty(), "{label}: no extension is set: [{ext}]");
        i.commit = true;
        let head_before = git_head(&fx.root);
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        run.outcome
            .unwrap_or_else(|e| panic!("{label}: the modelled form commits: {e}"));
        assert_ne!(git_head(&fx.root), head_before, "{label}: nothing landed");
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            owed,
            "{label}: the commit changed exactly the owed set"
        );
    }
}

                                                                                                     

/// Leave the checkout mid-merge. `--no-commit --no-ff` writes MERGE_HEAD and stages nothing.
fn start_a_merge(root: &Path) {
    git_out(root, &["checkout", "-q", "-b", "r16-side"]);
    git_out(
        root,
        &["commit", "-q", "--allow-empty", "-m", "a side commit"],
    );
    git_out(root, &["checkout", "-q", "-"]);
    git_out(root, &["merge", "--no-commit", "--no-ff", "r16-side"]);
}

/// A conflicting history at an UNDECLARED path, so the owed set stays exactly the declared pair.
/// Returns the side branch name.
fn conflicting_history(root: &Path) -> &'static str {
    std::fs::write(root.join("unrelated.txt"), "base\n").expect("w");
    git_out(root, &["add", "--", "unrelated.txt"]);
    git_out(root, &["commit", "-qm", "an unrelated baseline"]);
    git_out(root, &["checkout", "-q", "-b", "r16-side"]);
    std::fs::write(root.join("unrelated.txt"), "side\n").expect("w");
    git_out(root, &["commit", "-qam", "a side edit"]);
    git_out(root, &["checkout", "-q", "-"]);
    std::fs::write(root.join("unrelated.txt"), "mainline\n").expect("w");
    git_out(root, &["commit", "-qam", "a mainline edit"]);
    "r16-side"
}

/// Run a git command that MUST fail (the conflict is the fixture).
fn git_must_conflict(root: &Path, args: &[&str]) {
    let (ok, _, err) = git_try(root, args);
    assert!(
        !ok,
        "git {args:?} had to conflict to leave its marker: {err}"
    );
}

fn start_a_cherry_pick(root: &Path) {
    let side = conflicting_history(root);
    git_must_conflict(root, &["cherry-pick", side]);
}

fn start_a_revert(root: &Path) {
    conflicting_history(root);
                                                                                         
    git_must_conflict(root, &["revert", "--no-edit", "HEAD~1"]);
}

fn start_a_rebase_merge(root: &Path) {
    let side = conflicting_history(root);
    git_must_conflict(root, &["rebase", side]);
}

fn start_a_rebase_apply(root: &Path) {
    let side = conflicting_history(root);
    git_must_conflict(root, &["rebase", "--apply", side]);
}

fn start_an_am(root: &Path) {
    let side = conflicting_history(root);
    let patch = git_out(
        root,
        &["format-patch", "--stdout", &format!("HEAD..{side}")],
    );
    std::fs::write(root.join("../side.patch"), &patch).expect("w patch");
    git_must_conflict(root, &["am", "../side.patch"]);
}

fn start_a_bisect(root: &Path) {
    git_out(root, &["bisect", "start"]);
    git_out(root, &["bisect", "bad"]);
}

/// A multi-commit cherry-pick whose conflict the operator resolved with a plain `git commit`:
/// CHERRY_PICK_HEAD is gone, the sequencer todo is not. §3.1's `sequencer` predicate is the only one
/// that fires (measured, git 2.55.0).
fn leave_a_sequencer_todo(root: &Path) {
    std::fs::write(root.join("unrelated.txt"), "base\n").expect("w");
    git_out(root, &["add", "--", "unrelated.txt"]);
    git_out(root, &["commit", "-qm", "an unrelated baseline"]);
    git_out(root, &["checkout", "-q", "-b", "r16-side"]);
    for (n, body) in [(1, "side one\n"), (2, "side two\n")] {
        std::fs::write(root.join("unrelated.txt"), body).expect("w");
        git_out(root, &["commit", "-qam", &format!("side {n}")]);
    }
    git_out(root, &["checkout", "-q", "-"]);
    std::fs::write(root.join("unrelated.txt"), "mainline\n").expect("w");
    git_out(root, &["commit", "-qam", "a mainline edit"]);
    git_must_conflict(root, &["cherry-pick", "r16-side~1", "r16-side"]);
                                                                                                    
                                                 
    std::fs::write(root.join("unrelated.txt"), "resolved\n").expect("w");
    git_out(root, &["add", "--", "unrelated.txt"]);
    git_out(root, &["commit", "-qm", "resolved by hand"]);
}

                                                                                                
/// before the prompt, with the cure the detected OPERATION selects and HEAD unmoved. The `sequencer`
/// leg is the state no pseudo-ref covers. Arm sanity per leg reads git's own marker (the file at
/// `--git-path`, or the pseudo-ref through `rev-parse --verify`), so a leg whose fixture stopped
/// producing its state fails loudly instead of passing on another leg's marker.
#[test]
fn every_in_progress_marker_refuses_the_partial_commit_before_the_prompt() {
    type Start = fn(&Path);
    let cures = [
        CURE_MERGE,
        CURE_CHERRY_PICK,
        CURE_REVERT,
        CURE_REBASE,
        CURE_AM,
        CURE_BISECT,
    ];
    assert_eq!(
        cures
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        cures.len(),
        "six operations, six distinct routes"
    );
    for (label, op_label, cure, marker, start) in [
        (
            "merge",
            "merge",
            CURE_MERGE,
            "MERGE_HEAD",
            start_a_merge as Start,
        ),
        (
            "cherry-pick",
            "cherry-pick",
            CURE_CHERRY_PICK,
            "CHERRY_PICK_HEAD",
            start_a_cherry_pick as Start,
        ),
        (
            "revert",
            "revert",
            CURE_REVERT,
            "REVERT_HEAD",
            start_a_revert as Start,
        ),
        (
            "rebase (merge backend)",
            "rebase",
            CURE_REBASE,
            "rebase-merge",
            start_a_rebase_merge as Start,
        ),
        (
            "rebase (apply backend)",
            "rebase",
            CURE_REBASE,
            "rebase-apply",
            start_a_rebase_apply as Start,
        ),
        (
            "am",
            "am",
            CURE_AM,
            "rebase-apply/applying",
            start_an_am as Start,
        ),
        (
            "bisect",
            "bisect",
            CURE_BISECT,
            "BISECT_LOG",
            start_a_bisect as Start,
        ),
        (
            "sequencer alone",
            "cherry-pick",
            CURE_CHERRY_PICK,
            "sequencer",
            leave_a_sequencer_todo as Start,
        ),
    ] {
        let (fx, mut records, admitted, i, profile) = gate_fixture_with(start);
        let owed = dirty_the_declared_pair(&fx, &mut records);
                                                                                        
        let path = fx
            .root
            .join(git_out(&fx.root, &["rev-parse", "--git-path", marker]));
        let (ref_ok, _, _) = git_try(&fx.root, &["rev-parse", "--verify", "--quiet", marker]);
        assert!(
            path.exists() || ref_ok,
            "{label}: git left no {marker} (path {})",
            path.display()
        );
        assert_eq!(owed.len(), 2, "{label}: the declared pair is owed");
        let head_before = git_head(&fx.root);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "partial-commit-blocked",
            "{label}: {}",
            refusal.detail
        );
        assert!(
            refusal
                .detail
                .contains(&format!("a git {op_label} is in progress")),
            "{label}: the detail names the operation it read: {}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            cure,
            "{label}: the cure is the one this operation selects"
        );
        assert_eq!(git_head(&fx.root), head_before, "{label}: HEAD moved");
    }
}

/// §3.1's other direction: a marker git LEFT BEHIND after the operation ended produces no refusal.
/// Three measured states (`bisect reset`, `am --abort`, a clean `cherry-pick --no-commit` of two
/// commits) reach the commit and land it, so the guard is not a blanket refusal on the marker
/// directory's existence.
#[test]
fn a_lingering_marker_from_a_finished_operation_never_refuses() {
    type Start = fn(&Path);
    let after_bisect: Start = |root| {
        start_a_bisect(root);
        git_out(root, &["bisect", "reset"]);
    };
    let after_am: Start = |root| {
        start_an_am(root);
        git_out(root, &["am", "--abort"]);
    };
    let clean_pick: Start = |root| {
                                                                                                
        std::fs::write(root.join("unrelated.txt"), "base\n").expect("w");
        git_out(root, &["add", "--", "unrelated.txt"]);
        git_out(root, &["commit", "-qm", "an unrelated baseline"]);
        git_out(root, &["checkout", "-q", "-b", "r16-side"]);
        for (n, name) in [(1, "s1.txt"), (2, "s2.txt")] {
            std::fs::write(root.join(name), "side\n").expect("w");
            git_out(root, &["add", "--", name]);
            git_out(root, &["commit", "-qm", &format!("side {n}")]);
        }
        git_out(root, &["checkout", "-q", "-"]);
        git_out(
            root,
            &["cherry-pick", "--no-commit", "r16-side~1", "r16-side"],
        );
                                                                                                
        git_out(root, &["reset", "-q", "HEAD"]);
        std::fs::remove_file(root.join("s1.txt")).expect("rm");
        std::fs::remove_file(root.join("s2.txt")).expect("rm");
    };

    for (label, start) in [
        ("after bisect reset", after_bisect),
        ("after am --abort", after_am),
        ("after a clean cherry-pick --no-commit", clean_pick),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(start);
        let owed = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        run.outcome.unwrap_or_else(|e| {
            panic!("{label}: a finished operation's leftovers must not refuse: {e}")
        });
        assert_ne!(git_head(&fx.root), head_before, "{label}: nothing landed");
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            owed,
            "{label}: the commit changed exactly the owed set"
        );
    }
}

/// §3.1 under the reftable backend: `CHERRY_PICK_HEAD` exists as a REF with no file at
/// `--git-path`, so the pseudo-ref predicate is the only one that can see it. Arm sanity asserts
/// both halves of that state before the property.
#[test]
fn a_reftable_pseudo_ref_marker_refuses_though_no_file_exists_at_its_git_path() {
    let (fx, mut records, admitted, i, profile) =
        gate_fixture_opts(&["--ref-format=reftable"], start_a_cherry_pick);
    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2);
                                                                                              
    let path = fx.root.join(git_out(
        &fx.root,
        &["rev-parse", "--git-path", "CHERRY_PICK_HEAD"],
    ));
    assert!(
        !path.exists(),
        "under reftable no file should back CHERRY_PICK_HEAD: {}",
        path.display()
    );
    let (ref_ok, _, _) = git_try(
        &fx.root,
        &["rev-parse", "--verify", "--quiet", "CHERRY_PICK_HEAD"],
    );
    assert!(ref_ok, "the reftable backend holds no CHERRY_PICK_HEAD ref");
    let head_before = git_head(&fx.root);
    let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
    assert_eq!(run.refusal().id.token(), "partial-commit-blocked");
    assert_eq!(git_head(&fx.root), head_before, "HEAD moved");
}

                                                                                                     

/// §3.4b: a construction record git DROPS never passes as landed. `vendor/.git.` is a name git's
/// `verify_path` rejects under `core.protectNTFS` (default 1 at 2.55.0): `update-index --index-info`
/// prints `Ignoring path` on stderr and exits 0, so without the presence check the gate would commit
/// a tree missing the declared path and report success. Arm sanity measures git's own drop first.
#[test]
fn a_record_git_drops_from_the_constructed_tree_refuses_naming_the_path() {
    const DROPPED: &str = "vendor/.git.";
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    record_write(&fx, &mut records, DROPPED, BYTES, false);
                                                                                               
    let status = git_out(
        &fx.root,
        &["status", "--porcelain", "--untracked-files=all"],
    );
    assert!(
        status.contains(DROPPED),
        "git does not report {DROPPED}: {status}"
    );
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "gate-record-dropped",
        "{}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains(DROPPED),
        "the refusal names the dropped path: {}",
        refusal.detail
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a refusal"
    );
}

                                                                                                     

/// §3.4c: writing a blob at a path that collides with a HEAD entry the dirt scan did not report
/// changes a path outside the owed set, and the containment check refuses pre-prompt. Both collision
/// directions are driven: HEAD holds a BLOB where the owed path needs a directory, and HEAD holds a
/// TREE where the owed path needs a file. `--assume-unchanged` is what hides the colliding entry
/// from `git status` (the cure's own condition). Arm sanity reads the changed set from git.
#[test]
fn a_tree_delta_outside_the_owed_set_refuses_before_the_prompt() {
    type Setup = fn(&Path);
    let blob_where_dir_is_needed: Setup = |root| {
        std::fs::write(root.join("vendor"), "a blob at vendor\n").expect("w");
        git_out(root, &["add", "--", "vendor"]);
        git_out(root, &["commit", "-qm", "vendor as a blob"]);
        git_out(root, &["update-index", "--assume-unchanged", "vendor"]);
        std::fs::remove_file(root.join("vendor")).expect("rm");
        std::fs::create_dir(root.join("vendor")).expect("mkdir");
    };
    let tree_where_file_is_needed: Setup = |root| {
        std::fs::create_dir_all(root.join(VENDORED)).expect("mkdir");
        std::fs::write(root.join(VENDORED).join("inner"), "inner\n").expect("w");
        git_out(root, &["add", "-A"]);
        git_out(root, &["commit", "-qm", "a tree at the owed path"]);
        git_out(
            root,
            &[
                "update-index",
                "--assume-unchanged",
                &format!("{VENDORED}/inner"),
            ],
        );
        std::fs::remove_dir_all(root.join(VENDORED)).expect("rm -r");
    };

    for (label, extra, setup) in [
        (
            "HEAD holds a blob at `vendor`",
            "vendor",
            blob_where_dir_is_needed,
        ),
        (
            "HEAD holds a tree at the owed path",
            "vendor/x.tar.xz/inner",
            tree_where_file_is_needed,
        ),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(setup);
        record_write(&fx, &mut records, VENDORED, BYTES, false);
                                                                                                
        assert_eq!(
            declared_dirt(&fx.root),
            vec![VENDORED.to_string()],
            "{label}: the hidden collision leaked into the dirt scan"
        );
        i.commit = true;
        let head_before = git_head(&fx.root);
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "gate-tree-delta-exceeds-owed",
            "{label}: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains(extra),
            "{label}: the refusal names the extra path: {}",
            refusal.detail
        );
        assert_eq!(git_head(&fx.root), head_before, "{label}: HEAD moved");
    }
}

/// §3.4c's other direction: an owed set MIXING a path whose recorded state already equals its
/// committed state with one that differs proceeds, and the landed commit changes exactly the
/// differing path. The containment check is a bound, not a requirement that C equal the owed set.
#[test]
fn a_mixed_owed_set_commits_exactly_the_paths_whose_content_differs_from_head() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
                                                                                                   
                                        
    let tracked = fx.at(TRACKED);
    let head_bytes = git_out(&fx.root, &["show", &format!("HEAD:{TRACKED}")]);
    std::fs::write(&tracked, "a staged edit\n").expect("staged edit");
    git_out(&fx.root, &["add", "--", TRACKED]);
    record_write(
        &fx,
        &mut records,
        TRACKED,
        format!("{head_bytes}\n").as_bytes(),
        false,
    );
    record_write(&fx, &mut records, VENDORED, BYTES, false);
                                                                                        
    assert!(
        git_out(&fx.root, &["status", "--porcelain", "--", TRACKED]).contains(TRACKED),
        "the tracked path is owed dirt"
    );
    assert_eq!(
        git_out(&fx.root, &["diff", "HEAD", "--name-only", "--", TRACKED]),
        "",
        "and it lands nothing against HEAD"
    );
    i.commit = true;
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    run.outcome
        .unwrap_or_else(|e| panic!("a mixed owed set commits: {e}"));
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        vec![VENDORED.to_string()],
        "the commit changed exactly the path whose content differs from HEAD"
    );
}

                                                                                                     

                                                                                                      
/// stops with `commit-preview-empty` before the prompt, and the cure NAMES BOTH conditions of the
/// stop (already-committed, and a content filter re-dirtying a declared path) plus the settle route.
/// The second condition is driven too: a `clean` filter configured on the declared path re-dirties
/// it on the run after the bytes landed, which is the state that reaches this stop in production.
#[test]
fn an_owed_set_that_lands_nothing_stops_with_both_conditions_named() {
    const CURE: &str = "no owed declared path holds a change against HEAD for the ceremony to \
         commit: either every owed path's recorded state already equals its committed state, or a \
         content filter configured on a declared path re-dirties it after the first ceremony \
         commit; settle or commit any staged-only edits yourself, then re-run";

                                                                       
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let head_bytes = git_out(&fx.root, &["show", &format!("HEAD:{TRACKED}")]);
    std::fs::write(fx.at(TRACKED), "a staged edit\n").expect("staged edit");
    git_out(&fx.root, &["add", "--", TRACKED]);
    record_write(
        &fx,
        &mut records,
        TRACKED,
        format!("{head_bytes}\n").as_bytes(),
        false,
    );
    let head_before = git_head(&fx.root);
    let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "commit-preview-empty",
        "{}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        CURE,
        "the cure names both conditions and the settle route"
    );
    assert_eq!(git_head(&fx.root), head_before, "HEAD moved under a stop");

                                                                                                  
                                                                                                  
                                                                          
    let (fx2, mut records2, admitted2, mut i2, profile2) = gate_fixture_with(|root| {
        std::fs::write(
            root.join(".gitattributes"),
            format!("{VENDORED} filter=strip\n"),
        )
        .expect("w");
        git_out(root, &["add", "--", ".gitattributes"]);
        git_out(root, &["commit", "-qm", "a filter on the declared path"]);
        git_out(root, &["config", "filter.strip.clean", "sed '/^MARKER$/d'"]);
    });
    record_write(&fx2, &mut records2, VENDORED, b"payload\nMARKER\n", false);
    i2.commit = true;
                                     
    let first = run_gate_headless(&fx2, &mut records2, &admitted2, &i2, &profile2);
    first
        .outcome
        .unwrap_or_else(|e| panic!("the first run commits the recorded bytes: {e}"));
    assert_eq!(
        git_out(
            &fx2.root,
            &["cat-file", "blob", &format!("HEAD:{VENDORED}")]
        ),
        "payload\nMARKER",
        "the landed bytes are the RECORDED bytes, the clean filter notwithstanding"
    );
                                                                                                
    let (_fx3, records3, admitted3, i3, profile3) = (
        &fx2,
        RunRecords::open_dir(&fx2.at("boxes/alpha.d"), "run-2").expect("records"),
        admitted2,
        i2,
        profile2,
    );
    let mut records3 = records3.with_checkout(&fx2.root);
    record_write(&fx2, &mut records3, VENDORED, b"payload\nMARKER\n", false);
    assert!(
        git_out(&fx2.root, &["status", "--porcelain", "--", VENDORED]).contains(VENDORED),
        "arm sanity: the filter keeps the declared path dirty on the second run"
    );
    let head2 = git_head(&fx2.root);
    let second = run_gate_headless(&fx2, &mut records3, &admitted3, &i3, &profile3);
    let refusal2 = second.refusal();
    assert_eq!(
        refusal2.id.token(),
        "commit-preview-empty",
        "the filter's perpetual dirt reaches the §3.5 stop: {}",
        refusal2.detail
    );
    assert_eq!(
        git_head(&fx2.root),
        head2,
        "the second run committed anyway"
    );
}

                                                                                                     

/// Configure ssh commit signing in the fixture and return nothing; the private key sits beside the
/// public one, which is what `-S` needs.
fn configure_ssh_signing(root: &Path, key_dir: &Path) {
    let key = key_dir.join("sign-key");
    let out = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "t@t", "-f"])
        .arg(&key)
        .output()
        .expect("ssh-keygen must be on PATH for the signing arm to mean anything");
    assert!(
        out.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    git_out(root, &["config", "gpg.format", "ssh"]);
    git_out(
        root,
        &[
            "config",
            "user.signingkey",
            &format!("{}.pub", key.display()),
        ],
    );
}

                                                                                                     
/// to `commit-tree`, and the LANDED commit carries a signature (read from git's own object header, so
/// the oracle is git and not the flag the code passed). A malformed value and a signing failure both
/// refuse with HEAD unmoved.
#[test]
fn the_signing_read_signs_the_landed_commit_and_both_failure_shapes_refuse() {
                                                     
    let keys = tempfile::tempdir().expect("keydir");
    let keydir = keys.path().to_path_buf();
    let (fx, mut records, admitted, mut i, profile) =
        gate_fixture_with(move |root| configure_ssh_signing(root, &keydir));
    let owed = dirty_the_declared_pair(&fx, &mut records);
    git_out(&fx.root, &["config", "commit.gpgSign", "true"]);
    i.commit = true;
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    run.outcome
        .unwrap_or_else(|e| panic!("a signed gate commit lands: {e}"));
    let header = git_out(&fx.root, &["cat-file", "commit", "HEAD"]);
    assert!(
        header.contains("gpgsig -----BEGIN SSH SIGNATURE-----"),
        "the landed commit carries no signature:\n{header}"
    );
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "the signed commit changed exactly the owed set"
    );

                                                                                               
    let (fx2, mut records2, admitted2, mut i2, profile2) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx2, &mut records2);
    git_out(&fx2.root, &["config", "commit.gpgSign", "notabool"]);
    let (ok, _, stderr) = git_try(
        &fx2.root,
        &["config", "--type=bool", "--default=false", "commit.gpgSign"],
    );
    assert!(!ok, "arm sanity: git accepted the malformed boolean");
    assert!(
        stderr.contains("bad boolean config value"),
        "git's own reason moved: {stderr}"
    );
    i2.commit = true;
    let head2 = git_head(&fx2.root);
    let run2 = run_gate_headless(&fx2, &mut records2, &admitted2, &i2, &profile2);
    let refusal2 = run2.refusal();
    assert_eq!(
        refusal2.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal2.detail
    );
    assert!(
        refusal2.detail.contains("commit.gpgSign is malformed"),
        "the refusal names the read that failed: {}",
        refusal2.detail
    );
    assert_eq!(
        git_head(&fx2.root),
        head2,
        "HEAD moved on a malformed value"
    );

                                                                                                   
    let (fx3, mut records3, admitted3, mut i3, profile3) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx3, &mut records3);
    git_out(&fx3.root, &["config", "gpg.format", "ssh"]);
    git_out(
        &fx3.root,
        &["config", "user.signingkey", "/nonexistent.pub"],
    );
    git_out(&fx3.root, &["config", "commit.gpgSign", "true"]);
    i3.commit = true;
    let head3 = git_head(&fx3.root);
    let run3 = run_gate_headless(&fx3, &mut records3, &admitted3, &i3, &profile3);
    let refusal3 = run3.refusal();
    assert_eq!(
        refusal3.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal3.detail
    );
    assert!(
        refusal3.detail.contains("commit-tree"),
        "the refusal names the stage that failed: {}",
        refusal3.detail
    );
    assert_eq!(
        git_head(&fx3.root),
        head3,
        "HEAD moved on a signing failure"
    );
}

                                                                                                     

/// §3.8 step 3: a branch move inside the consent window makes the gate's `update-ref` compare-and-
/// swap refuse, and NOTHING of the gate lands: HEAD is the operator's own commit, and no commit whose
/// message is the ceremony's exists. Driven at a terminal, where the operator's `y` is what opens the
/// window; the mover runs inside the prompt closure, which is the window itself.
#[test]
fn a_branch_move_inside_the_consent_window_refuses_and_lands_nothing() {
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    let root = fx.root.clone();
    let prompt = move || {
        git_out(
            &root,
            &[
                "commit",
                "--allow-empty",
                "-qm",
                "an operator commit inside the consent window",
            ],
        );
        'y'
    };
    let run = run_gate(&fx, &mut records, &admitted, &i, &profile, true, &prompt);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    let now = git_head(&fx.root);
    assert!(
        refusal.detail.contains("but expected"),
        "the detail carries git's own compare-and-swap line: {}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains(&format!("HEAD is now at {now}")),
        "the detail states the computed HEAD state (moved): {}",
        refusal.detail
    );
    assert!(
        refusal
            .cure()
            .as_str()
            .contains("another git operation advanced HEAD")
            && refusal.cure().as_str().contains(&now),
        "the Moved cure names the new HEAD id: {}",
        refusal.cure().as_str()
    );
    assert_eq!(
        git_log_message(&fx.root, "HEAD").trim(),
        "an operator commit inside the consent window",
        "HEAD is the mover's commit"
    );
    assert!(
        !git_out(&fx.root, &["log", "--format=%s", "--all"]).contains("ceremony("),
        "a ceremony commit landed under a refused compare-and-swap"
    );
}

                                                                                                     

/// A `post-index-change` hook that amends HEAD ONCE, on the first REAL-index write after the fixture
/// arms it. `GIT_INDEX_FILE` unset is what separates a real-index write from §3.4's three temp-index
/// firings (measured: the construction fires `1 0`, `0 1`, `0 0` with it set); the arming file is what
/// separates the run's own writes from the fixture's `git add` (which is also a real-index write).
const AMEND_AT_SETTLE: &str = "[ -n \"${GIT_INDEX_FILE:-}\" ] && exit 0\n\
     [ -e .git/hook-armed ] || exit 0\n\
     [ -e .git/amended ] && exit 0\n\
     : > .git/amended\n\
     git commit --amend --no-verify -q -m 'amended by the settle hook'\n\
     exit 0\n";

/// §3.8 steps 4-5: the settle runs BEFORE the identity read, so a `post-index-change` hook that moves
/// HEAD at the settle is caught. The hook is guarded on `GIT_INDEX_FILE` being unset, so it acts on
/// REAL-index writes only and never on §3.4's three temp-index firings (measured: the construction
/// fires `1 0`, `0 1`, `0 0` with `GIT_INDEX_FILE` set; the settle fires `0 1` with it unset).
#[test]
fn a_post_index_change_amend_at_the_settle_fails_the_identity_read() {
    let (fx, mut records, admitted, mut i, profile) =
        gate_fixture_with(|root| install_hook(root, "post-index-change", AMEND_AT_SETTLE));
    let _ = dirty_the_declared_pair(&fx, &mut records);
    arm_hook(&fx.root);
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-verify-failed",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("does not equal the constructed commit"),
        "the refusal names the identity compare: {}",
        refusal.detail
    );
                                                                                               
    assert!(
        fx.root.join(".git/amended").exists(),
        "the hook never fired, so this arm measured nothing"
    );
    assert_eq!(
        git_log_message(&fx.root, "HEAD").trim(),
        "amended by the settle hook",
        "HEAD is the hook's commit"
    );
    assert_ne!(git_head(&fx.root), head_before, "the hook amended nothing");
}

/// §3.8's exit table, the settle-failure row: an operator-held `index.lock` fails the settle while
/// every read of the gate still answers (measured: `status --no-optional-locks`, `ls-files`,
/// `rev-parse`, `ls-tree` and a `GIT_INDEX_FILE` `read-tree` all exit 0 with the lock held). The
/// commit LANDS, the identity read verifies it, and the typed settle condition reports the index the
/// operator still has to settle.
#[test]
fn an_operator_held_index_lock_lands_the_commit_and_reports_the_settle_condition() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    std::fs::write(fx.at(".git/index.lock"), "").expect("hold the lock");
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "gate-settle-failed",
        "{}",
        refusal.detail
    );
                                                           
    assert_ne!(git_head(&fx.root), head_before, "nothing landed");
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "the landed commit changed exactly the owed set"
    );
    assert!(
        refusal.detail.contains("the identity read verified it"),
        "the condition states the commit is verified: {}",
        refusal.detail
    );
                                                                                        
    assert_eq!(
        git_out(&fx.root, &["ls-files", "--", VENDORED]),
        "",
        "the settle wrote the index anyway"
    );
    for p in &owed {
        assert!(
            refusal.cure().as_str().contains(p),
            "the cure names the owed path {p} to restore: {}",
            refusal.cure().as_str()
        );
    }
    std::fs::remove_file(fx.at(".git/index.lock")).expect("release the lock");
}

                                                                                                     

/// A `post-index-change` hook whose amend latch is ARMED BY THE SETTLE and fires on the next
                                                                                                     
/// `write-tree` fires `0 0` inside the construction). `GIT_INDEX_FILE` unset selects real-index
/// writes; `.git/hook-armed` excludes the fixture's own `git add`.
const AMEND_AFTER_THE_GATE: &str = "[ -n \"${GIT_INDEX_FILE:-}\" ] && exit 0\n\
     [ -e .git/hook-armed ] || exit 0\n\
     if [ -e .git/settle-seen ]; then\n\
     [ -e .git/amended ] && exit 0\n\
     : > .git/amended\n\
     git commit --amend --no-verify -q -m 'amended after the gate returned'\n\
     else\n\
     : > .git/settle-seen\n\
     fi\n\
     exit 0\n";

/// §3.9 P-LAST at the run level: after the gate's identity read, no git command the RUN issues
/// refreshes or writes the index, so HEAD at run end is still the gate's own commit. The latch is
/// armed by the settle and would amend on the next real-index write; the arm proves the latch is live
/// by driving one plain `git status` after the assertion and watching it trip.
#[test]
fn no_git_read_after_the_gates_identity_read_writes_the_index_in_the_run() {
    let (fx, mut records, admitted, mut i, profile) =
        gate_fixture_with(|root| install_hook(root, "post-index-change", AMEND_AFTER_THE_GATE));
    let owed = dirty_the_declared_pair(&fx, &mut records);
    arm_hook(&fx.root);
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    run.outcome
        .unwrap_or_else(|e| panic!("the gate commits and the run completes: {e}"));
    let landed = git_head(&fx.root);
    assert_ne!(landed, head_before, "nothing landed");
    assert!(
        git_log_message(&fx.root, "HEAD").starts_with("ceremony("),
        "HEAD is not the gate's commit: {}",
        git_log_message(&fx.root, "HEAD")
    );
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "the landed commit changed exactly the owed set"
    );
                                                                                 
    assert!(
        fx.at(".git/settle-seen").exists(),
        "the settle never fired the hook, so the latch is not armed and this arm is vacuous"
    );
    assert!(
        !fx.at(".git/amended").exists(),
        "a git command the run issued after the identity read wrote the index"
    );

                                                                                                  
    let _ = git_out(&fx.root, &["status", "--porcelain"]);
    assert!(
        fx.at(".git/amended").exists(),
        "the latch never trips, so the assertion above proves nothing"
    );
    assert_ne!(
        git_head(&fx.root),
        landed,
        "the latch fired without moving HEAD"
    );
}

/// §3.9 (ii): every step child's environment carries the `GIT_OPTIONAL_LOCKS=0` pair, so a `git` a
/// child or its descendants spawn does not refresh the index. Asserted over every `ChildCall` a real
/// run produced, not over one composed call.
#[test]
fn every_executed_steps_child_call_carries_the_optional_locks_pair() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    run.outcome
        .unwrap_or_else(|e| panic!("the run completes so its steps really executed: {e}"));
    assert!(
        !run.calls.is_empty(),
        "the run spawned no child, so this arm measured nothing"
    );
    for call in &run.calls {
        assert!(
            call.env
                .iter()
                .any(|(k, v)| k == "GIT_OPTIONAL_LOCKS" && v == "0"),
            "step {:?} child env carries no GIT_OPTIONAL_LOCKS=0: {:?}",
            call.step,
            call.env
        );
                                                                                                     
                           
        assert!(
            call.env
                .iter()
                .any(|(k, v)| k == "GIT_NO_LAZY_FETCH" && v == "1"),
            "step {:?} child env carries no GIT_NO_LAZY_FETCH=1: {:?}",
            call.step,
            call.env
        );
    }
}

/// §3.9's `diff_stat` row: `git diff` refreshes and WRITES the index under `diff.autoRefreshIndex`
                                                                                
/// `diff_stat` read passes `-c diff.autoRefreshIndex=false`, so it fires no `post-index-change`. The
/// fixture holds an index with ZEROED stat data (what a gate settle leaves), which is the state a
/// refresh rewrites; the arm then drives a bare `git diff --stat` and a `GIT_OPTIONAL_LOCKS=0` one to
/// show both DO fire, so the suppression is the config flag's and not the fixture's.
#[test]
fn the_s6_diff_stat_read_never_refreshes_the_index() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).expect("mk root");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(&root, &args);
    }
    std::fs::write(root.join("consume-pins.toml"), "pin = 1\n").expect("w");
    git_out(&root, &["add", "-A"]);
    git_out(&root, &["commit", "-qm", "base"]);
    install_hook(
        &root,
        "post-index-change",
        "echo \"$1 $2\" >> .git/pic.log\nexit 0\n",
    );
    /// Zero the index entry's stat data the way a gate settle does, then take the hook log.
    fn settle_and_clear(root: &Path) {
        let blob = git_out(root, &["hash-object", "-w", "consume-pins.toml"]);
        let mut child = std::process::Command::new("git")
            .current_dir(root)
            .args(["update-index", "-z", "--index-info"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("update-index");
        {
            use std::io::Write as _;
            let mut si = child.stdin.take().expect("stdin");
            si.write_all(format!("100644 {blob} 0\tconsume-pins.toml\0").as_bytes())
                .expect("w");
        }
        assert!(child.wait().expect("wait").success(), "the settle failed");
        let _ = std::fs::remove_file(root.join(".git/pic.log"));
    }
    fn fired(root: &Path) -> String {
        std::fs::read_to_string(root.join(".git/pic.log")).unwrap_or_default()
    }

                                         
    settle_and_clear(&root);
    let stat = orchard::deploy::git_commit::diff_stat(&root, &[root.join("consume-pins.toml")]);
    assert_eq!(
        fired(&root),
        "",
        "diff_stat refreshed the index: {:?}",
        fired(&root)
    );

                                                                                                    
                                               
    settle_and_clear(&root);
    let _ = git_out(&root, &["diff", "--stat", "--", "consume-pins.toml"]);
    assert_eq!(
        fired(&root).trim(),
        "0 0",
        "a bare `git diff --stat` did not refresh, so the fixture cannot show the flag's effect"
    );
    settle_and_clear(&root);
    let out = std::process::Command::new("git")
        .current_dir(&root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["diff", "--stat", "--", "consume-pins.toml"])
        .output()
        .expect("git");
    assert!(out.status.success());
    assert_eq!(
        fired(&root).trim(),
        "0 0",
        "GIT_OPTIONAL_LOCKS=0 gated `git diff`, which is the reading falsified"
    );
                                                                                                  
    assert_eq!(
        stat, None,
        "the settled worktree equals its index entry, so there is no churn to report"
    );
    std::fs::write(root.join("consume-pins.toml"), "pin = 2\n").expect("w");
    let stat2 = orchard::deploy::git_commit::diff_stat(&root, &[root.join("consume-pins.toml")])
        .expect("the read answers over a real difference");
    assert!(
        stat2.contains("consume-pins.toml"),
        "the churn report lost its path: {stat2}"
    );
}

                                                                                                     

                                                                                                      
/// the lookup is an exact-string match on the repo-relative path against a whole `ls-files -s -z`
/// listing. A declared path whose NAME carries glob metacharacters therefore answers with its own
/// bit, not a glob-matched sibling's. Both directions are driven end to end, and the oracle is the
/// mode git reports in the LANDED tree against the mode git reports in the index.
#[test]
fn a_glob_named_declared_path_lands_its_own_index_exec_bit_not_a_siblings() {
                                                                                                     
                                            
    const GLOB: &str = "vendor/x[1].tar.xz";
    const SIBLING: &str = "vendor/x1.tar.xz";
    for (label, own_exec, sibling_exec, want_mode) in [
        ("own bit off, sibling on", false, true, "100644"),
        ("own bit on, sibling off", true, false, "100755"),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(move |root| {
            for (rel, exec) in [(GLOB, own_exec), (SIBLING, sibling_exec)] {
                let p = root.join(rel);
                std::fs::create_dir_all(p.parent().expect("parent")).expect("mk vendor");
                std::fs::write(&p, "committed\n").expect("w");
                git_out(root, &["add", "--", rel]);
                if exec {
                    git_out(root, &["update-index", "--chmod=+x", "--", rel]);
                }
            }
            git_out(root, &["commit", "-qm", "the glob-named pair"]);
                                                                                               
            git_out(root, &["config", "core.fileMode", "false"]);
        });
                                                                                              
        let modes: Vec<String> = git_out(&fx.root, &["ls-files", "-s"])
            .lines()
            .filter(|l| l.contains("vendor/x"))
            .map(str::to_string)
            .collect();
        assert_eq!(
            modes.len(),
            2,
            "{label}: the glob-named pair is not both tracked: {modes:?}"
        );
        assert!(
            modes
                .iter()
                .any(|m| m.contains(GLOB)
                    && m.starts_with(if own_exec { "100755" } else { "100644" })),
            "{label}: the glob-named path's own index mode is not the fixture's: {modes:?}"
        );
        assert_eq!(
            git_out(&fx.root, &["status", "--porcelain"]),
            "",
            "{label}: the fixture starts clean, so the ceremony's write is the only dirt"
        );
                                                                                                    
                                                                                                     
        record_write(&fx, &mut records, GLOB, BYTES, !own_exec);
        i.commit = true;
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        run.outcome
            .unwrap_or_else(|e| panic!("{label}: the gate commits: {e}"));
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            vec![GLOB.to_string()],
            "{label}: the commit changed a path other than the owed one"
        );
        let (mode, otype) = landed_entry(&fx.root, GLOB).unwrap_or_else(|| {
            panic!("{label}: HEAD carries no entry for {GLOB}");
        });
        assert_eq!(otype, "blob", "{label}: {GLOB} landed as {otype}");
        assert_eq!(
            mode, want_mode,
            "{label}: the landed mode is not the glob-named path's own index bit"
        );
    }
}

                                                                                                  
/// prompt with the resolve cure. A stash-apply conflict is the state: measured, it leaves stages 1-3
/// and none of the seven §3.1 markers, and porcelain commits over it exit 0. Arm sanity asserts both
/// halves of that state, so the arm cannot pass on a §3.1 refusal.
#[test]
fn an_unmerged_owed_path_refuses_before_the_prompt_with_the_resolve_cure() {
    const CURE: &str = "resolve the conflict at the named owed path(s), stage the resolution \
         (`git add` or `git rm`), then re-run";
    let (fx, mut records, admitted, i, profile) = gate_fixture_with(|root| {
        let p = root.join(VENDORED);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mk vendor");
        std::fs::write(&p, "base\n").expect("w");
        git_out(root, &["add", "--", VENDORED]);
        git_out(root, &["commit", "-qm", "the declared path, tracked"]);
        std::fs::write(&p, "mine\n").expect("w");
        git_out(root, &["stash", "-q"]);
        std::fs::write(&p, "theirs\n").expect("w");
        git_out(root, &["commit", "-qam", "theirs"]);
        git_must_conflict(root, &["stash", "apply"]);
    });
                                                                                
    let listing = git_out(&fx.root, &["ls-files", "-s", "--", VENDORED]);
    let stages: Vec<&str> = listing
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .collect();
    assert_eq!(
        stages,
        vec!["1", "2", "3"],
        "the stash apply left no conflict stages: {listing}"
    );
    for marker in [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "rebase-merge",
        "rebase-apply",
        "BISECT_LOG",
        "sequencer",
    ] {
        let path = fx
            .root
            .join(git_out(&fx.root, &["rev-parse", "--git-path", marker]));
        let (ref_ok, _, _) = git_try(&fx.root, &["rev-parse", "--verify", "--quiet", marker]);
        assert!(
            !path.exists() && !ref_ok,
            "{marker} exists, so §3.1 would refuse and this arm proves nothing about §3.10"
        );
    }
                                                                                                  
                                                                        
    let conflicted = std::fs::read(fx.at(VENDORED)).expect("read the conflicted file");
    record_write(&fx, &mut records, VENDORED, &conflicted, false);
    let head_before = git_head(&fx.root);
    let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "unmerged-owed-path",
        "{}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains(VENDORED),
        "the refusal names the unmerged path: {}",
        refusal.detail
    );
    assert_eq!(refusal.cure().as_str(), CURE);
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a refusal"
    );
}

                                                                                                    

                                                                                                  
/// that speaks for the bytes, and the renderer's `this_run` branch compares it against the observing
/// run — both were unarmed, and both mutations (the witness attributed to the observing run; the
/// branch forced true) left the whole suite green. This arm drives a run-2 gate over content run-1
/// recorded and reads the composed row off fd 1 as the operator sees it, against a hand-built
/// expected line.
#[test]
fn the_record_view_attributes_a_prior_runs_content_to_that_run() {
    use sha2::{Digest, Sha256};
    let (fx, mut records, admitted, i, profile) = gate_fixture();
                               
    record_write(&fx, &mut records, VENDORED, BYTES, false);
    drop(records);
                                                            
    let mut records2 = records_as_run(&fx, "run-2");
                                                                                   
    assert_eq!(
        orchard::ceremony::records::classify_executing_dirt(&records2, &fx.at(VENDORED)),
        orchard::ceremony::records::DirtClass::PriorRunRecorded,
        "the fixture is not a prior-run path"
    );
    let sha12: String = hex::encode(Sha256::digest(BYTES))
        .chars()
        .take(12)
        .collect();
    let expected = format!(
        " {VENDORED:?} [recorded by a prior run] prior run run-1 {sha12} {} bytes",
        BYTES.len()
    );
    let prompt = || 'n';
    let (run, captured) =
        capture_fd1(|| run_gate(&fx, &mut records2, &admitted, &i, &profile, true, &prompt));
    assert!(
        run.outcome.is_err(),
        "declining at the prompt stops the run"
    );
    let rows: Vec<&str> = captured
        .lines()
        .filter(|l| l.starts_with(' ') && l.contains(" ["))
        .collect();
    assert_eq!(
        rows,
        vec![expected.as_str()],
        "the prior-run row moved.\nfull capture:\n{captured}"
    );
}

                                                                                                    
/// not force a read failure. A mode-000 regular file the suite owns is `EACCES` for a process without
/// `CAP_DAC_OVERRIDE`, so the class is drivable; the arm asserts the recording site renders the Io
/// cure. Skipped, loudly, when the suite runs as root (where the open succeeds).
#[test]
fn a_mode_000_declared_path_renders_the_io_cure_at_the_recording_site() {
    use std::os::unix::fs::PermissionsExt as _;
    const IO_CURE: &str = "the path could not be read; check permissions and the filesystem, then \
         re-run";
    let (fx, mut records, _admitted, _i, _profile) = gate_fixture();
    let p = fx.at(VENDORED);
    std::fs::create_dir_all(p.parent().expect("parent")).expect("mk vendor");
    std::fs::write(&p, BYTES).expect("w");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
                                                                                      
    let opened = std::fs::File::open(&p);
    if opened.is_ok() {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("restore");
        panic!(
            "this process can read a mode-000 file (running as root or with CAP_DAC_OVERRIDE), so \
             the Io class cannot be driven here"
        );
    }
    let e = orchard::ceremony::records::open_path_record(&mut records, &p)
        .expect_err("an unreadable pre-state refuses");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("restore");
    assert_eq!(e.id.token(), "declared-path-unhashable");
    assert_eq!(
        e.cure().as_str(),
        IO_CURE,
        "the recording site renders the cure for the class it met"
    );
}

                                                                                                   
/// checkout rendered the commit gate's cure, which tells the operator about the EXECUTING checkout.
/// Driven through `sibling_gate` over a tenant path that exists and is not a repository; the expected
/// cure is a hand literal, so a rotation of the two `GitReadPurpose` bodies reds this arm and the
/// artifact-naming arm rather than passing on a self-comparison.
#[test]
fn the_sibling_checkout_read_renders_its_own_cure_not_the_commit_gates() {
    const SIBLING_CURE: &str = "git refused the read for the sibling gate; the detail carries \
         git's line; repair what it names, then re-run";
    const COMMIT_GATE_CURE: &str = "git refused the read for the commit gate; the detail \
         carries git's line; repair what it names, then re-run";
    assert_ne!(SIBLING_CURE, COMMIT_GATE_CURE, "two reads, two routes");
    let (fx, _records, _admitted, i, profile) = gate_fixture();
    std::fs::write(
        fx.at("repo-manifest.toml"),
        "schema-version = 1\n[repos.recipes]\npath = \"../recipes\"\nartifacts = [\"recipes-app\"]\n",
    )
    .expect("manifest");
    let tenant = fx.root.join("../recipes");
    std::fs::create_dir_all(&tenant).expect("tenant dir");
                                                                                                       
    let (ok, _, _) = git_try(&tenant, &["status", "--porcelain"]);
    assert!(
        !ok,
        "the tenant path is a git repo, so the read would succeed"
    );
    let reporter = orchard::ceremony::runner::Reporter { porcelain: true };
    let err = orchard::ceremony::runner::sibling_gate(
        orchard::ceremony::spine::SPINE
            .iter()
            .find(|s| s.id == orchard::ceremony::spine::StepId::S6TenantRepin)
            .expect("S6 in the spine"),
        &i,
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect_err("an unreadable tenant checkout fails closed at the sibling gate");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .unwrap_or_else(|| panic!("expected a typed Refusal, got: {err}"));
    assert_eq!(refusal.id.token(), "git-state-unreadable");
    assert_eq!(
        refusal.cure().as_str(),
        SIBLING_CURE,
        "the sibling read renders the commit gate's cure"
    );
}

/// M-PURPOSE-SIB (floor 3C residual 6): the sibling read's SPAWN failure renders the sibling
/// purpose's git-on-PATH cure. PATH is emptied around the read only; the tenant is a real repository.
#[test]
fn a_sibling_read_that_cannot_spawn_git_renders_the_sibling_purposes_path_cure() {
    let (fx, _records, _admitted, i, profile) = gate_fixture();
    std::fs::write(
        fx.at("repo-manifest.toml"),
        "schema-version = 1\n[repos.recipes]\npath = \"../recipes\"\nartifacts = [\"recipes-app\"]\n",
    )
    .expect("manifest");
    let tenant = fx.root.join("../recipes");
    std::fs::create_dir_all(&tenant).expect("tenant dir");
    git_out(&tenant, &["init", "-q"]);
    let (ok, _, _) = git_try(&tenant, &["status", "--porcelain"]);
    assert!(ok, "arm sanity: the tenant reads before PATH is emptied");
    let reporter = orchard::ceremony::runner::Reporter { porcelain: true };
    let step = orchard::ceremony::spine::SPINE
        .iter()
        .find(|s| s.id == orchard::ceremony::spine::StepId::S6TenantRepin)
        .expect("S6 in the spine");
    let empty = fx.at(".nopath");
    std::fs::create_dir_all(&empty).expect("empty PATH dir");
    let old_path = std::env::var("PATH").expect("PATH");
                                                                                           
    unsafe { std::env::set_var("PATH", empty.display().to_string()) };
    let err = orchard::ceremony::runner::sibling_gate(step, &i, &fx.ctx, &profile, &reporter)
        .expect_err("a sibling read that cannot spawn git fails closed");
    unsafe { std::env::set_var("PATH", &old_path) };
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .unwrap_or_else(|| panic!("expected a typed Refusal, got: {err}"));
    assert_eq!(refusal.id.token(), "git-state-unreadable");
    assert!(
        refusal.detail.contains("could not run"),
        "the detail does not carry the spawn failure: {}",
        refusal.detail
    );
    const SIBLING_SPAWN_CURE: &str = "the ceremony could not read the sibling checkout's git \
         state for its sibling gate; run from the checkout the ceremony was invoked on, with \
         `git` on PATH";
    assert_eq!(
        refusal.cure().as_str(),
        SIBLING_SPAWN_CURE,
        "the sibling spawn failure does not render the sibling purpose's PATH cure"
    );
}

                                                                                            
/// constructed commit the state lands (a removal plus an addition) instead of dying at a pathspec, so
/// the residual the R15 floor froze is closed by shape; the arm holds the landed shape on the token
                                                                                                
#[test]
fn a_recorded_rename_of_declared_paths_lands_as_a_removal_and_an_addition_on_both_routes() {
    const RENAMED: &str = "vendor/y.tar.xz";
    for (label, token) in [("the token route", true), ("the interactive route", false)] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            let p = root.join(VENDORED);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mk vendor");
            std::fs::write(&p, "committed\n").expect("w");
            git_out(root, &["add", "--", VENDORED]);
            git_out(root, &["commit", "-qm", "the declared path, tracked"]);
        });
                                                                                                       
                                   
        record_write(&fx, &mut records, RENAMED, b"committed\n", false);
        let origin = fx.at(VENDORED);
        let tok = orchard::ceremony::records::open_path_record(&mut records, &origin)
            .expect("open the origin");
        std::fs::remove_file(&origin).expect("the rename's removal");
        orchard::ceremony::records::finalize_path_record(&mut records, tok).expect("finalize");
        git_out(&fx.root, &["add", "-A"]);
                                                                  
        let staged = git_out(&fx.root, &["diff", "--cached", "--name-status", "-M"]);
        assert!(
            staged.lines().any(|l| l.starts_with('R')),
            "{label}: git does not read the fixture as a rename: {staged}"
        );
        i.commit = token;
        let prompt = || 'y';
        let run = run_gate(&fx, &mut records, &admitted, &i, &profile, !token, &prompt);
        run.outcome
            .unwrap_or_else(|e| panic!("{label}: the rename state commits: {e}"));
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            vec![VENDORED.to_string(), RENAMED.to_string()],
            "{label}: the landed commit is not the removal plus the addition"
        );
        assert_eq!(
            landed_entry(&fx.root, VENDORED),
            None,
            "{label}: the rename origin still has an entry at HEAD"
        );
        assert_eq!(
            landed_entry(&fx.root, RENAMED).map(|e| e.0),
            Some("100644".to_string()),
            "{label}: the rename destination did not land"
        );
    }
}

                                                                                                     

/// The env var that turns this test binary into one §3.11 role.
const ENV_ROLE: &str = "ORCHARD_R16_ENV_ROLE";
/// The test the role harness re-execs.
const ENV_DRIVEN_TEST: &str = "the_gates_reads_ignore_a_decoy_git_environment";
/// What a passing role prints before exiting 0.
const ROLE_OK: &str = "R16-ENV-ROLE-OK";

/// One §3.11 role, run in a DEDICATED process: the role sets `GIT_*` variables in its own
/// environment, which is process-global and cannot be done inside a parallel test run. A failed
/// assertion panics, so the role's process exits non-zero and the parent reads that. The fixture is
/// built with a clean environment first (`git init` under a decoy `GIT_DIR` would create the
/// repository at the decoy), then the decoy is set, then the gate runs.
fn run_env_role(role: &str) {
                                                                                                 
                                                                                                     
    const DECOY_KEYS: &[&str] = &[
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
        "GIT_CONFIG_GLOBAL",
    ];

    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);

                                                                     
    let decoy = fx.at("../decoy");
    std::fs::create_dir_all(&decoy).expect("mk decoy");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "d@d"],
        vec!["config", "user.name", "d"],
    ] {
        git_out(&decoy, &args);
    }
    std::fs::write(decoy.join("decoy.txt"), "decoy\n").expect("w");
    git_out(&decoy, &["add", "-A"]);
    git_out(&decoy, &["commit", "-qm", "the decoy's own baseline"]);
    std::fs::write(decoy.join("decoy.txt"), "decoy dirt\n").expect("w");
    let decoy_head = git_head(&decoy);

    let global_config = fx.at("../global.gitconfig");
    if role == "globalconfig" {
        std::fs::write(&global_config, "[extensions]\n\tsomefuture = 1\n").expect("w");
    }
    unsafe {
        match role {
            "gitdir" => std::env::set_var("GIT_DIR", decoy.join(".git")),
            "indexfile" => std::env::set_var("GIT_INDEX_FILE", decoy.join(".git/index")),
            "configcount" => {
                std::env::set_var("GIT_CONFIG_COUNT", "1");
                std::env::set_var("GIT_CONFIG_KEY_0", "commit.gpgSign");
                std::env::set_var("GIT_CONFIG_VALUE_0", "notabool");
            }
            "ident" => {
                std::env::set_var("GIT_AUTHOR_NAME", "Env Author");
                std::env::set_var("GIT_AUTHOR_EMAIL", "env-author@example.invalid");
                std::env::set_var("GIT_AUTHOR_DATE", "2026-01-02T03:04:05+00:00");
                std::env::set_var("GIT_COMMITTER_NAME", "Env Committer");
                std::env::set_var("GIT_COMMITTER_EMAIL", "env-committer@example.invalid");
                std::env::set_var("GIT_COMMITTER_DATE", "2026-01-02T03:04:05+00:00");
            }
            "globalconfig" => std::env::set_var("GIT_CONFIG_GLOBAL", &global_config),
            other => panic!("unknown §3.11 role {other}"),
        }
    }

    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);

                                                                            
    let global_visible = (role == "globalconfig").then(|| {
        let (_, out, _) = git_try(&fx.root, &["config", "--get-regexp", r"^extensions\."]);
        out
    });
    unsafe {
        for k in DECOY_KEYS {
            std::env::remove_var(k);
        }
    }

    run.outcome
        .unwrap_or_else(|e| panic!("role {role}: the gate did not commit: {e}"));
                                                                                                     
                                          
    assert_ne!(
        git_head(&fx.root),
        head_before,
        "role {role}: nothing landed in the named checkout"
    );
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "role {role}: the commit changed a path outside the owed set"
    );
    assert_eq!(
        git_head(&decoy),
        decoy_head,
        "role {role}: the decoy repository's HEAD moved"
    );

    match role {
                                                                                                   
        "gitdir" => assert!(
            !git_show_names(&fx.root, "HEAD")
                .iter()
                .any(|p| p == "decoy.txt"),
            "the decoy's dirt landed in the ceremony's commit"
        ),
                                                                        
        "indexfile" => assert!(
            !git_out(&fx.root, &["ls-files", "--", VENDORED]).is_empty(),
            "the settle did not write the named checkout's index"
        ),
                                                                                                   
                                                  
        "configcount" => {
            let header = git_out(&fx.root, &["cat-file", "commit", "HEAD"]);
            assert!(
                !header.contains("gpgsig"),
                "an injected config reached the gate: {header}"
            );
        }
        "ident" => {
            let ident = git_out(
                &fx.root,
                &["log", "-1", "--format=%an|%ae|%aI|%cn|%ce|%cI", "HEAD"],
            );
            assert_eq!(
                ident,
                "Env Author|env-author@example.invalid|2026-01-02T03:04:05Z|Env Committer|\
                 env-committer@example.invalid|2026-01-02T03:04:05Z",
                "the allowlisted ident and date variables did not reach the commit"
            );
        }
                                                                                                 
                                                                                                   
        "globalconfig" => {
            let seen = global_visible.unwrap_or_default();
            assert!(
                seen.contains("somefuture"),
                "the global config carried no extensions key, so this role proves nothing: [{seen}]"
            );
        }
        _ => unreachable!(),
    }
    println!("{ROLE_OK} {role}");
}

                                                                                                       
/// for a repository an inherited `GIT_*` variable points at. Five roles, each in its own process
/// because the environment is process-global: a decoy `GIT_DIR`, a decoy `GIT_INDEX_FILE`, a
/// `GIT_CONFIG_COUNT` injection, the allowlisted ident and date pair (which must pass through), and a
/// `GIT_CONFIG_GLOBAL` carrying an unmodelled `extensions.*` key (which §3.0 must not see, because
/// its reads are `--local`). Each role asserts inside its own process and exits 0; the parent asserts
/// the exit status and the sentinel.
#[test]
fn the_gates_reads_ignore_a_decoy_git_environment() {
    if let Ok(role) = std::env::var(ENV_ROLE) {
        run_env_role(&role);
        return;
    }
    let exe = std::env::current_exe().expect("the test binary's own path");
    for role in [
        "gitdir",
        "indexfile",
        "configcount",
        "ident",
        "globalconfig",
    ] {
        let out = std::process::Command::new(&exe)
            .args([
                ENV_DRIVEN_TEST,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ENV_ROLE, role)
            .output()
            .expect("spawn the role");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "role {role} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("{ROLE_OK} {role}")),
            "role {role} exited 0 without reaching its assertions:\n{stdout}"
        );
    }
}

                                                                                                     

/// The four commit hooks porcelain would run, each leaving a marker and the message hook rewriting
/// the message.
fn install_the_commit_hooks(root: &Path) {
    for name in ["pre-commit", "commit-msg", "post-commit"] {
        install_hook(root, name, &format!(": > .git/hook-{name}\nexit 0\n"));
    }
    install_hook(
        root,
        "prepare-commit-msg",
        ": > .git/hook-prepare-commit-msg\n\
         echo 'substituted by the host hook' > \"$1\"\n\
         exit 0\n",
    );
}

/// §4 (M-MSG re-authored) and §7's hook row: the constructed commit runs NO host commit hook, so a
/// `prepare-commit-msg` hook cannot substitute the landed message. The oracle is a DIFFERENTIAL: the
/// same fixture without the hooks lands a message, and the hooked run's landed message must equal it
/// byte for byte, so the arm does not re-derive the composer's output. The four hook markers must all
/// be absent.
#[test]
fn no_host_commit_hook_runs_and_the_landed_message_is_the_composed_text() {
    let mut landed: Vec<String> = Vec::new();
    for (label, hooked) in [("without the hooks", false), ("with the hooks", true)] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(move |root| {
            if hooked {
                install_the_commit_hooks(root);
            }
        });
        let owed = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        run.outcome
            .unwrap_or_else(|e| panic!("{label}: the gate commits: {e}"));
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            owed,
            "{label}: the commit changed a path outside the owed set"
        );
        if hooked {
            for name in [
                "pre-commit",
                "prepare-commit-msg",
                "commit-msg",
                "post-commit",
            ] {
                assert!(
                    !fx.at(&format!(".git/hook-{name}")).exists(),
                    "the {name} hook ran"
                );
            }
        }
        landed.push(git_log_message(&fx.root, "HEAD"));
    }
    assert!(
        !landed[0].contains("substituted by the host hook"),
        "arm sanity: the unhooked run's message already carries the substitution"
    );
    assert_eq!(
        landed[1], landed[0],
        "the hooked run's landed message is not the message the composer produced"
    );
}

/// §3.6 / §4 (MR-D2 and the token-route note arms re-authored onto the one computed disclosure): the
/// discard note names the ORIGIN of a staged rename (`--no-renames`), each consent route emits it
/// exactly once, and it precedes the commit — a run whose commit REFUSES has still emitted it. The
/// last leg is the specificity half: no staged edit at an owed path, no note.
#[test]
fn the_discard_note_names_a_staged_renames_origin_once_per_route_before_the_commit() {
    const RENAMED: &str = "vendor/y.tar.xz";
    const NOTE: &str = " staged edit(s) the commit overwrites: ";
    /// A ceremony-recorded rename of the declared path, staged: the origin is an owed absence and the
    /// destination an owed write, and git reads the index as a rename.
    fn stage_a_recorded_rename(fx: &Fixture, records: &mut RunRecords) {
        record_write(fx, records, RENAMED, b"committed\n", false);
        let origin = fx.at(VENDORED);
        let tok = orchard::ceremony::records::open_path_record(records, &origin).expect("open");
        std::fs::remove_file(&origin).expect("the rename's removal");
        orchard::ceremony::records::finalize_path_record(records, tok).expect("finalize");
        git_out(&fx.root, &["add", "-A"]);
    }
    fn tracked_origin(root: &Path) {
        let p = root.join(VENDORED);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mk vendor");
        std::fs::write(&p, "committed\n").expect("w");
        git_out(root, &["add", "--", VENDORED]);
        git_out(root, &["commit", "-qm", "the declared path, tracked"]);
    }
    let expected = format!(
        "{NOTE}{:?}",
        std::collections::BTreeSet::from([VENDORED.to_string(), RENAMED.to_string()])
    );

                                                                                       
    let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(tracked_origin);
    stage_a_recorded_rename(&fx, &mut records);
    i.commit = true;
    let (run, captured) =
        capture_fd1(|| run_gate_headless(&fx, &mut records, &admitted, &i, &profile));
    run.outcome
        .unwrap_or_else(|e| panic!("the token route commits the rename state: {e}"));
    assert_eq!(
        captured.matches(NOTE).count(),
        1,
        "the token route emitted the note {} times:\n{captured}",
        captured.matches(NOTE).count()
    );
    assert!(
        captured.contains(&expected),
        "the note does not name the rename's origin.\nwant:\n{expected}\ngot:\n{captured}"
    );

                                                                                               
                                                                                                       
                                                                                                   
                   
    let (fx2, mut records2, admitted2, i2, profile2) = gate_fixture_with(tracked_origin);
    stage_a_recorded_rename(&fx2, &mut records2);
    let prompt = || 'y';
    let (run2, captured2) = capture_fd1(|| {
        run_gate(
            &fx2,
            &mut records2,
            &admitted2,
            &i2,
            &profile2,
            true,
            &prompt,
        )
    });
    run2.outcome
        .unwrap_or_else(|e| panic!("the prompt route commits the rename state: {e}"));
    assert_eq!(
        captured2.matches(NOTE).count(),
        1,
        "the interactive `y` route emitted the note {} times:\n{captured2}",
        captured2.matches(NOTE).count()
    );
    assert!(
        captured2.contains(&expected),
        "the prompt route's disclosure does not name the rename's origin:\n{captured2}"
    );

                                                                                         
    let (fx3, mut records3, admitted3, mut i3, profile3) = gate_fixture_with(|root| {
        tracked_origin(root);
        git_out(root, &["config", "commit.gpgSign", "notabool"]);
    });
    stage_a_recorded_rename(&fx3, &mut records3);
    i3.commit = true;
    let head3 = git_head(&fx3.root);
    let (run3, captured3) =
        capture_fd1(|| run_gate_headless(&fx3, &mut records3, &admitted3, &i3, &profile3));
    assert_eq!(
        run3.refusal().id.token(),
        "ceremony-commit-refused",
        "arm sanity: the malformed boolean is what stops this run"
    );
    assert_eq!(git_head(&fx3.root), head3, "the refused run committed");
    assert!(
        captured3.contains(&expected),
        "the note is emitted after the commit, so a refused commit tells the operator nothing about \
         the staged edits it would have overwritten:\n{captured3}"
    );

                                                                
    let (fx4, mut records4, admitted4, mut i4, profile4) = gate_fixture();
    record_write(&fx4, &mut records4, VENDORED, BYTES, false);
    i4.commit = true;
    let (run4, captured4) =
        capture_fd1(|| run_gate_headless(&fx4, &mut records4, &admitted4, &i4, &profile4));
    run4.outcome
        .unwrap_or_else(|e| panic!("an untracked-only owed set commits: {e}"));
    assert!(
        !captured4.contains(NOTE),
        "the note is emitted with an empty discard set:\n{captured4}"
    );
}

/// §4 (M-CURE re-targeted onto the plumbing stages): a failing construction stage refuses
/// `ceremony-commit-refused` carrying git's own reason and THAT STAGE's cure, with HEAD unmoved. Two
/// stages are driven under a read-only `.git/objects` (a real operator permissions state): the
/// per-path `hash-object -w`, whose owed path's blob the object store does not already hold, and
/// `write-tree`, reached when every owed blob is already present. `commit-tree`'s stage is driven by
/// `the_signing_read_signs_the_landed_commit_and_both_failure_shapes_refuse`.
#[test]
fn each_failing_plumbing_stage_refuses_with_gits_own_reason_and_that_stages_cure() {
    use std::os::unix::fs::PermissionsExt as _;
    const HASH_CURE: &str = "git refused the ceremony's commit at `hash-object`; the detail \
         carries git's own reason; repair what it names, then re-run";
    const PLUMBING_CURE: &str = "git refused the ceremony's commit at `write-tree`; the detail \
         carries git's own reason; repair what it names, then re-run";
    assert_ne!(HASH_CURE, PLUMBING_CURE, "two stages, two routes");

    for (label, vendored_bytes, want_stage, want_cure) in [
        (
            "hash-object",
            b"bytes no object exists for\n".as_slice(),
            "hash the declared path",
            HASH_CURE,
        ),
        ("write-tree", BYTES, "write-tree", PLUMBING_CURE),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
                                                                                                      
                                                         
        record_write(&fx, &mut records, TRACKED, BYTES, false);
        git_out(&fx.root, &["add", TRACKED]);
        record_write(&fx, &mut records, VENDORED, vendored_bytes, false);
        i.commit = true;
        let objects = fx.at(".git/objects");
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o500))
            .expect("make the object store read-only");
        let head_before = git_head(&fx.root);
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        let (id, detail, cure) = {
            let r = run.refusal();
            (
                r.id.token().to_string(),
                r.detail.clone(),
                r.cure().as_str().to_string(),
            )
        };
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o755))
            .expect("restore the object store");
        assert_eq!(id, "ceremony-commit-refused", "{label}: {detail}");
        assert!(
            detail.contains(want_stage),
            "{label}: the refusal does not name the stage that failed: {detail}"
        );
        assert!(
            detail.contains("permission") || detail.contains("Permission"),
            "{label}: the refusal does not carry git's own reason: {detail}"
        );
        assert_eq!(cure, want_cure, "{label}: the cure is not this stage's");
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{label}: HEAD moved under a refusal"
        );
    }
}

                                                                                          

/// The frozen this-run heading, hardcoded (the composer's `class_heading` is the mechanism; an arm
/// that read it back would compare the composer against itself).
const H_THIS_RUN_FIXED: &str = "Declared paths written by this ceremony run:";

                                                                                                    
/// operator's consent view or the landed commit message: both render the path through Debug, so a
/// crafted name lands inside one escaped line. Leg (a) the token route + the message; leg (b) the
/// interactive `y` route + the record view.
#[test]
fn a_forged_declared_path_name_lands_as_one_escaped_line_not_as_rows_or_headings() {
                                                                
    const FORGED_MSG: &str =
        "vendor/a\nDeclared paths written by this ceremony run:\n  vendor/never-committed.toml";
    {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        record_write(&fx, &mut records, VENDORED, BYTES, false);
        record_write(&fx, &mut records, FORGED_MSG, b"payload\n", false);
        i.commit = true;

        let (run, _captured) =
            capture_fd1(|| run_gate_headless(&fx, &mut records, &admitted, &i, &profile));
        run.outcome
            .expect("the token route lands the forged-name declared path");

        let landed = git_show_names(&fx.root, "HEAD");
        assert_eq!(
            landed.len(),
            2,
            "exactly the two owed paths land: {landed:?}"
        );
        assert!(
            !landed.iter().any(|p| p == "vendor/never-committed.toml"),
            "the forged path is not a landed path: {landed:?}"
        );

        let message = git_log_message(&fx.root, "HEAD");
        assert_eq!(
            message.lines().filter(|l| *l == H_THIS_RUN_FIXED).count(),
            1,
            "exactly one class heading stands as its own line; the forged heading stays inside the \
             escaped path line: {message}"
        );
        assert_eq!(
            message.lines().filter(|l| l.starts_with("  ")).count(),
            2,
            "exactly owed.len() indented path lines under the one heading: {message}"
        );
        assert_eq!(
            message
                .lines()
                .filter(|l| l.contains("never-committed"))
                .count(),
            1,
            "the forged text is escaped into one physical line: {message}"
        );
    }

                                                                                              
    const FORGED_VIEW: &str = "vendor/a\n vendor/never-committed.toml [recorded by this run] this \
         run 000000000000 42 bytes\n 3 declared path(s)\nvendor/z";
    {
        let (fx, mut records, admitted, i, profile) = gate_fixture();
        record_write(&fx, &mut records, VENDORED, BYTES, false);
        record_write(&fx, &mut records, FORGED_VIEW, b"payload\n", false);
        let prompt = || 'y';
        let (run, captured) =
            capture_fd1(|| run_gate(&fx, &mut records, &admitted, &i, &profile, true, &prompt));
        run.outcome.expect("the interactive y route commits");

        let rows = captured
            .lines()
            .filter(|l| l.starts_with(' ') && l.contains(" ["))
            .count();
        assert_eq!(
            rows, 2,
            "the record view holds exactly owed.len() rows; the forged newline adds none: {captured}"
        );
        assert_eq!(
            captured
                .lines()
                .filter(|l| l.trim_end() == " 2 declared path(s)")
                .count(),
            1,
            "one footer carrying the true count: {captured}"
        );
        assert!(
            !captured.lines().any(|l| l.trim() == "3 declared path(s)"),
            "the forged footer does not stand as its own line: {captured}"
        );
    }
}

                                                                                           

/// A `reference-transaction` hook that moves HEAD back to the parent in the `committed` phase ONCE,
/// so the identity read fails; guarded on the arming file.
const RT_MOVE_HEAD_BACK: &str = "[ \"$1\" = committed ] || exit 0\n\
     if [ -e .git/hook-armed ] && [ ! -e .git/rt-done ]; then\n\
     : > .git/rt-done\n\
     git update-ref HEAD \"$(git rev-parse HEAD^)\"\n\
     fi\n\
     exit 0\n";

                                                                                              
/// settle's real state, read from `settle`: with `.git/index.lock` held the settle fails and the
/// index at the owed path holds no entry (pre-commit); without the lock the settle runs and the
/// owed path carries the constructed blob. The detail's clause agrees with `git ls-files -s` either
/// way.
#[test]
fn the_identity_failure_detail_states_the_settles_real_result() {
                                                   
    {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            install_hook(root, "reference-transaction", RT_MOVE_HEAD_BACK)
        });
        let _owed = dirty_the_declared_pair(&fx, &mut records);
        arm_hook(&fx.root);
        std::fs::write(fx.at(".git/index.lock"), "").expect("hold the lock");
        i.commit = true;
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "ceremony-commit-verify-failed",
            "{}",
            refusal.detail
        );
        assert!(
            fx.root.join(".git/rt-done").exists(),
            "the hook never fired, so this arm measured nothing"
        );
        assert!(
            refusal.detail.contains("the settle failed")
                && refusal
                    .detail
                    .contains("pre-commit entries at the owed paths"),
            "the detail states the settle failed: {}",
            refusal.detail
        );
        let _ = std::fs::remove_file(fx.at(".git/index.lock"));
        assert!(
            git_out(&fx.root, &["ls-files", "-s", "--", VENDORED])
                .trim()
                .is_empty(),
            "a failed settle wrote no owed entry, matching the clause"
        );
    }

                                         
    {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            install_hook(root, "reference-transaction", RT_MOVE_HEAD_BACK)
        });
        let _owed = dirty_the_declared_pair(&fx, &mut records);
        arm_hook(&fx.root);
        i.commit = true;
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "ceremony-commit-verify-failed",
            "{}",
            refusal.detail
        );
        assert!(
            fx.root.join(".git/rt-done").exists(),
            "the hook never fired, so this arm measured nothing"
        );
        assert!(
            refusal.detail.contains("the settle ran")
                && refusal
                    .detail
                    .contains("constructed commit's entries at the owed paths"),
            "the detail states the settle ran: {}",
            refusal.detail
        );
        let listed = git_out(&fx.root, &["ls-files", "-s", "--", VENDORED]);
        assert!(
            listed.contains(VENDORED) && !listed.trim().is_empty(),
            "a settle that ran wrote the constructed owed entry, matching the clause: {listed:?}"
        );
    }
}

                                                                                           

/// A `reference-transaction` hook that rejects the transaction in the `prepared` phase, guarded on
/// the arming file; git aborts, exit 128, HEAD unmoved.
const RT_REJECT_PREPARED: &str = "[ \"$1\" = prepared ] || exit 0\n\
     [ -e .git/hook-armed ] || exit 0\n\
     echo 'policy: this repository forbids un-reviewed ref updates' >&2\n\
     exit 1\n";

                                                                                                   
/// the parent. The refusal carries git's own line and the Unmoved cure, HEAD byte-identical.
#[test]
fn a_reference_transaction_prepared_abort_refuses_with_the_unmoved_cure() {
    let (fx, mut records, admitted, mut i, profile) =
        gate_fixture_with(|root| install_hook(root, "reference-transaction", RT_REJECT_PREPARED));
    let _ = dirty_the_declared_pair(&fx, &mut records);
    arm_hook(&fx.root);
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("aborted by the reference-transaction hook"),
        "the detail carries git's own line: {}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains(&format!("HEAD is still at {head_before}")),
        "the detail states HEAD unmoved: {}",
        refusal.detail
    );
    assert!(
        refusal.cure().as_str()
            == format!(
                "HEAD is still at {head_before}; git refused the ref update for the reason in the \
                 detail; repair what git names, then re-run"
            ),
        "the Unmoved cure: {}",
        refusal.cure().as_str()
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under an unmoved-CAS refusal"
    );
    assert!(
        !git_out(&fx.root, &["log", "--format=%s", "--all"]).contains("ceremony("),
        "a ceremony commit landed under a refused compare-and-swap"
    );
}

                                                                                                  
/// HEAD unmoved, the Unmoved cure names git's own refusal reason.
#[test]
fn a_stale_head_lock_refuses_with_the_unmoved_cure() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    std::fs::write(fx.at(".git/HEAD.lock"), "").expect("hold the ref lock");
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    let _ = std::fs::remove_file(fx.at(".git/HEAD.lock"));
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains("cannot lock ref 'HEAD'")
            && refusal
                .detail
                .contains(&format!("HEAD is still at {head_before}")),
        "the detail carries git's own lock line and the unmoved state: {}",
        refusal.detail
    );
    assert!(
        refusal.cure().as_str().contains("repair what git names"),
        "the Unmoved cure: {}",
        refusal.cure().as_str()
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under an unmoved-CAS refusal"
    );
}

                                                                                               
/// makes that stage's spawn fail. PATH is the shim dir only, so once the shim removes itself the
/// next `git` lookup finds nothing; the shim execs the real git by absolute path for every earlier
/// call. Two stages are driven: `hash-object` (shim removed at the §3.2 `HEAD^{tree}` read, the
/// call before it) and `commit-tree` (shim removed at the §3.8 `commit.gpgSign` read, the call
/// before it), measured. Each refuses `ceremony-commit-refused` with the Spawn cure naming the
/// stage, HEAD unmoved.
#[test]
fn a_git_spawn_failure_at_a_construction_stage_refuses_with_the_spawn_cure() {
    use std::os::unix::fs::PermissionsExt as _;
    let real_git = {
        let out = std::process::Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .expect("resolve git");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let real_rm = {
        let out = std::process::Command::new("sh")
            .args(["-c", "command -v rm"])
            .output()
            .expect("resolve rm");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert!(
        !real_git.is_empty() && !real_rm.is_empty(),
        "git and rm must be resolvable for this arm"
    );

    for (trigger, stage, detail_names) in [
        ("HEAD^{tree}", "hash-object", "hash the declared path"),
        ("commit.gpgSign", "commit-tree", "commit-tree"),
    ] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        record_write(&fx, &mut records, TRACKED, BYTES, false);
        git_out(&fx.root, &["add", TRACKED]);
        record_write(
            &fx,
            &mut records,
            VENDORED,
            b"bytes no object holds yet\n",
            false,
        );
        i.commit = true;

        let shimdir = fx.at(".shim");
        std::fs::create_dir_all(&shimdir).expect("mk shim dir");
        let shim_git = shimdir.join("git");
        std::fs::write(
            &shim_git,
            format!(
                "#!/bin/sh\ncase \"$*\" in\n  *'{trigger}'*) '{rm}' -f '{shim}' ;;\nesac\nexec {real_git} \"$@\"\n",
                rm = real_rm,
                shim = shim_git.display()
            ),
        )
        .expect("write shim");
        std::fs::set_permissions(&shim_git, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shim");

        let old_path = std::env::var("PATH").expect("PATH");
        let head_before = git_head(&fx.root);
                                                                                               
        unsafe { std::env::set_var("PATH", shimdir.display().to_string()) };
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        unsafe { std::env::set_var("PATH", &old_path) };

        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "ceremony-commit-refused",
            "{stage}: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains(detail_names) && refusal.detail.contains("could not run"),
            "{stage}: the detail names the stage and the spawn failure: {}",
            refusal.detail
        );
        assert!(
            refusal
                .cure()
                .as_str()
                .starts_with(&format!("git could not be spawned at `{stage}`"))
                && refusal
                    .cure()
                    .as_str()
                    .contains("check that git is on PATH and executable"),
            "{stage}: the Spawn cure names the stage: {}",
            refusal.cure().as_str()
        );
        assert!(
            !shim_git.exists(),
            "{stage}: the shim never removed itself, so this arm measured a different failure"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{stage}: HEAD moved under a spawn refusal"
        );
    }
}

/// delta v3.4 §1.3: a `--git-path` answer outside UTF-8 no longer reads as bytes. In a linked
/// worktree `rev-parse --git-path` answers an absolute path in the MAIN repository's bytes
/// (pC16c_8); with a byte outside UTF-8 in that path, the contract check's
/// `rev-parse --git-path info/grafts` read decodes strict, fails, and refuses
/// `repository-form-unmodelled` through `RepoFormCondition::Unreadable`, naming the command and the
/// escaped sample. The contract check runs before the in-progress guard and the grafts-file check
/// (runner.rs `executing_gate`), so the refusal is the same whether an in-progress marker or a
/// grafts file is planted. The two MAIN-worktree controls (relative, ASCII answers) refuse their own
/// conditions.
#[test]
fn a_linked_worktree_with_a_non_utf8_main_path_refuses_at_the_contract_check() {
                                                                                                 
                        
    {
        let (fx, mut records, admitted, i, profile, _main_git, wt_git) =
            gate_fixture_linked_nonutf8();
        std::fs::write(wt_git.join("MERGE_HEAD"), b"deadbeef\n").expect("plant MERGE_HEAD");
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "the declared pair is owed");
        let head_before = git_head(&fx.root);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "repository-form-unmodelled",
            "marker planted: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("rev-parse --git-path info/grafts"),
            "marker planted: the detail names the --git-path command: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("\\xff"),
            "marker planted: the detail carries the escaped sample: {}",
            refusal.detail
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "marker planted: HEAD moved"
        );
    }
                                                                                 
    {
        let (fx, mut records, admitted, i, profile, main_git, _wt_git) =
            gate_fixture_linked_nonutf8();
        std::fs::create_dir_all(main_git.join("info")).expect("mk info");
        std::fs::write(main_git.join("info/grafts"), b"x\n").expect("plant grafts");
        let _ = dirty_the_declared_pair(&fx, &mut records);
        let head_before = git_head(&fx.root);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "repository-form-unmodelled",
            "grafts planted: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("rev-parse --git-path info/grafts"),
            "grafts planted: the detail names the --git-path command: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("\\xff"),
            "grafts planted: the detail carries the escaped sample: {}",
            refusal.detail
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "grafts planted: HEAD moved"
        );
    }
                                                                                 
    {
        let (fx, mut records, admitted, i, profile) = gate_fixture_with(|root| {
            std::fs::write(root.join(".git/MERGE_HEAD"), b"deadbeef\n").expect("plant MERGE_HEAD");
        });
        let _ = dirty_the_declared_pair(&fx, &mut records);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        assert_eq!(
            run.refusal().id.token(),
            "partial-commit-blocked",
            "main worktree marker: {}",
            run.refusal().detail
        );
    }
    {
        let (fx, mut records, admitted, i, profile) = gate_fixture_with(|root| {
            std::fs::create_dir_all(root.join(".git/info")).expect("mk info");
            std::fs::write(root.join(".git/info/grafts"), b"x\n").expect("plant grafts");
        });
        let _ = dirty_the_declared_pair(&fx, &mut records);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        assert_eq!(
            run.refusal().id.token(),
            "repository-form-unmodelled",
            "main worktree grafts: {}",
            run.refusal().detail
        );
    }
}

/// A two-commit `git revert` conflicting on the first, resolved with a plain `git commit`:
/// REVERT_HEAD is gone, the sequencer todo remains and its first command is `revert` (measured,
/// git 2.55.0).
fn leave_a_revert_sequencer_todo(root: &Path) {
    for (n, body) in [(1, "one\n"), (2, "two\n"), (3, "mainline\n")] {
        std::fs::write(root.join("unrelated.txt"), body).expect("w");
        git_out(root, &["add", "--", "unrelated.txt"]);
        git_out(root, &["commit", "-qm", &format!("edit {n}")]);
    }
    git_must_conflict(root, &["revert", "--no-edit", "HEAD~1", "HEAD~2"]);
    std::fs::write(root.join("unrelated.txt"), "resolved\n").expect("w");
    git_out(root, &["add", "--", "unrelated.txt"]);
    git_out(root, &["commit", "-qm", "resolved by hand"]);
}

/// delta v3.4 §1.3: the contract check runs before the in-progress guard, and in a linked worktree
/// whose main repository path holds a byte outside UTF-8 the contract check's
/// `rev-parse --git-path info/grafts` read refuses `repository-form-unmodelled`, so a sequencer todo
/// present in that worktree never reaches `sequencer_op`. Driven with a revert todo and a pick todo;
/// both refuse the same way. Arm sanity per leg reads the todo git left (ASCII) and asserts both
/// sequencer pseudo-refs are absent.
#[test]
fn in_a_linked_non_utf8_worktree_a_sequencer_todo_refuses_at_the_contract_check() {
    type Start = fn(&Path);
    for (label, first_word, start) in [
        (
            "revert sequencer",
            "revert",
            leave_a_revert_sequencer_todo as Start,
        ),
        ("pick sequencer", "pick", leave_a_sequencer_todo as Start),
    ] {
        let (fx, mut records, admitted, i, profile, _main_git, wt_git) =
            gate_fixture_linked_nonutf8_with(start);
        let todo = std::fs::read(wt_git.join("sequencer/todo"))
            .unwrap_or_else(|e| panic!("{label}: git left no sequencer todo: {e}"));
        let todo = String::from_utf8(todo).expect("git's own todo is ASCII here");
        assert_eq!(
            todo.split_whitespace().next(),
            Some(first_word),
            "{label}: the todo's first command"
        );
        for pseudo in ["CHERRY_PICK_HEAD", "REVERT_HEAD"] {
            let (present, _, _) = git_try(&fx.root, &["rev-parse", "--verify", "--quiet", pseudo]);
            assert!(!present, "{label}: {pseudo} exists");
        }
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "{label}: the declared pair is owed");
        let head_before = git_head(&fx.root);
        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "repository-form-unmodelled",
            "{label}: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("rev-parse --git-path info/grafts"),
            "{label}: the detail names the --git-path command: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("\\xff"),
            "{label}: the detail carries the escaped sample: {}",
            refusal.detail
        );
        assert_eq!(git_head(&fx.root), head_before, "{label}: HEAD moved");
    }
}

/// The sample the seam renders for a single 0xFF byte: `non_utf8_sample` is `escape_ascii`, so the
/// byte renders `\xff` (measured with `rustc` before this arm was written).
const NONUTF8_SAMPLE: &str = "\\xff";

/// The stderr the CAS leg's shim writes when it refuses the ref update.
const SHIM_UPDATE_REF_STDERR: &str = "the shim refused the update";

/// One `git` shim on PATH: `body` is a `case` over the argv, everything it does not intercept execs
/// the real git by absolute path.
fn install_git_shim(dir: &Path, body: &str, real_git: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).expect("mk shim dir");
    let shim = dir.join("git");
    std::fs::write(
        &shim,
        format!("#!/bin/sh\n{body}\nexec {real_git} \"$@\"\n"),
    )
    .expect("write shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    shim
}

                                                                                                    
/// typed condition, carrying the sample in the composed detail and that condition's cure. One PATH
/// `git` shim per leg emits the byte 0xFF at one command and execs the real git for every other
/// call, so each leg measures one consumer. Every expected detail and cure is a hand literal
/// composed here; none is read from the mechanism. The post-swap leg is the one that LANDS: its
/// HEAD is the constructed commit, read back with git itself.
#[test]
fn a_non_utf8_git_read_refuses_at_each_run_str_consumer_with_the_sample_in_the_detail() {
    let resolve = |tool: &str| {
        let out = std::process::Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .expect("resolve tool");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let real_git = resolve("git");
    assert!(!real_git.is_empty(), "git must be resolvable for this arm");

    let emitted = |op: &str| format!("`git {op}` emitted bytes outside UTF-8 ({NONUTF8_SAMPLE})");
    let read_cure = |op: &str| {
        format!(
            "git's `{op}` output for the commit gate holds bytes outside UTF-8; the ceremony \
             requires UTF-8 paths and configuration keys; rename the path or key the sample \
             names to UTF-8, then re-run"
        )
    };
    let parse_cure = |stage: &str| {
        format!(
            "the ceremony could not parse git's `{stage}` output; the detail carries the record; \
             report it"
        )
    };
    let one_shot =
        |trigger: &str| format!("case \"$*\" in\n  *'{trigger}'*) printf '\\377'; exit 0 ;;\nesac");

                                                                                               
    type Text = Box<dyn Fn(&str) -> String>;
    let legs: Vec<(&str, String, &str, Text, Text, bool)> = vec![
        (
            "rev-parse --is-shallow-repository",
            one_shot("--is-shallow-repository"),
            "git-state-unreadable",
            Box::new(move |_| {
                format!(
                    "cannot read the executing checkout's git state: {}",
                    emitted("rev-parse --is-shallow-repository")
                )
            }),
            Box::new(move |_| read_cure("rev-parse --is-shallow-repository")),
            false,
        ),
        (
            "the parent read",
            one_shot("HEAD^{commit}"),
            "git-state-unreadable",
            Box::new(move |_| {
                format!(
                    "read HEAD for the commit gate: {}",
                    emitted("rev-parse HEAD^{commit}")
                )
            }),
            Box::new(move |_| read_cure("rev-parse HEAD^{commit}")),
            false,
        ),
        (
            "the HEAD tree read",
            one_shot("HEAD^{tree}"),
            "git-state-unreadable",
            Box::new(move |_| {
                format!(
                    "read HEAD tree for the commit gate: {}",
                    emitted("rev-parse HEAD^{tree}")
                )
            }),
            Box::new(move |_| read_cure("rev-parse HEAD^{tree}")),
            false,
        ),
        (
            "write-tree",
            one_shot("write-tree"),
            "ceremony-commit-refused",
            Box::new(move |_| {
                format!(
                    "the ceremony's gate commit failed at `write-tree`: {}",
                    emitted("write-tree")
                )
            }),
            Box::new(move |_| parse_cure("write-tree")),
            false,
        ),
        (
            "commit-tree",
            one_shot("commit-tree"),
            "ceremony-commit-refused",
            Box::new(move |_| {
                format!(
                    "the ceremony's gate commit failed at `commit-tree`: {}",
                    emitted("commit-tree")
                )
            }),
            Box::new(move |_| parse_cure("commit-tree")),
            false,
        ),
        (
            "the post-CAS head read",
            String::from(
                "case \"$*\" in\n  *update-ref*) echo 'MSG' >&2; : > 'MARKER'; exit 1 ;;\n  \
                 *'rev-parse HEAD'*) if [ -e 'MARKER' ]; then printf '\\377'; exit 0; fi ;;\nesac",
            ),
            "ceremony-commit-refused",
            Box::new(move |_| {
                format!(
                    "`git update-ref HEAD` failed (exit status: 1): {SHIM_UPDATE_REF_STDERR}; the \
                     HEAD read after the refused update failed: {}",
                    emitted("rev-parse HEAD")
                )
            }),
            Box::new(move |_| {
                format!(
                    "the HEAD read after the refused update failed ({}); inspect `git rev-parse \
                     HEAD` by hand, then re-run",
                    emitted("rev-parse HEAD")
                )
            }),
            false,
        ),
        (
            "the identity read",
            String::from(
                "case \"$*\" in\n  *update-ref*) REALGIT \"$@\"; s=$?; : > 'MARKER'; exit $s ;;\n  \
                 *'rev-parse HEAD'*) if [ -e 'MARKER' ]; then printf '\\377'; exit 0; fi ;;\nesac",
            ),
            "ceremony-commit-verify-failed",
            Box::new(move |landed: &str| {
                format!(
                    "the identity read failed after the swap to {landed}: {}; the settle ran; the \
                     index holds the constructed commit's entries at the owed paths",
                    emitted("rev-parse HEAD")
                )
            }),
            Box::new(move |landed: &str| {
                format!("inspect `git log -1 HEAD` against {landed}, settle by hand, then re-run")
            }),
            true,
        ),
    ];

    for (label, body, id, detail, cure, lands) in legs {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "{label}: the declared pair is owed");
        i.commit = true;

        let shimdir = fx.at(".shim");
        let marker = fx.at(".shim-fired");
        let body = body
            .replace("MARKER", &marker.display().to_string())
            .replace("REALGIT", &real_git)
            .replace("MSG", SHIM_UPDATE_REF_STDERR);
        let shim = install_git_shim(&shimdir, &body, &real_git);
        assert!(shim.exists(), "{label}: the shim is on disk");

        let old_path = std::env::var("PATH").expect("PATH");
        let head_before = git_head(&fx.root);
                                                                                               
        unsafe { std::env::set_var("PATH", shimdir.display().to_string()) };
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        unsafe { std::env::set_var("PATH", &old_path) };

        let head_after = git_head(&fx.root);
        if lands {
            assert_ne!(
                head_after, head_before,
                "{label}: the commit had to land for this read to run"
            );
            assert!(
                marker.exists(),
                "{label}: the shim never reached its second phase"
            );
        } else {
            assert_eq!(head_after, head_before, "{label}: HEAD moved");
        }
        let refusal = run.refusal();
        assert_eq!(refusal.id.token(), id, "{label}: {}", refusal.detail);
        assert_eq!(
            refusal.detail,
            detail(&head_after),
            "{label}: the composed detail"
        );
        assert_eq!(
            refusal.cure().as_str(),
            cure(&head_after),
            "{label}: the cure"
        );
    }
}

/// Run `git` in `root` with raw byte arguments and return its raw stdout; a non-zero exit panics
/// with git's stderr. For a ref name or a listing that holds bytes outside UTF-8, which `git_out`
/// would decode lossily.
fn git_bytes(root: &Path, args: &[&std::ffi::OsStr]) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

                                                                                                
/// (`trim_ascii` over `for-each-ref`'s stdout), so a replace ref whose name holds a byte outside
/// UTF-8 refuses `repository-form-unmodelled` with the replaced-history condition's own cure, and
/// not the read-failure route a decode of that listing would take. Arm sanity reads the same
/// listing with git itself and asserts it is not UTF-8, so the leg cannot pass on an ASCII ref.
#[test]
fn a_replace_ref_named_outside_utf8_refuses_the_replaced_history_condition() {
    use std::ffi::OsStr;
    let (fx, mut records, admitted, i, profile) = gate_fixture_with(|root| {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        let head = git_out(root, &["rev-parse", "HEAD"]);
        let mut name = b"refs/replace/bad".to_vec();
        name.push(0xff);
        name.extend_from_slice(b"name");
        git_bytes(
            root,
            &[
                OsStr::new("update-ref"),
                &OsString::from_vec(name),
                OsStr::new(&head),
            ],
        );
    });
    let listing = git_bytes(
        &fx.root,
        &[
            OsStr::new("--no-replace-objects"),
            OsStr::new("for-each-ref"),
            OsStr::new("--count=1"),
            OsStr::new("--format=%(refname)"),
            OsStr::new("refs/replace/"),
        ],
    );
    assert!(
        std::str::from_utf8(&listing).is_err() && listing.contains(&0xff),
        "arm sanity: git's own listing must carry the byte outside UTF-8: {listing:?}"
    );

    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2, "the declared pair is owed");
    let head_before = git_head(&fx.root);
    let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "repository-form-unmodelled",
        "{}",
        refusal.detail
    );
    assert_eq!(
        refusal.detail,
        "the repository carries a replace ref (a ref under refs/replace/)"
    );
    assert_eq!(refusal.cure().as_str(), CURE_REPLACE_REFS);
    assert_eq!(git_head(&fx.root), head_before, "HEAD moved");
}
