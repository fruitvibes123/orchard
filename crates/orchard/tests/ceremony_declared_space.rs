//! R16 fold-3 §1 floor arms: the declared space, `orchard admit`, and the no-lazy-fetch belt.
//! Every arm drives the production path (`run_ceremony`, `declared_space_body`, or the built
//! `orchard` binary) over a real checkout and reads its oracle from `git` itself or from a hand
//! literal.

                                                                                                   
#[allow(dead_code)]
#[path = "common/admit.rs"]
mod admit;
#[allow(dead_code)]
#[path = "ceremony_gate_commit/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/roles.rs"]
mod roles;
#[allow(dead_code)]
#[path = "common/shell_split.rs"]
mod shell_split;

use std::path::{Path, PathBuf};

use fixture::*;
use orchard::ceremony::gate_commit::declared_space_body;

/// The §1.4 cures, as hand literals carrying the invocation's own `orchard admit` command
                                                                                             
/// against itself (M-R16-1b's class).
fn cure_no_space(admit: &str) -> String {
    format!(
        "the executing checkout has no operator-ratified declared space; run `{admit}` to ratify \
         its current declared space, then re-run"
    )
}
fn cure_undeclared(admit: &str) -> String {
    format!(
        "the executing checkout's effective git configuration differs from its ratified declared \
         space (the delta is in the detail: keys at every scope, and values at the program-valued \
         keys); revert the configuration, or run `{admit}` to ratify the shown delta, then re-run"
    )
}

/// The composed operator text of a §1.4 refusal, as `Refusal`'s `Display` writes it.
fn composed(id: &str, detail: &str, cure: &str) -> String {
    format!("refusal ({id}): {detail}\n  cure: {cure}")
}

                                                                                                      

/// §1.3 / §1.1: the measured declared space is git's OWN `--show-scope` listing reduced to
/// scope-qualified keys, sorted, deduplicated, one per line; a value enters a line only at a
/// value-sensitive key (§2.1), none of which this fixture's keys are.
///
/// What it claims: for this fixture's configuration, `declared_space_body` returns exactly the
/// frozen thirteen lines below. The set is a hand literal, so a mutation that widens the record to
/// the value, drops the scope prefix, splits records on LF instead of NUL, drops the deduplication,
/// or drops the sort reddens it. What it does NOT claim: anything about a git configuration shape
/// this fixture does not carry — a freeze compares content and models no grammar. Blind spots, named:
/// the `command` scope this fixture cannot set in-process, which
/// `the_declared_space_delta_is_seen_at_every_scope_git_lists` drives in dedicated processes (as it
/// does the `global`/`system` deltas); a git version whose `git init` writes a different `core.*`
/// set, which reddens this arm and is re-frozen consciously. The measurement runs in a role process
/// whose `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` point at empty scratch files from before its first
/// git command, so no host `~/.gitconfig`, `/etc/gitconfig` or inherited `GIT_CONFIG_GLOBAL` enters
                                                                                
///
/// The fixture exercises, per the R16b/fold-3 grounding: a subsection carrying a space
/// (`remote."a b".promisor`), a value carrying a newline (`user.multi`), a multivalued key
/// (`mv.k`, two records), a non-lexicographic insertion order (`zz.last` before `aa.first`), and a
/// `worktree`-scope entry.
#[test]
fn the_measured_key_set_is_gits_scope_qualified_keys_sorted_deduplicated_without_values() {
    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "the_measured_key_set_is_gits_scope_qualified_keys_sorted_deduplicated_without_values",
            &["frozenset"],
        );
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    roles::pin_empty_git_config(tmp.path());
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "true"],
        vec!["config", "extensions.worktreeConfig", "true"],
        vec!["config", "--worktree", "wt.floor", "xyz"],
        vec!["config", "remote.a b.promisor", "true"],
        vec!["config", "user.multi", "first\nsecond"],
        vec!["config", "--add", "mv.k", "a"],
        vec!["config", "--add", "mv.k", "b"],
        vec!["config", "zz.last", "1"],
        vec!["config", "aa.first", "1"],
    ] {
        git_out(&root, &args);
    }
                                                                                                
                                                             
    let raw = git_out(&root, &["config", "--list", "--show-scope", "--null"]);
    assert_eq!(
        raw.matches("mv.k").count(),
        2,
        "git listed no duplicate for the multivalued key, so the dedup claim is untested: {raw:?}"
    );
    assert!(
        raw.contains("user.multi\nfirst\nsecond"),
        "git did not keep the newline inside the record, so the first-LF claim is untested: {raw:?}"
    );

    let body = declared_space_body(&root).expect("measure the scratch checkout");
    let want = "\
local\taa.first
local\tcore.bare
local\tcore.filemode
local\tcore.logallrefupdates
local\tcore.repositoryformatversion
local\textensions.worktreeconfig
local\tmv.k
local\tremote.a b.promisor
local\tuser.email
local\tuser.multi
local\tuser.name
local\tzz.last
worktree\twt.floor
";
    assert_eq!(
        body, want,
        "role {role}: the measured declared space is not the frozen set"
    );
    println!("{} {role}", roles::ROLE_OK);
}

                                                                                                      

                                                                                         
/// `repository-form-unmodelled` and the admit cure, before the prompt, with HEAD unmoved and
/// nothing committed. Both consent routes are driven: the terminal route (whose prompt closure
/// panics if reached) and the forwarded `--commit` route.
#[test]
fn a_checkout_with_no_ratified_declared_space_refuses_before_the_prompt_on_both_routes() {
    for is_tty in [true, false] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = !is_tty;
        let head_before = git_head(&fx.root);
                                                                                             
        let file = i.ratified_file(&fx.ctx.repo_root, "executing");
        assert!(
            file.parent().expect("key directory").is_dir() && !file.exists(),
            "the fixture already carries a ratified file, so this arm proves nothing"
        );
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, is_tty, &prompt);
        let refusal = run.refusal();
        assert_eq!(
            refusal.to_string(),
            composed(
                "repository-form-unmodelled",
                &format!(
                    "the executing checkout has no ratified declared space at {}",
                    file.display()
                ),
                &cure_no_space(&i.admit_command(&fx.ctx)),
            ),
            "route is_tty={is_tty}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "route is_tty={is_tty}: HEAD moved on a pre-prompt refusal"
        );
    }
}

                                                                                                  
/// the `added` side; a key REMOVED names it on the `removed` side. The two in-process scopes are
/// driven here (`local`, and `worktree` under `extensions.worktreeConfig=true`); `global` and
/// `system` need a process-global environment and are driven by
/// `the_declared_space_delta_is_seen_at_every_scope_git_lists`.
#[test]
fn an_added_or_removed_key_refuses_naming_its_scope_qualified_line() {
                                                                                   
    let legs: Vec<(&str, Vec<Vec<&str>>, &str, &str)> = vec![
        (
            "local added",
            vec![vec!["config", "floor.local", "1"]],
            "[\"local\\tfloor.local\"]",
            "[]",
        ),
        (
            "worktree added",
            vec![vec!["config", "--worktree", "floor.wt", "1"]],
            "[\"worktree\\tfloor.wt\"]",
            "[]",
        ),
        (
            "local removed",
            vec![vec!["config", "--unset", "user.name"]],
            "[]",
            "[\"local\\tuser.name\"]",
        ),
    ];
    for (label, edits, added, removed) in legs {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            git_out(root, &["config", "extensions.worktreeConfig", "true"]);
        });
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        ratify_executing(&fx, &i);
        for args in &edits {
            git_out(&fx.root, args);
        }
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        assert_eq!(
            run.refusal().to_string(),
            composed(
                "repository-form-unmodelled",
                &format!(
                    "the executing checkout's declared space differs from the ratified file: added \
                     {added}, removed {removed}"
                ),
                &cure_undeclared(&i.admit_command(&fx.ctx)),
            ),
            "leg {label}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "leg {label}: HEAD moved on a pre-prompt refusal"
        );
    }
}

/// §1.1 / delta §8 Q1: the declared space carries KEYS, so changing a key's VALUE after
/// ratification refuses nothing and the run commits. Two shapes: a plain single-line value, and a
/// value carrying a newline (whose second line must never enter the key).
#[test]
fn a_config_value_change_never_refuses_the_declared_space() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
        git_out(root, &["config", "user.multi", "first\nsecond"]);
    });
    let owed = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
    ratify_executing(&fx, &i);
                                                                                      
    let ratified =
        std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
    for key in ["local\tuser.name", "local\tuser.multi"] {
        assert!(
            ratified.lines().any(|l| l == key),
            "the ratified space carries no {key:?} line, so this arm proves nothing:\n{ratified}"
        );
    }
    git_out(&fx.root, &["config", "user.name", "other"]);
    git_out(&fx.root, &["config", "user.multi", "third\nfourth"]);

    let prompt = || panic!("the forwarded token commits with no prompt");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    run.outcome
        .unwrap_or_else(|e| panic!("a value change is not a declared-space delta: {e}"));
    assert_ne!(git_head(&fx.root), head_before, "the run committed nothing");
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "the commit changed a path outside the owed set"
    );
}

/// delta §2.6 (pC16c_15, pC16c_16): a VALUE swap at a value-sensitive key changes the value column,
/// so the declared space differs and the gate refuses naming the removed and added lines. The
/// keys-only counterpart (`user.name`) is `a_config_value_change_never_refuses_the_declared_space`.
#[test]
fn a_value_sensitive_value_swap_refuses_naming_the_lines() {
                                                                                               
                                                                                                   
                                                   
    let legs: Vec<(&str, &str, &str, &str)> = vec![
        ("core.fsmonitor", "core.fsmonitor", "false", "/x/fsmon"),
        ("filter.zz.clean", "filter.zz.clean", "sedA", "sedB"),
    ];
    for (label, key, v0, v1) in legs {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            git_out(root, &["config", key, v0]);
        });
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        ratify_executing(&fx, &i);
                                                                               
        let ratified =
            std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
        let removed_line = format!("local\t{key}\t{v0:?}");
        assert!(
            ratified.lines().any(|l| l == removed_line),
            "leg {label}: the ratified space has no value line {removed_line:?}:\n{ratified}"
        );
        git_out(&fx.root, &["config", key, v1]);
        let added_line = format!("local\t{key}\t{v1:?}");
        let added = format!("[{added_line:?}]");
        let removed = format!("[{removed_line:?}]");
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        assert_eq!(
            run.refusal().to_string(),
            composed(
                "repository-form-unmodelled",
                &format!(
                    "the executing checkout's declared space differs from the ratified file: added \
                     {added}, removed {removed}"
                ),
                &cure_undeclared(&i.admit_command(&fx.ctx)),
            ),
            "leg {label}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "leg {label}: HEAD moved on a pre-prompt refusal"
        );
    }
}

/// delta §2.6 (pC16c_7): a config key carrying bytes outside UTF-8 is refused at the measurement,
/// not collapsed to one line, so the two `pC16c_7` shapes (a key swap, a key addition) can no
/// longer be admitted. The gate refuses `repository-form-unmodelled` with the sample naming the
/// lossy key; `orchard admit`'s measurement (`declared_space_body`) fails the same way, so admit
/// prints the error and writes nothing.
#[test]
fn a_non_utf8_config_key_refuses_at_the_gate_and_admit() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
    let cfg = fx.root.join(".git/config");
    let mut bytes = std::fs::read(&cfg).expect("read .git/config");
    bytes.extend_from_slice(b"[remote \"a");
    bytes.push(0xff);
    bytes.extend_from_slice(b"\"]\n\turl = https://x/\n");
    std::fs::write(&cfg, &bytes).expect("write .git/config");

                                                                                    
    let err = declared_space_body(&fx.root).expect_err("a non-UTF-8 key is not measurable");
    let orchard::ceremony::refusal::GitRunError::NonUtf8Output { sample, .. } = &err else {
        panic!("expected NonUtf8Output, got {err:?}");
    };
    let sample = sample.clone();
    assert!(
        sample.contains("remote.a"),
        "the sample names the lossy key: {sample}"
    );

                                                                                             
    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    let text = run.refusal().to_string();
    assert!(
        text.starts_with(
            "refusal (repository-form-unmodelled): cannot read the executing checkout's git \
             configuration listing:"
        ),
        "the gate refuses via the unreadable path: {text}"
    );
    assert!(
        text.contains(&sample),
        "the gate detail carries the sample {sample:?}: {text}"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved on a pre-prompt refusal"
    );
}

                                                                                                     

/// §1.4 / delta §8 Q1: the comparison reads git's whole listing, not the local file. Three roles,
/// each in its own process: a key added at `global` scope (`GIT_CONFIG_GLOBAL`), a key added at
/// `system` scope (`GIT_CONFIG_SYSTEM`), and a key MOVED from `local` to `global` (whose delta names
/// the removed line and the added line, and which a scope-blind comparison would call unchanged).
#[test]
fn the_declared_space_delta_is_seen_at_every_scope_git_lists() {
    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "the_declared_space_delta_is_seen_at_every_scope_git_lists",
            &["globalscope", "systemscope", "movedscope"],
        );
        return;
    };
                                                                                                 
                                                  
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);

    let global = fx.at("../global.gitconfig");
    let system = fx.at("../system.gitconfig");
    std::fs::write(&global, "[baseglob]\n\tkey = 1\n").expect("w");
    std::fs::write(&system, "[basesys]\n\tkey = 1\n").expect("w");
    roles::pin_git_config(&global, &system);
                                                                                                    
             
    ratify_executing(&fx, &i);
    let ratified =
        std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
    for key in ["global\tbaseglob.key", "system\tbasesys.key"] {
        assert!(
            ratified.lines().any(|l| l == key),
            "role {role}: the ratified space carries no {key:?}, so the environment did not \
             reach the measurement:\n{ratified}"
        );
    }

    let (added, removed) = match role.as_str() {
        "globalscope" => {
            std::fs::write(&global, "[baseglob]\n\tkey = 1\n[floor]\n\tglob = 1\n").expect("w");
            ("[\"global\\tfloor.glob\"]", "[]")
        }
        "systemscope" => {
            std::fs::write(&system, "[basesys]\n\tkey = 1\n[floor]\n\tsys = 1\n").expect("w");
            ("[\"system\\tfloor.sys\"]", "[]")
        }
        "movedscope" => {
                                                                                            
                                                         
            let name = git_out(&fx.root, &["config", "--local", "user.name"]);
            git_out(&fx.root, &["config", "--local", "--unset", "user.name"]);
            std::fs::write(
                &global,
                format!("[baseglob]\n\tkey = 1\n[user]\n\tname = {name}\n"),
            )
            .expect("w");
            ("[\"global\\tuser.name\"]", "[\"local\\tuser.name\"]")
        }
        other => panic!("unknown declared-space role {other}"),
    };

    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    let text = run.refusal().to_string();
    unsafe {
        std::env::remove_var("GIT_CONFIG_GLOBAL");
        std::env::remove_var("GIT_CONFIG_SYSTEM");
    }
    assert_eq!(
        text,
        composed(
            "repository-form-unmodelled",
            &format!(
                "the executing checkout's declared space differs from the ratified file: added \
                 {added}, removed {removed}"
            ),
            &cure_undeclared(&i.admit_command(&fx.ctx)),
        ),
        "role {role}"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "role {role}: HEAD moved on a pre-prompt refusal"
    );
    println!("{} {role}", roles::ROLE_OK);
}

                                                                                                      

/// Every path under `dir` with its bytes, for a byte-identity comparison across a run.
fn dir_snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let bytes = std::fs::read(e.path()).unwrap_or_default();
        out.push((name, bytes));
    }
    out.sort();
    out
}

                                                                                                    
/// against its ratified file, writes NOTHING when the authorize is declined, writes the sorted file
/// when it is given, and prints an empty diff on a re-run.
///
/// Leg 2 compares the file the spawned `admit` wrote against an in-process `declared_space_body`,
/// so both halves must see one git configuration; the arm runs in a role process pinned at empty
/// `global`/`system` files from before its first git command, which is the pin
                                                     
#[test]
fn orchard_admit_writes_only_after_the_authorize_and_ratifies_the_sorted_key_set() {
    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "orchard_admit_writes_only_after_the_authorize_and_ratifies_the_sorted_key_set",
            &["admitwrite"],
        );
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    roles::pin_empty_git_config(tmp.path());
    let root = tmp.path().join("repo");
                                                                                      
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "true"],
                                                                                                   
                                                                  
        vec!["config", "zz.last", "1"],
        vec!["config", "aa.first", "1"],
        vec!["config", "--add", "mv.k", "a"],
        vec!["config", "--add", "mv.k", "b"],
    ] {
        git_out(&root, &args);
    }
    std::fs::write(root.join("repo-manifest.toml"), "schema-version = 1\n").expect("manifest");
    let profile = tmp.path().join("alpha.toml");
    std::fs::write(&profile, "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n").expect("profile");
    let dir = tmp.path().join("repo-form");
    std::fs::create_dir_all(&dir).expect("mk repo-form");
    let file = dir.join("executing.keys");

                                                                                 
    let before = dir_snapshot(&dir);
    let (ok, text) = admit::run_admit(&root, &profile, &dir, "no\n");
    assert!(ok, "declined admit did not exit 0:\n{text}");
    assert!(
        text.contains("  +local\taa.first\n") && text.contains("  +local\tzz.last\n"),
        "the diff does not name its `+` lines:\n{text}"
    );
    assert!(
        text.contains("nothing written"),
        "the declined run does not say it wrote nothing:\n{text}"
    );
    assert_eq!(
        dir_snapshot(&dir),
        before,
        "the declined run changed the key directory"
    );

                                                                            
    let (ok, text) = admit::run_admit(&root, &profile, &dir, "admit\n");
    assert!(ok, "authorized admit did not exit 0:\n{text}");
    assert!(
        text.contains(&format!("wrote {}", file.display())),
        "the authorized run does not name the written path:\n{text}"
    );
    let body = std::fs::read_to_string(&file).expect("read executing.keys");
    let lines: Vec<&str> = body.lines().collect();
    let mut sorted = lines.clone();
    sorted.sort_unstable();
    assert_eq!(lines, sorted, "the written file is not sorted:\n{body}");
    assert_eq!(
        lines.iter().filter(|l| **l == "local\tmv.k").count(),
        1,
        "the multivalued key is not deduplicated:\n{body}"
    );
    assert_eq!(
        body,
        declared_space_body(&root).expect("measure"),
        "the written file is not the measured declared space"
    );

                                                                                           
    let after_write = dir_snapshot(&dir);
    let (ok, text) = admit::run_admit(&root, &profile, &dir, "admit\n");
    assert!(ok, "the second admit did not exit 0:\n{text}");
    assert!(
        text.contains("(no change)") && text.contains("nothing written"),
        "the second run does not print an empty diff:\n{text}"
    );
    assert_eq!(
        dir_snapshot(&dir),
        after_write,
        "role {role}: the second run rewrote the key directory"
    );
    println!("{} {role}", roles::ROLE_OK);
}

                                                                                                      

/// §1.5: a ceremony NEVER writes the declared space. Driven end to end: a committing run over a
/// WRITABLE key directory leaves every file in it byte-identical, and the same run over a key
/// directory whose write bits the operator cleared still commits.
///
/// What it claims: this driven run wrote nothing under the key directory. What it does NOT claim:
/// that no code path can — a run that refuses, or another verb, is outside what this arm drives;
/// `the_declared_space_file_references_under_src_ceremony_are_frozen` holds the source-side set.
#[test]
fn a_committing_ceremony_writes_nothing_under_the_key_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    for readonly in [false, true] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let key_file = i.ratified_file(&fx.ctx.repo_root, "executing");
        let key_dir = key_file.parent().expect("key directory");
        let owed = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        ratify_executing(&fx, &i);
        let before = dir_snapshot(key_dir);
        assert!(
            !before.is_empty(),
            "the key directory is empty, so a byte-identity claim over it is vacuous"
        );
        if readonly {
            std::fs::set_permissions(key_dir, std::fs::Permissions::from_mode(0o500))
                .expect("chmod 0500");
        }
        let prompt = || panic!("the forwarded token commits with no prompt");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        if readonly {
            std::fs::set_permissions(key_dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod 0700");
        }
        run.outcome
            .unwrap_or_else(|e| panic!("readonly={readonly}: the gate did not commit: {e}"));
        assert_ne!(
            git_head(&fx.root),
            head_before,
            "readonly={readonly}: the run committed nothing, so it never reached the gate"
        );
        assert_eq!(
            git_show_names(&fx.root, "HEAD"),
            owed,
            "readonly={readonly}: the commit changed a path outside the owed set"
        );
        assert_eq!(
            dir_snapshot(key_dir),
            before,
            "readonly={readonly}: the ceremony changed the key directory"
        );
    }
}

/// The source lines under `crates/orchard/src/ceremony/` that name the declared-space file or its
/// directory, frozen as an exact set.
///
/// What it claims: over the non-comment lines of `crates/orchard/src/ceremony/**/*.rs`, the four
/// names `repo_form_dir`, `ratified_file`, `.keys"` and `declared_space_body` occur at exactly
/// these (file, trimmed line) pairs. A new mention — a write, a copy, a self-heal — reddens it and
/// forces a conscious re-freeze with a disposition. What it does NOT claim: that no code under
/// `src/ceremony/` can write the key directory; a freeze compares content and models no grammar.
/// Blind spots, named: a write through a path value bound before this freeze was cut and passed on
/// without naming it again; a macro-emitted mention; a path assembled from fragments; a line whose
/// trimmed form starts with `//` (the normalization this comparison relies on); and everything
/// outside `crates/orchard/src/ceremony/`. The driven half is
/// `a_committing_ceremony_writes_nothing_under_the_key_directory`.
#[test]
fn the_declared_space_file_references_under_src_ceremony_are_frozen() {
    const NAMES: &[&str] = &[
        "repo_form_dir",
        "ratified_file",
        ".keys\"",
        "declared_space_body",
    ];
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ceremony");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("read {}: {e}", d.display()))
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    assert!(
        files.len() >= 8,
        "the scan found {} source files under {}, so it is scanning nothing",
        files.len(),
        dir.display()
    );
    files.sort();
    let mut hits: Vec<(String, String)> = Vec::new();
    for p in &files {
        let rel = p
            .strip_prefix(&dir)
            .expect("under the scan root")
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for line in text.lines() {
            let s = line.trim();
            if s.starts_with("//") {
                continue;
            }
            if NAMES.iter().any(|n| s.contains(n)) {
                hits.push((rel.clone(), s.to_string()));
            }
        }
    }
    hits.sort();
                                                                                                   
                                 
    let sample = "std::fs::write(inv.ratified_file(\"executing\"), body)?;";
    assert!(
        NAMES.iter().any(|n| sample.contains(n)),
        "the scanner's predicate does not match its own sample"
    );
    assert!(
        !NAMES.iter().any(|n| "let x = 1;".contains(n)),
        "the scanner's predicate matches a line naming none of the frozen names"
    );

    let want: Vec<(String, String)> = FROZEN_REFERENCES
        .iter()
        .map(|(f, l)| ((*f).to_string(), (*l).to_string()))
        .collect();
    assert_eq!(
        hits, want,
        "the declared-space references under src/ceremony/ moved; re-freeze consciously"
    );
}

/// The frozen set for [`the_declared_space_file_references_under_src_ceremony_are_frozen`]:
/// (file relative to `src/ceremony/`, trimmed source line), sorted.
const FROZEN_REFERENCES: &[(&str, &str)] = &[
    (
        "admission.rs",
        ".join(&Utf8PathBuf::from(format!(\"{checkout}.keys\")))",
    ),
    ("admission.rs", "if let Some(dir) = &self.repo_form_dir {"),
    ("admission.rs", "if let Some(dir) = &self.repo_form_dir {"),
    (
        "admission.rs",
        "let dir = self.repo_form_dir.as_ref().unwrap_or(&default_dir);",
    ),
    (
        "admission.rs",
        "pub fn ratified_file(&self, repo_root: &Utf8PathBuf, checkout: &str) -> Utf8PathBuf {",
    ),
    ("admission.rs", "pub repo_form_dir: Option<Utf8PathBuf>,"),
    ("gate_commit.rs", "file: ratified_file.clone(),"),
    (
        "gate_commit.rs",
        "let ratified = match super::admission::read_ratified(ratified_file) {",
    ),
    (
        "gate_commit.rs",
        "pub fn declared_space_body(repo_root: &Path) -> Result<String, GitRunError> {",
    ),
    ("gate_commit.rs", "ratified_file.display()"),
    ("gate_commit.rs", "ratified_file: &super::Utf8PathBuf,"),
    ("interview.rs", "repo_form_dir: Option<&Utf8PathBuf>,"),
    ("interview.rs", "repo_form_dir: repo_form_dir.cloned(),"),
    ("interview.rs", "repo_form_dir: repo_form_dir.cloned(),"),
    (
        "runner.rs",
        "&inv.ratified_file(&ctx.repo_root, \"executing\"),",
    ),
    (
        "runner.rs",
        "&inv.ratified_file(&ctx.repo_root, super::spine::SiblingId::TenantRepo.token()),",
    ),
];

                                                                                                  
/// an absolute `--repo-form-dir` is used as given.
#[test]
fn ratified_file_bases_under_repo_root_and_an_absolute_override_survives() {
    use orchard::ceremony::Utf8PathBuf;
    use orchard::ceremony::admission::RunInvocation;
    let repo_root = Utf8PathBuf::from("/some/checkout");
    let mut inv = RunInvocation::default();
    assert_eq!(
        inv.ratified_file(&repo_root, "executing").as_str(),
        "/some/checkout/boxes/repo-form/executing.keys"
    );
    assert!(inv.ratified_file(&repo_root, "executing").is_absolute());
    inv.repo_form_dir = Some(Utf8PathBuf::from("custom/dir"));
    assert_eq!(
        inv.ratified_file(&repo_root, "executing").as_str(),
        "/some/checkout/custom/dir/executing.keys"
    );
    inv.repo_form_dir = Some(Utf8PathBuf::from("/abs/dir"));
    assert_eq!(
        inv.ratified_file(&repo_root, "tenant-repo").as_str(),
        "/abs/dir/tenant-repo.keys"
    );
}

                                                                                                       

/// Turn `root` into a checkout whose HEAD tree is only available from a promisor remote: a bare
/// `file://` donor with `uploadpack.allowFilter`, `remote.origin.partialclonefilter` set with NO
                                                                                                   
/// object store. Returns HEAD's tree oid.
fn make_promisor_tree_missing(root: &Path, donor: &Path) -> String {
    git_out(
        root,
        &["clone", "-q", "--bare", ".", &donor.to_string_lossy()],
    );
    git_out(donor, &["config", "uploadpack.allowfilter", "true"]);
    git_out(
        root,
        &[
            "remote",
            "add",
            "origin",
            &format!("file://{}", donor.display()),
        ],
    );
    git_out(
        root,
        &["config", "remote.origin.partialclonefilter", "tree:0"],
    );
    let t_head = git_out(root, &["rev-parse", "HEAD^{tree}"]);
    let listing = git_out(
        root,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        ],
    );
    let mut removed = 0usize;
    for line in listing.lines() {
        let mut it = line.split_whitespace();
        let (Some(oid), Some(kind)) = (it.next(), it.next()) else {
            continue;
        };
        if kind != "tree" {
            continue;
        }
        let p = root.join(format!(".git/objects/{}/{}", &oid[..2], &oid[2..]));
        if std::fs::remove_file(&p).is_ok() {
            removed += 1;
        }
    }
    assert!(
        removed > 0,
        "no loose tree object was removed, so nothing is missing from the object store"
    );
    t_head
}

/// True when `oid` is present in `root`'s object store without contacting a promisor remote.
fn object_present_locally(root: &Path, oid: &str) -> bool {
    std::process::Command::new("git")
        .current_dir(root)
        .env("GIT_NO_LAZY_FETCH", "1")
        .args(["cat-file", "-e", oid])
        .status()
        .expect("git cat-file")
        .success()
}

                                                                                                 
/// checkout whose HEAD tree exists only at the promisor remote: the gate's first object read fails,
/// the run refuses `git-state-unreadable` before the prompt with HEAD unmoved, and the missing
/// object is STILL missing afterwards (a fetch would have brought it in). The control at the end
/// runs the same read without the belt and shows the object was fetchable all along, so the absence
/// above is the belt's doing and not the fixture's.
#[test]
fn a_promisor_object_the_gate_reads_refuses_instead_of_fetching() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
    ratify_executing(&fx, &i);
    let donor = fx.at("../donor.git");
    let t_head = make_promisor_tree_missing(&fx.root, &donor);
                                                                                              
    ratify_executing(&fx, &i);
    assert!(
        !object_present_locally(&fx.root, &t_head),
        "arm sanity: HEAD's tree is still in the local object store"
    );

    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "git-state-unreadable",
        "the run did not fail closed on the unreadable object: {refusal}"
    );
    assert!(
        refusal.detail.contains("bad tree object"),
        "the refusal does not carry git's own line: {refusal}"
    );
    assert_eq!(git_head(&fx.root), head_before, "HEAD moved");
    assert!(
        !object_present_locally(&fx.root, &t_head),
        "the run fetched the missing tree from the promisor remote"
    );

                                                                                               
    let ok = std::process::Command::new("git")
        .current_dir(&fx.root)
        .args([
            "--no-optional-locks",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ])
        .output()
        .expect("git status")
        .status
        .success();
    assert!(ok, "control: the unbelted read did not succeed");
    assert!(
        object_present_locally(&fx.root, &t_head),
        "control: the unbelted read fetched nothing, so this fixture cannot show a fetch"
    );
}

/// §1.6 / §3.11: the belt is the BUILDER's value, not an inherited one. The role process exports
/// `GIT_NO_LAZY_FETCH=0`; `ceremony_git` strips the inherited `GIT_*` variable and sets its own
/// after, so the gate still refuses on the promisor-only object rather than fetching it. A build
/// order that sets the value before the strip leaves the child with no variable at all.
#[test]
fn the_belt_survives_an_inherited_no_lazy_fetch_value() {
    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "the_belt_survives_an_inherited_no_lazy_fetch_value",
            &["beltdecoy"],
        );
        return;
    };
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
    let donor = fx.at("../donor.git");
    let t_head = make_promisor_tree_missing(&fx.root, &donor);
    ratify_executing(&fx, &i);
    unsafe { std::env::set_var("GIT_NO_LAZY_FETCH", "0") };
    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    let token = run.refusal().id.token();
    let fetched = object_present_locally(&fx.root, &t_head);
    unsafe { std::env::remove_var("GIT_NO_LAZY_FETCH") };
    assert_eq!(
        token, "git-state-unreadable",
        "role {role}: the inherited value defeated the belt"
    );
    assert!(
        !fetched,
        "role {role}: the run fetched the missing tree from the promisor remote"
    );
    assert_eq!(git_head(&fx.root), head_before, "role {role}: HEAD moved");
    println!("{} {role}", roles::ROLE_OK);
}

                                                                                                    

/// The §3.3 `RatifiedUnreadable` cure, as a hand literal: it names the ratified file and the
                                                           
fn cure_ratified_unreadable(file: &str, admit: &str) -> String {
    format!(
        "restore `{file}` from a trusted copy (its git history when the file is tracked), or \
         remove it and run `{admit}` to ratify the current declared space, then re-run"
    )
}

/// Replace the ratified file for `checkout` with one of the three unreadable shapes.
fn plant_unreadable(file: &Path, shape: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::remove_file(file);
    match shape {
        "non-UTF-8 bytes" => std::fs::write(file, b"local\t\xff\n").expect("plant bytes"),
        "a directory" => std::fs::create_dir_all(file).expect("plant a directory"),
        "mode 000" => {
            std::fs::write(file, "local\tzz.k\n").expect("plant a file");
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000))
                .expect("chmod 000");
        }
        other => panic!("unknown shape {other}"),
    }
}

/// §3.3 / floor row C'2: a ratified declared-space file that exists and cannot be read stops the
/// gate `repository-form-unmodelled` through `RatifiedUnreadable`, naming the file and the error.
///
/// What it claims: over the three shapes delta §0.3 measured (bytes outside UTF-8, a directory at
/// the path, mode 000), the whole composed refusal is the hand literal below, HEAD is unmoved and
/// the planted file is still in place. What it does NOT claim: that every `std::io::Error` kind
/// routes to `Io` — the three shapes exercise `NonUtf8`, `EISDIR` and `EACCES`, and the other kinds
/// take the same `Err(e)` arm unmeasured. Blind spots, named: the error text is the host libc's
/// (`Is a directory (os error 21)`, `Permission denied (os error 13)`), so another libc or locale
/// reddens the literal; a run as root can read a file whose mode grants nobody read, which reddens
/// the third leg's own sanity assert rather than passing it.
#[test]
fn an_unreadable_ratified_file_stops_the_gate_naming_the_file_and_the_error() {
    for shape in ["non-UTF-8 bytes", "a directory", "mode 000"] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        ratify_executing(&fx, &i);
        let file = i.ratified_file(&fx.ctx.repo_root, "executing");
        plant_unreadable(&file, shape);
        let head_before = git_head(&fx.root);

                                                                                       
        let err = std::fs::read_to_string(&file)
            .err()
            .map(|e| e.to_string())
            .or_else(|| {
                std::fs::read(&file)
                    .ok()
                    .map(|_| "read as bytes".to_string())
            });
        assert!(
            err.is_some(),
            "{shape}: the planted file reads back fine, so this leg proves nothing"
        );

        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        let rendered = match shape {
            "non-UTF-8 bytes" => {
                format!("{}: bytes outside UTF-8 (local\\t\\xff)", file.display())
            }
            "a directory" => format!("{}: Is a directory (os error 21)", file.display()),
            "mode 000" => format!("{}: Permission denied (os error 13)", file.display()),
            other => panic!("unknown shape {other}"),
        };
        assert_eq!(
            run.refusal().to_string(),
            composed(
                "repository-form-unmodelled",
                &format!(
                    "the executing checkout's ratified declared-space file exists and cannot be \
                     read: {rendered}"
                ),
                &cure_ratified_unreadable(file.as_str(), &i.admit_command(&fx.ctx)),
            ),
            "{shape}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{shape}: HEAD moved on a pre-prompt refusal"
        );
        assert!(
            file.symlink_metadata().is_ok(),
            "{shape}: the refused run removed the planted file"
        );
    }
}

                                                                                                  
/// `RatifiedUnreadable` cure names the file, the trusted-copy route and the composed `admit`
/// command, and does not send the operator to the repository history as the sole route.
///
/// What it claims: with the declared-space directory an absolute tempdir outside the checkout —
/// the configuration `RunInvocation::ratified_file`'s own doc admits, where `Path::join` drops the
/// repo root — the gate stops `repository-form-unmodelled` with HEAD unmoved and the whole
/// composed refusal equals the hand literal below, whose `admit` command is written out here from
/// the fixture's five values rather than taken from `admit_command`. The pre-fold cure's route
/// ("restore `{file}` from the repository history") is a false instruction for this file, and the
/// arm asserts that phrase absent. What it does NOT claim: the three unreadable SHAPES
/// (`an_unreadable_ratified_file_stops_the_gate_naming_the_file_and_the_error` drives them over
/// the default directory), the `admit` command's parse (row E3's arm), or that `orchard admit`
/// over this directory ratifies the file. Blind spots, named: this is one configuration, so the
/// cure's text is held here for the outside-the-checkout case and by the standing arm for the
/// inside case; the error text is the host libc's; the tempdir path is asserted to lie inside
/// §2.3's bare set, so the hand literal's unquoted spelling is the expected rendering.
#[test]
fn the_unreadable_cure_over_a_directory_outside_the_checkout_names_a_trusted_copy() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let outside = tempfile::tempdir().expect("a declared-space directory outside the checkout");
    i.repo_form_dir = Some(u8p(outside.path()));
    let dir = i.repo_form_dir.clone().expect("just set");
    let file = i.ratified_file(&fx.ctx.repo_root, "executing");

                                                                                              
                                             
    assert!(
        !file.as_str().starts_with(fx.ctx.repo_root.as_str()),
        "the ratified file {file} is inside the checkout {}, so this arm drives the standing \
         arm's configuration",
        fx.ctx.repo_root
    );
                                                                                                   
                                                                             
    let bare = |t: &str| {
        t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:=+@%,-".contains(&b))
    };
    for v in [
        i.profile_path.as_str(),
        dir.as_str(),
        fx.ctx.repo_root.as_str(),
        fx.ctx.artifact_store.as_str(),
        fx.ctx.repo_manifest.as_str(),
    ] {
        assert!(
            bare(v),
            "the fixture value {v:?} renders quoted, so the literal below is wrong"
        );
    }
    let admit = format!(
        "orchard admit --box {} --repo-form-dir {} --repo-root {} --artifact-store {} \
         --repo-manifest {}",
        i.profile_path, dir, fx.ctx.repo_root, fx.ctx.artifact_store, fx.ctx.repo_manifest
    );

    ratify_executing(&fx, &i);
    plant_unreadable(file.as_path(), "non-UTF-8 bytes");
    let head_before = git_head(&fx.root);
    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    assert_eq!(
        run.refusal().id.token(),
        "repository-form-unmodelled",
        "the stop is not the declared-space gate's"
    );
    assert_eq!(
        run.refusal().to_string(),
        composed(
            "repository-form-unmodelled",
            &format!(
                "the executing checkout's ratified declared-space file exists and cannot be read: \
                 {}: bytes outside UTF-8 (local\\t\\xff)",
                file.display()
            ),
            &cure_ratified_unreadable(file.as_str(), &admit),
        ),
    );
    assert!(
        !run.refusal().cure().as_str().contains("repository history"),
        "the cure sends the operator to the repository history for a file outside the checkout: {}",
        run.refusal().cure().as_str()
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved on a pre-prompt refusal"
    );
}

                                                                                                     

/// The `orchard admit` command a §1.4 cure carries: the backtick-quoted span that opens with the
/// program name. `RatifiedUnreadable` quotes the ratified file first, so the span is chosen by its
/// opening and not by position.
fn admit_in(cure: &str) -> &str {
    let quoted: Vec<&str> = cure
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|s| s.starts_with("orchard admit "))
        .collect();
    assert_eq!(
        quoted.len(),
        1,
        "the cure carries {} backtick-quoted admit commands: {cure:?}",
        quoted.len()
    );
    quoted[0]
}

/// Row E3's oracle, as delta v3.6 §5 row G2 re-cuts it: the admit command a cure prints, split by
/// the shell that will receive it and then read by the parser.
fn parse_printed_admit(printed: &str) -> orchard::cli::Cli {
    use clap::Parser as _;
    let tokens = shell_split::shell_split(printed);
    let argv: Vec<&str> = std::iter::once("orchard")
        .chain(tokens.iter().map(String::as_str))
        .collect();
    orchard::cli::Cli::try_parse_from(&argv)
        .unwrap_or_else(|e| panic!("the printed admit command does not parse: {e}\n{printed:?}"))
}

/// Delta v3.5 §6 row E3: each of the three declared-space cures carries an `orchard admit` command
/// that clap parses to THIS invocation's profile and declared-space directory over THIS run's
/// resolved context.
///
/// What it claims: over a non-default declared-space directory and a flag-tier repo root, the
/// `NoDeclaredSpace`, `DeclaredSpaceDelta` and `RatifiedUnreadable` cures each carry a
/// backtick-quoted command whose parse is an `Admit` whose `--box` equals the invocation's profile
/// path and whose `--repo-form-dir` equals the invocation's directory, with the three globals equal
/// to the resolved context; and the `RatifiedUnreadable` cure names the ratified file's path and
/// carries no `<dir>` placeholder. The oracle is clap over the printed tokens, so a cure that named
/// a directory the run did not use reds this arm; the three standing cure arms compare a hand
/// sentence whose `{admit}` slot is filled by `i.admit_command(&fx.ctx)`, the composer under test.
/// What it does NOT claim: the cure sentences around the command (the standing arms'), that
/// `orchard admit` run with these arguments ratifies the file (`ceremony_utf8_argv.rs`'s row E6),
/// or that these are the only cures naming `admit`. Blind spots, named: the fixture's paths carry
/// no character outside §2.3's bare set, so the reading exercises the composer's bare rendering
/// only (`ceremony_interview.rs`'s row G2 arm drives the quoted classes); the fixture's directory
/// is absolute, so a relative `--repo-form-dir` is unmeasured here.
#[test]
fn every_declared_space_cure_carries_an_admit_command_clap_parses_to_this_invocation() {
                                                                               
    for leg in ["no declared space", "delta", "unreadable"] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let dir = i
            .repo_form_dir
            .clone()
            .expect("the gate fixture carries a declared-space directory");
        let file = i.ratified_file(&fx.ctx.repo_root, "executing");
                                                                                                  
                                                                                            
        assert!(
            !dir.as_str().ends_with("boxes/repo-form"),
            "{leg}: the fixture ratifies the default directory, so this arm proves nothing"
        );
        assert!(
            matches!(
                fx.ctx.sources.repo_root,
                orchard::deploy::context::ValueSource::Flag
            ),
            "{leg}: the fixture's repo root is not the flag tier's"
        );
        match leg {
            "no declared space" => {}
            "delta" => {
                ratify_executing(&fx, &i);
                git_out(&fx.root, &["config", "floor.local", "1"]);
            }
            "unreadable" => {
                ratify_executing(&fx, &i);
                plant_unreadable(&file, "non-UTF-8 bytes");
            }
            other => panic!("unknown leg {other}"),
        }
        let head_before = git_head(&fx.root);
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "repository-form-unmodelled",
            "{leg}: the stop is not the declared-space gate's"
        );
        let cure = refusal.cure().as_str().to_string();
                                                                                          
        let marker = match leg {
            "no declared space" => "has no operator-ratified declared space",
            "delta" => "differs from its ratified declared space",
            "unreadable" => "restore `",
            other => panic!("unknown leg {other}"),
        };
        assert!(
            cure.contains(marker),
            "{leg}: the cure is another condition's: {cure:?}"
        );
        let cli = parse_printed_admit(admit_in(&cure));
        assert_eq!(cli.repo_root.as_ref(), Some(&fx.ctx.repo_root), "{leg}");
        assert_eq!(
            cli.artifact_store.as_ref(),
            Some(&fx.ctx.artifact_store),
            "{leg}"
        );
        assert_eq!(
            cli.repo_manifest.as_ref(),
            Some(&fx.ctx.repo_manifest),
            "{leg}"
        );
        assert_eq!(cli.context, None, "{leg}: no --context is composed");
                                                                                                   
                                                  
        let orchard::cli::OrchardCmd::Admit {
            box_profile,
            repo_form_dir,
        } = cli.command
        else {
            panic!("{leg}: the printed command is not an `admit`: {cure:?}");
        };
        assert_eq!(box_profile, i.profile_path, "{leg}");
        assert_eq!(repo_form_dir, Some(dir.clone()), "{leg}");
        if leg == "unreadable" {
            assert!(
                cure.contains(file.as_str()),
                "the unreadable cure does not name the ratified file: {cure:?}"
            );
            assert!(
                !cure.contains("<dir>"),
                "the unreadable cure carries a placeholder: {cure:?}"
            );
        }
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{leg}: HEAD moved on a pre-prompt refusal"
        );
    }
}

                                                                                 
/// `core.fsmonitor = old`, the configuration then moved to `new`, and a stale file in the DEFAULT
/// directory measured at `new`. A run against the default directory passes the gate; a run against
/// the operator's directory meets the delta.
fn staged_two_directories() -> (
    Fixture,
    orchard::ceremony::records::RunRecords,
    orchard::ceremony::admission::Admitted,
    orchard::ceremony::admission::RunInvocation,
    orchard::deploy::profile::Profile,
) {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let audited = fx.root.join("boxes/audited-form");
    std::fs::create_dir_all(&audited).expect("mk audited");
    i.repo_form_dir = Some(u8p(&audited));
    git_out(&fx.root, &["config", "core.fsmonitor", "old"]);
    ratify_executing(&fx, &i);
    git_out(&fx.root, &["config", "core.fsmonitor", "new"]);
    let default_dir = fx.root.join("boxes/repo-form");
    std::fs::create_dir_all(&default_dir).expect("mk default");
    std::fs::write(
        default_dir.join("executing.keys"),
        declared_space_body(&fx.root).expect("measure the checkout"),
    )
    .expect("write the default directory's file");
    (fx, records, admitted, i, profile)
}

/// Delta v3.5 §6 row E4: the invocation reconstructed from a printed resume command meets the
/// operator's own ratified declared space, not the stale file in the default directory.
///
                                                                                               
/// through clap back into an invocation and driving the gate with it refuses
/// `repository-form-unmodelled` with HEAD unmoved; the control, the same fixture driven with the
/// invocation a resume command that dropped `--repo-form-dir` reconstructs, COMMITS. The oracle is
/// the run's own outcome read from git (HEAD before and after), not the text of any command. What
/// it does NOT claim: that the resume command's fields are right — `ceremony_runner.rs`'s row E2
/// arms hold that — only that resuming lands the operator back on the same ratified file. Blind
/// spot, named: the reconstruction happens in-process through clap, not by a spawned child.
#[test]
fn the_resumed_invocation_meets_the_operators_own_ratified_declared_space() {
    use clap::Parser as _;

    let (fx, mut records, admitted, i, profile) = staged_two_directories();
                                                                                                
                                                                                   
    let current = declared_space_body(&fx.root).expect("measure the checkout");
    assert_eq!(
        std::fs::read_to_string(fx.root.join("boxes/repo-form/executing.keys")).expect("read"),
        current,
        "the default directory's file does not match the current configuration"
    );
    assert_ne!(
        std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing").as_path())
            .expect("read"),
        current,
        "the operator's ratified file already matches, so the resumed run meets no delta"
    );

    let printed = i.resume_command(&fx.ctx);
    let tokens = shell_split::shell_split(&printed);
    let argv: Vec<&str> = std::iter::once("orchard")
        .chain(tokens.iter().map(String::as_str))
        .collect();
    let cli = orchard::cli::Cli::try_parse_from(&argv)
        .unwrap_or_else(|e| panic!("the printed resume command does not parse: {e}\n{printed:?}"));
    let orchard::cli::OrchardCmd::Run {
        profile: parsed_profile,
        target,
        image_version,
        commit,
        wipe_confirmed,
        porcelain,
        repo_form_dir,
    } = cli.command
    else {
        panic!("the printed resume command is not a `run`: {printed:?}");
    };
    let mut judgment = std::collections::BTreeMap::new();
    if let Some(v) = image_version {
        judgment.insert("image_version".to_string(), v.to_string());
    }
    let resumed = orchard::ceremony::admission::RunInvocation {
        profile_path: parsed_profile,
        target,
        judgment,
        commit,
        wipe_confirmed,
        porcelain,
        repo_form_dir,
    };

    let head_before = git_head(&fx.root);
    let prompt = || panic!("the forwarded token commits with no prompt");
    let run = run_gate_preratified(
        &fx,
        &mut records,
        &admitted,
        &resumed,
        &profile,
        false,
        &prompt,
    );
    assert_eq!(
        run.refusal().id.token(),
        "repository-form-unmodelled",
        "the resumed run did not meet the operator's ratified declared space"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved on a pre-prompt refusal"
    );

                                                                                                
                                                                                                
    let (fx2, mut records2, admitted2, i2, profile2) = staged_two_directories();
    let mut dropped = i2.clone();
    dropped.repo_form_dir = None;
    let head_before2 = git_head(&fx2.root);
    let prompt2 = || panic!("the forwarded token commits with no prompt");
    let run2 = run_gate_preratified(
        &fx2,
        &mut records2,
        &admitted2,
        &dropped,
        &profile2,
        false,
        &prompt2,
    );
    assert!(
        run2.outcome.is_ok(),
        "control: the default-directory invocation did not commit: {:?}",
        run2.outcome.as_ref().err().map(ToString::to_string)
    );
    assert_ne!(
        git_head(&fx2.root),
        head_before2,
        "control: the default-directory invocation left HEAD unmoved, so the arm above proves \
         nothing about the directory"
    );
}

/// §3.3 / floor row C'2: `orchard admit` over the same three shapes prints the error, exits
/// non-zero and writes nothing for any checkout; an absent file is the first ratification.
///
/// What it claims: for each shape the built binary exits non-zero, prints
/// `admit: cannot read the ratified file for executing: <path>: <error>; nothing written`, reaches
/// no authorize prompt, and leaves the key directory byte-identical; and over an absent file the
/// same binary prints the first-ratification header and writes the sorted measured body. What it
/// does NOT claim: the behaviour at a second checkout — these fixtures resolve no `tenant-repo`
/// sibling. The absent-file leg compares the child's write against an in-process measurement, so
/// the arm runs in a role process pinned at empty `global`/`system` files, which is the pin
                                                                                                
/// libc's, as in the gate arm above.
#[test]
fn admit_stops_on_an_unreadable_ratified_file_and_first_ratifies_an_absent_one() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "admit_stops_on_an_unreadable_ratified_file_and_first_ratifies_an_absent_one",
            &["ratifiedread"],
        );
        return;
    };
    let pin = tempfile::tempdir().expect("tempdir");
    roles::pin_empty_git_config(pin.path());

    for shape in ["non-UTF-8 bytes", "a directory", "mode 000"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, profile, dir) = admit_fixture(tmp.path());
        let file = dir.join("executing.keys");
        plant_unreadable(&file, shape);
                                                                                                  
                                                                   
        if shape == "mode 000" {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        }
        let before = dir_snapshot(&dir);
        if shape == "mode 000" {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        }

        let (ok, text) = admit::run_admit(&root, &profile, &dir, "admit\n");
        assert!(
            !ok,
            "{shape}: admit exited 0 over an unreadable file:\n{text}"
        );
        let rendered = match shape {
            "non-UTF-8 bytes" => {
                format!("{}: bytes outside UTF-8 (local\\t\\xff)", file.display())
            }
            "a directory" => format!("{}: Is a directory (os error 21)", file.display()),
            "mode 000" => format!("{}: Permission denied (os error 13)", file.display()),
            other => panic!("unknown shape {other}"),
        };
        assert!(
            text.contains(&format!(
                "admit: cannot read the ratified file for executing: {rendered}; nothing written"
            )),
            "{shape}: admit does not print the read error:\n{text}"
        );
        assert!(
            !text.contains("type `admit`"),
            "{shape}: admit reached the authorize prompt:\n{text}"
        );
        if shape == "mode 000" {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
                .expect("restore the mode for the comparison");
        }
        assert_eq!(
            dir_snapshot(&dir),
            before,
            "{shape}: the refused admit changed the key directory"
        );
    }

                                               
    let tmp = tempfile::tempdir().expect("tempdir");
    let (root, profile, dir) = admit_fixture(tmp.path());
    let file = dir.join("executing.keys");
    assert!(
        !file.exists(),
        "the fixture already carries a ratified file, so this leg proves nothing"
    );
    let (ok, text) = admit::run_admit(&root, &profile, &dir, "admit\n");
    assert!(ok, "the first admit did not exit 0:\n{text}");
    assert!(
        text.contains(&format!(
            "declared space for executing ({}): no ratified file, first ratification",
            root.display()
        )),
        "admit does not print the first-ratification header:\n{text}"
    );
    assert_eq!(
        std::fs::read_to_string(&file).expect("read the written file"),
        declared_space_body(&root).expect("measure"),
        "role {role}: the written file is not the measured declared space"
    );
    println!("{} {role}", roles::ROLE_OK);
}

/// A scratch orchard checkout `admit` accepts: the repo-root recognizer's directory, a manifest, a
/// box profile and an empty key directory.
fn admit_fixture(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let root = tmp.join("repo");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(&root, &args);
    }
    std::fs::write(root.join("repo-manifest.toml"), "schema-version = 1\n").expect("manifest");
    let profile = tmp.join("alpha.toml");
    std::fs::write(&profile, "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n").expect("profile");
    let dir = tmp.join("repo-form");
    std::fs::create_dir_all(&dir).expect("mk repo-form");
    (root, profile, dir)
}
