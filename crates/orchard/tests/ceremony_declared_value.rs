//! R16 fold-4 §2 floor arms: the declared space's value axis and its strict per-field decode.
//! Every arm drives the production path (`run_ceremony`, `declared_space_body`, or the built
//! `orchard` binary) over a real checkout, and reads its oracle from a hand literal or from `git`
//! itself. The §1 arms (the key set, the scopes, `admit`'s write) are in
//! `ceremony_declared_space.rs`.

                                                                                                   
#[allow(dead_code)]
#[path = "common/admit.rs"]
mod admit;
#[allow(dead_code)]
#[path = "ceremony_gate_commit/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/roles.rs"]
mod roles;

use std::collections::BTreeSet;
use std::path::Path;

use fixture::*;
use orchard::ceremony::gate_commit::{
    VALUE_SENSITIVE_EXACT, VALUE_SENSITIVE_PATTERNED, declared_space_body, is_value_sensitive,
};

/// The §2.3 delta cure, as a hand literal carrying the invocation's own `orchard admit` command
                                                                                                   
/// itself (M-R16-1b's class).
fn cure_delta(admit: &str) -> String {
    format!(
        "the executing checkout's effective git configuration differs from its ratified declared \
         space (the delta is in the detail: keys at every scope, and values at the program-valued \
         keys); revert the configuration, or run `{admit}` to ratify the shown delta, then re-run"
    )
}

/// The §2.3 unreadable cure over one rendered `GitRunError`, as a hand literal.
fn cure_unreadable(e: &str) -> String {
    format!(
        "the ceremony could not read the checkout's git configuration listing ({e}); repair what \
         git names, then re-run"
    )
}

/// `GitRunError::NonUtf8Output`'s `Display` for the declared-space read, as a hand literal.
fn nonutf8_error(sample: &str) -> String {
    format!("`git config --list --show-scope --null` emitted bytes outside UTF-8 ({sample})")
}

/// The composed operator text of a refusal, as `Refusal`'s `Display` writes it.
fn composed(id: &str, detail: &str, cure: &str) -> String {
    format!("refusal ({id}): {detail}\n  cure: {cure}")
}

/// The composed text of the §2.2 fail-closed refusal for one lossy sample.
fn unreadable_refusal(sample: &str) -> String {
    let e = nonutf8_error(sample);
    composed(
        "repository-form-unmodelled",
        &format!("cannot read the executing checkout's git configuration listing: {e}"),
        &cure_unreadable(&e),
    )
}

/// The composed text of a §2.3 declared-space delta naming one removed and one added line.
fn delta_refusal(removed_line: &str, added_line: &str, admit: &str) -> String {
    let added = format!("[{added_line:?}]");
    let removed = format!("[{removed_line:?}]");
    composed(
        "repository-form-unmodelled",
        &format!(
            "the executing checkout's declared space differs from the ratified file: added \
             {added}, removed {removed}"
        ),
        &cure_delta(admit),
    )
}

/// Replace the first occurrence of `needle` in `file` with `raw`, as bytes: a git config value or
/// subsection outside UTF-8 cannot be written through `git config`.
fn plant_bytes(file: &Path, needle: &[u8], raw: &[u8]) {
    let bytes = std::fs::read(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| {
            panic!(
                "{} carries no {:?}",
                file.display(),
                String::from_utf8_lossy(needle)
            )
        });
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(raw);
    out.extend_from_slice(&bytes[at + needle.len()..]);
    std::fs::write(file, out).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
}

/// Append raw bytes to a config file, creating it when absent.
fn append_bytes(file: &Path, raw: &[u8]) {
    let mut bytes = std::fs::read(file).unwrap_or_default();
    bytes.extend_from_slice(raw);
    std::fs::write(file, bytes).unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
}

                                                                                                      

/// §2.2 / row B6: the value column's rendering, over a scratch checkout whose `local` scope carries
/// one key of each shape the delta names.
///
/// What it claims: for this fixture's configuration, the `local` lines of `declared_space_body`
/// that carry a value column are exactly the five below, in that order, and the keys-only keys
/// carry no third field; two measurements of one state are byte-equal. The expected lines are hand
/// literals, so a mutation that drops the `Debug` escape (an LF or tab value then breaks the line
/// form), drops the value column, folds a multivalued key's records into one line, or renders a
/// valueless record as `""` reddens it. What it does NOT claim: anything about a configuration
/// shape this fixture does not carry, or about the `global`, `system` and `worktree` scopes — the
/// assertion is over the `local` projection, so a host `~/.gitconfig` or `/etc/gitconfig` cannot
                                                                           
/// `the_measured_key_set_is_gits_scope_qualified_keys_sorted_deduplicated_without_values`
/// (`ceremony_declared_space.rs`).
#[test]
fn the_value_column_renders_one_escaped_line_per_value_and_is_byte_stable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
                                                                      
        vec!["config", "core.fsmonitor", "a\tb\nc"],
                                                                                               
        vec!["config", "gpg.program", ""],
                                                                      
        vec!["config", "--add", "hook.zz.event", "post-index-change"],
        vec!["config", "--add", "hook.zz.event", "reference-transaction"],
                                                               
        vec!["config", "zz.keysonly", "a\tb"],
    ] {
        git_out(&root, &args);
    }
                                                                                
    append_bytes(&root.join(".git/config"), b"[core]\n\thookspath\n");

    let cfg = root.join(".git/config");
    let raw = git_out(&root, &["config", "--list", "--show-scope", "--null"]);
    assert_eq!(
        raw.matches("hook.zz.event").count(),
        2,
        "git listed one record for the multivalued key, so the line-per-value claim is untested: \
         {raw:?}"
    );
    assert!(
        std::fs::read_to_string(&cfg)
            .expect("read config")
            .contains("\thookspath\n"),
        "the valueless record is not in the config file, so its claim is untested"
    );

    let body = declared_space_body(&root).expect("measure the scratch checkout");
    let again = declared_space_body(&root).expect("measure the scratch checkout twice");
    assert_eq!(
        body, again,
        "two measurements of one state are not byte-equal"
    );

    let value_lines: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("local\t") && l.split('\t').count() == 3)
        .collect();
    let want = vec![
        "local\tcore.fsmonitor\t\"a\\tb\\nc\"",
        "local\tcore.hookspath\t",
        "local\tgpg.program\t\"\"",
        "local\thook.zz.event\t\"post-index-change\"",
        "local\thook.zz.event\t\"reference-transaction\"",
    ];
    assert_eq!(
        value_lines, want,
        "the local value-column lines are not the frozen five:\n{body}"
    );
    let keys_only: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("local\tzz.keysonly"))
        .collect();
    assert_eq!(
        keys_only,
        vec!["local\tzz.keysonly"],
        "a keys-only key carries a value column:\n{body}"
    );
}

                                                                                                      

/// §2.2 / row B2: a value outside UTF-8 is refused at a value-sensitive key and admitted at a
/// keys-only key, which is the boundary the measured domain draws.
///
/// Two legs, both driving `run_ceremony` over a real checkout: `user.nick` (keys-only) holding
/// `a\xffb` commits, and `core.fsmonitor` (value-sensitive) holding the same bytes after
/// ratification refuses `repository-form-unmodelled` with the composed unreadable text, HEAD
/// unmoved.
#[test]
fn a_non_utf8_value_refuses_only_at_a_value_sensitive_key() {
                                                                       
    let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
        git_out(root, &["config", "user.nick", "ZZVALUEZZ"]);
    });
    plant_bytes(&fx.root.join(".git/config"), b"ZZVALUEZZ", b"a\xffb");
    let owed = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
                                                                                     
    let body = declared_space_body(&fx.root).expect("a keys-only non-UTF-8 value is measurable");
    assert!(
        body.lines().any(|l| l == "local\tuser.nick"),
        "the keys-only key is not in the measured space, so this leg proves nothing:\n{body}"
    );
    ratify_executing(&fx, &i);
    let prompt = || panic!("the forwarded token commits with no prompt");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    run.outcome.unwrap_or_else(|e| {
        panic!("a non-UTF-8 value at a keys-only key is not a declared-space refusal: {e}")
    });
    assert_ne!(git_head(&fx.root), head_before, "the run committed nothing");
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        owed,
        "the commit changed a path outside the owed set"
    );

                                                                                              
    let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
        git_out(root, &["config", "core.fsmonitor", "false"]);
    });
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let head_before = git_head(&fx.root);
    ratify_executing(&fx, &i);
                                                                                               
                                                          
    let ratified =
        std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
    assert!(
        ratified
            .lines()
            .any(|l| l == "local\tcore.fsmonitor\t\"false\""),
        "the ratified space has no value line for the key:\n{ratified}"
    );
    git_out(&fx.root, &["config", "core.fsmonitor", "ZZVALUEZZ"]);
    plant_bytes(&fx.root.join(".git/config"), b"ZZVALUEZZ", b"a\xffb");
    let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
    let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
    assert_eq!(
        run.refusal().to_string(),
        unreadable_refusal("a\\xffb"),
        "the value-sensitive leg does not refuse with the composed unreadable text"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved on a pre-prompt refusal"
    );
}

                                                                                                      

/// The subsection every patterned form of §2.1 is instantiated with in this file.
const SUB: &str = "zz";

/// §2.1 / row B3: a value swap at each of the sixteen forms of the value-sensitive tables refuses
/// `repository-form-unmodelled` naming the removed and added value lines.
///
/// The leg set is compared to the crate's own tables by exact-set equality, so a member added to or
/// removed from `VALUE_SENSITIVE_EXACT` or `VALUE_SENSITIVE_PATTERNED` reddens this arm before any
/// leg runs. Each leg ratifies with the key at `zz-old`, swaps to `zz-new`, and drives
/// `run_ceremony`; git executes neither value, because the gate refuses at the declared-space
/// comparison before any status, hook or commit runs.
#[test]
fn a_value_swap_at_each_value_sensitive_form_refuses_naming_the_value_lines() {
    let mut legs: Vec<String> = VALUE_SENSITIVE_EXACT
        .iter()
        .map(|k| k.to_string())
        .collect();
    legs.extend(
        VALUE_SENSITIVE_PATTERNED
            .iter()
            .map(|(s, v)| format!("{s}.{SUB}.{v}")),
    );
    let leg_set: BTreeSet<&str> = legs.iter().map(String::as_str).collect();
    assert_eq!(
        leg_set.len(),
        16,
        "the §2.1 tables name {} distinct forms, not the sixteen this arm drives: {leg_set:?}",
        leg_set.len()
    );

    for key in &legs {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        git_out(&fx.root, &["config", key, "zz-old"]);
        ratify_executing(&fx, &i);
        let removed_line = format!("local\t{key}\t\"zz-old\"");
        let ratified =
            std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
        assert!(
            ratified.lines().any(|l| l == removed_line),
            "form {key}: the ratified space has no value line {removed_line:?}:\n{ratified}"
        );
        git_out(&fx.root, &["config", key, "zz-new"]);
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        assert_eq!(
            run.refusal().to_string(),
            delta_refusal(
                &removed_line,
                &format!("local\t{key}\t\"zz-new\""),
                &i.admit_command(&fx.ctx)
            ),
            "form {key}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "form {key}: HEAD moved on a pre-prompt refusal"
        );
    }
}

/// §2.1 / row B3: the four membership boundaries of `is_value_sensitive`, each driven through the
/// gate by a value swap. `filter.clean` (no subsection) and `filter..clean` (an empty subsection)
/// are keys-only, so their swap commits; `filter.a.b.clean` (a subsection carrying a dot) is
/// value-sensitive, so its swap refuses; `gpg.OpenPGP.program` is a different key from the table's
/// `gpg.openpgp.program` (git keeps the subsection's case), so its swap commits.
#[test]
fn the_membership_boundaries_of_the_value_sensitive_tables_hold_at_the_gate() {
                                                                                                 
    let legs: Vec<(&str, &str, bool, bool)> = vec![
        ("no subsection", "filter.clean", false, false),
        ("empty subsection", "filter..clean", true, false),
        ("dotted subsection", "filter.a.b.clean", false, true),
        ("cased subsection", "gpg.OpenPGP.program", false, false),
    ];
    for (label, key, raw, sensitive) in legs {
        assert_eq!(
            is_value_sensitive(key),
            sensitive,
            "leg {label}: the tables disagree with this arm's expectation for {key}"
        );
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let owed = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        let cfg = fx.root.join(".git/config");
        if raw {
            append_bytes(&cfg, b"[filter \"\"]\n\tclean = zz-old\n");
        } else {
            git_out(&fx.root, &["config", key, "zz-old"]);
        }
        ratify_executing(&fx, &i);
        let ratified =
            std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
        let keys_only_line = format!("local\t{key}");
        let value_line = format!("local\t{key}\t\"zz-old\"");
        let want_line = if sensitive {
            &value_line
        } else {
            &keys_only_line
        };
        assert!(
            ratified.lines().any(|l| l == want_line),
            "leg {label}: the ratified space has no {want_line:?} line:\n{ratified}"
        );
        if raw {
            plant_bytes(&cfg, b"zz-old", b"zz-new");
        } else {
            git_out(&fx.root, &["config", key, "zz-new"]);
        }
        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        if sensitive {
            assert_eq!(
                run.refusal().to_string(),
                delta_refusal(
                    &value_line,
                    &format!("local\t{key}\t\"zz-new\""),
                    &i.admit_command(&fx.ctx)
                ),
                "leg {label}"
            );
            assert_eq!(
                git_head(&fx.root),
                head_before,
                "leg {label}: HEAD moved on a pre-prompt refusal"
            );
        } else {
            run.outcome.unwrap_or_else(|e| {
                panic!("leg {label}: a keys-only value swap is not a declared-space refusal: {e}")
            });
            assert_ne!(
                git_head(&fx.root),
                head_before,
                "leg {label}: the run committed nothing"
            );
            assert_eq!(
                git_show_names(&fx.root, "HEAD"),
                owed,
                "leg {label}: the commit changed a path outside the owed set"
            );
        }
    }
}

                                                                                                      

/// One leg of [`a_non_utf8_key_after_ratification_refuses_at_the_gate`]: which config file the
/// plant edits, the ASCII baseline appended before ratification, the bytes appended after it, and
/// the sample the refusal must name.
struct KeyLeg {
    label: &'static str,
    file: &'static str,
    before: Option<&'static [u8]>,
    after: &'static [u8],
    sample: &'static str,
}

/// §2.2 / row B1: a config key carrying bytes outside UTF-8 fails the measurement closed at a
/// RATIFIED checkout, in both `pC16c_7` shapes and at a second scope.
///
/// Three legs, each ratifying an ASCII baseline first, so the refusal cannot be the
/// no-declared-space stop: a key ADDED whose subsection carries `0xff` (`pC16c_7` shape 2), an
/// already-ratified key whose subsection byte is REWRITTEN to `0xff` (shape 1), and the same
/// rewrite at `worktree` scope. What it does NOT claim: the `global` and `system` scopes, whose
/// environment is process-global (`the_declared_space_delta_is_seen_at_every_scope_git_lists` in
/// `ceremony_declared_space.rs` drives those in dedicated processes for the delta).
#[test]
fn a_non_utf8_key_after_ratification_refuses_at_the_gate() {
    let legs = vec![
        KeyLeg {
            label: "added local key",
            file: ".git/config",
            before: None,
            after: b"[remote \"bZZKEYZZ\"]\n\turl = https://two/\n",
            sample: "remote.b\\xff.url",
        },
        KeyLeg {
            label: "swapped local key",
            file: ".git/config",
            before: Some(b"[remote \"aZZKEYZZ\"]\n\turl = https://one/\n"),
            after: b"",
            sample: "remote.a\\xff.url",
        },
        KeyLeg {
            label: "swapped worktree key",
            file: ".git/config.worktree",
            before: Some(b"[wt \"aZZKEYZZ\"]\n\tk = 1\n"),
            after: b"",
            sample: "wt.a\\xff.k",
        },
    ];
    for KeyLeg {
        label,
        file,
        before,
        after,
        sample,
    } in legs
    {
        let worktree = file.ends_with("config.worktree");
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            if worktree {
                git_out(root, &["config", "extensions.worktreeConfig", "true"]);
                git_out(root, &["config", "--worktree", "wt.seed", "1"]);
            }
        });
        let _ = dirty_the_declared_pair(&fx, &mut records);
        i.commit = true;
        let head_before = git_head(&fx.root);
        let cfg = fx.root.join(file);
        if let Some(seed) = before {
            append_bytes(&cfg, seed);
        }
        ratify_executing(&fx, &i);
                                                                                                   
        let ratified =
            std::fs::read_to_string(i.ratified_file(&fx.ctx.repo_root, "executing")).expect("read");
        assert_eq!(
            ratified.contains("ZZKEYZZ"),
            before.is_some(),
            "leg {label}: the ratified baseline does not match this leg's shape:\n{ratified}"
        );
        if !after.is_empty() {
            append_bytes(&cfg, after);
        }
        plant_bytes(&cfg, b"ZZKEYZZ", b"\xff");

                                                                        
        let err = declared_space_body(&fx.root).expect_err("a non-UTF-8 key is not measurable");
        assert_eq!(err.to_string(), nonutf8_error(sample), "leg {label}");

        let prompt = || panic!("this stop is pre-prompt; the prompt must not be reached");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        assert_eq!(
            run.refusal().to_string(),
            unreadable_refusal(sample),
            "leg {label}"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "leg {label}: HEAD moved on a pre-prompt refusal"
        );
    }
}

                                                                                                      

/// A scratch orchard checkout `admit` accepts, with `extra` config applied: the repo-root
/// recognizer's directory, a manifest, a box profile and an empty key directory.
struct AdmitFixture {
    root: std::path::PathBuf,
    profile: std::path::PathBuf,
    dir: std::path::PathBuf,
}

fn admit_root(tmp: &Path, extra: &[(&str, &str)]) -> AdmitFixture {
    let root = tmp.join("repo");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(&root, &args);
    }
    for (k, v) in extra {
        git_out(&root, &["config", k, v]);
    }
    std::fs::write(root.join("repo-manifest.toml"), "schema-version = 1\n").expect("manifest");
    let profile = tmp.join("alpha.toml");
    std::fs::write(&profile, "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n").expect("profile");
    let dir = tmp.join("repo-form");
    std::fs::create_dir_all(&dir).expect("mk repo-form");
    AdmitFixture { root, profile, dir }
}

/// Every path under `dir` with its bytes, for a byte-identity comparison across a run.
fn dir_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
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

/// The v3.2 form of a measured body: every line's value column removed.
fn keys_only_form(body: &str) -> String {
    let mut s = String::new();
    for line in body.lines() {
        let mut f = line.splitn(3, '\t');
        let scope = f.next().unwrap_or_default();
        let key = f.next().unwrap_or_default();
        s.push_str(scope);
        s.push('\t');
        s.push_str(key);
        s.push('\n');
    }
    s
}

/// §2.4 / row B1: `orchard admit` over a checkout carrying a key outside UTF-8 prints git's own
/// error, exits non-zero, and leaves the key directory byte-identical.
#[test]
fn admit_refuses_a_non_utf8_key_and_writes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let f = admit_root(tmp.path(), &[]);
    let (root, profile, dir) = (f.root, f.profile, f.dir);
    let before = dir_bytes(&dir);
    append_bytes(
        &root.join(".git/config"),
        b"[remote \"aZZKEYZZ\"]\n\turl = https://one/\n",
    );
    plant_bytes(&root.join(".git/config"), b"ZZKEYZZ", b"\xff");

    let (ok, text) = admit::run_admit(&root, &profile, &dir, "admit\n");
    assert!(!ok, "admit exited 0 over an unmeasurable checkout:\n{text}");
    assert!(
        text.contains(&format!(
            "cannot measure the executing checkout's declared space: {}",
            nonutf8_error("remote.a\\xff.url")
        )),
        "admit does not print git's own error with the sample:\n{text}"
    );
    assert!(
        !text.contains("type `admit`"),
        "admit reached the authorize prompt over an unmeasurable checkout:\n{text}"
    );
    assert_eq!(
        dir_bytes(&dir),
        before,
        "the refused admit changed the key directory"
    );
}

/// §2.4 / row B5: `admit`'s diff carries the value column at a value-sensitive key and nowhere
/// else.
///
/// Leg 1 ratifies a v3.2-form file (every value column stripped) for a checkout holding
/// `core.fsmonitor`: the diff is exactly the one `-`/`+` pair for that key, and the declined run
/// writes nothing. Leg 2 ratifies the same v3.2 form for a checkout holding no value-sensitive
/// key, where the form is the measurement itself: the diff is empty and nothing is written.
///
/// The ratified baseline is an in-process `declared_space_body`, the diff comes from the spawned
/// `admit`, and the two measurements are compared, so both must see one git configuration. The arm
/// runs in a role process pinned at empty `global`/`system` files from before its first git
                                                                                                 
/// host `command`-scope or `worktree`-scope entry is not pinned away by either half.
#[test]
fn admit_prints_the_value_column_only_at_a_value_sensitive_key() {
    let Some(role) = roles::role() else {
        roles::dispatch_roles(
            "admit_prints_the_value_column_only_at_a_value_sensitive_key",
            &["valuecolumn"],
        );
        return;
    };
                                      
    let tmp = tempfile::tempdir().expect("tempdir");
    roles::pin_empty_git_config(tmp.path());
    let f = admit_root(tmp.path(), &[("core.fsmonitor", "false")]);
    let (root, profile, dir) = (f.root, f.profile, f.dir);
    let body = declared_space_body(&root).expect("measure");
    let v32 = keys_only_form(&body);
    assert_ne!(
        v32, body,
        "the fixture carries no value column, so this leg proves nothing:\n{body}"
    );
    std::fs::write(dir.join("executing.keys"), &v32).expect("write the v3.2 file");
    let before = dir_bytes(&dir);
    let (ok, text) = admit::run_admit(&root, &profile, &dir, "no\n");
    assert!(ok, "the declined admit did not exit 0:\n{text}");
    let diff: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  +") || l.starts_with("  -"))
        .collect();
    assert_eq!(
        diff,
        vec![
            "  +local\tcore.fsmonitor\t\"false\"",
            "  -local\tcore.fsmonitor",
        ],
        "the diff is not the one value-column pair:\n{text}"
    );
    assert!(
        text.contains("nothing written"),
        "the declined run does not say it wrote nothing:\n{text}"
    );
    assert_eq!(
        dir_bytes(&dir),
        before,
        "role {role}: the declined run changed the key directory"
    );

                                                                          
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let f2 = admit_root(tmp2.path(), &[("zz.keysonly", "1")]);
    let (root2, profile2, dir2) = (f2.root, f2.profile, f2.dir);
    let body2 = declared_space_body(&root2).expect("measure");
    assert!(
        !body2.lines().any(|l| l.split('\t').count() == 3),
        "the second fixture carries a value column, so its empty-diff claim is untested:\n{body2}"
    );
    std::fs::write(dir2.join("executing.keys"), keys_only_form(&body2)).expect("write");
    let before2 = dir_bytes(&dir2);
    let (ok, text) = admit::run_admit(&root2, &profile2, &dir2, "admit\n");
    assert!(ok, "the second admit did not exit 0:\n{text}");
    assert!(
        text.contains("(no change)") && text.contains("nothing written"),
        "a v3.2 file for a checkout without value-sensitive keys is not an empty diff:\n{text}"
    );
    assert_eq!(
        dir_bytes(&dir2),
        before2,
        "role {role}: the no-change run rewrote the key directory"
    );
    println!("{} {role}", roles::ROLE_OK);
}

                                                                                                     

/// What a spy program answers when git runs it.
#[derive(Clone, Copy)]
enum SpyKind {
    /// Log and exit 0, reading no stdin (git holds the fsmonitor hook's stdin open).
    Quiet,
    /// Log, then answer as a signing program does: `SIG_CREATED` on fd 2 and a signature block on
    /// stdout, so `commit-tree -S` completes and the run lands.
    Sign,
    /// Log, then pass stdin through, as a clean filter does.
    Pass,
}

/// Write an executable spy that appends `tag` to `log` and answers per `kind`; return its path.
fn write_spy(dir: &Path, tag: &str, log: &Path, kind: SpyKind) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    let answer = match kind {
        SpyKind::Quiet => "exit 0\n".to_string(),
        SpyKind::Sign => "echo '[GNUPG:] SIG_CREATED B 1 8 00 0 deadbeef' >&2\nprintf -- \
                          '-----BEGIN PGP SIGNATURE-----\\n\\nZmFrZQ==\\n-----END PGP \
                          SIGNATURE-----\\n'\nexit 0\n"
            .to_string(),
        SpyKind::Pass => "exec cat\n".to_string(),
    };
    let path = dir.join(format!("spy-{tag}"));
    std::fs::write(
        &path,
        format!("#!/bin/sh\necho {tag} >> '{}'\n{answer}", log.display()),
    )
    .expect("write spy");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod spy");
    path.display().to_string()
}

/// One candidate of `pF4_1`: the key as git emits it, the spy shape its value names, and the
/// configuration that makes the key live (`@spy` is the spy's path, `@hooks` the hook directory).
struct Cand {
    key: &'static str,
    kind: SpyKind,
    cfg: &'static [(&'static str, &'static str)],
}

/// The `pF4_1` candidate set, each in the arrangement under which its value would be read.
const CANDIDATES: &[Cand] = &[
    Cand {
        key: "core.fsmonitor",
        kind: SpyKind::Quiet,
        cfg: &[("core.fsmonitor", "@spy")],
    },
    Cand {
        key: "core.hookspath",
        kind: SpyKind::Quiet,
        cfg: &[("core.hooksPath", "@hooks")],
    },
    Cand {
        key: "hook.zz.command",
        kind: SpyKind::Quiet,
        cfg: &[
            ("hook.zz.command", "@spy"),
            ("hook.zz.event", "post-index-change"),
        ],
    },
    Cand {
        key: "filter.zz.clean",
        kind: SpyKind::Pass,
        cfg: &[("filter.zz.clean", "@spy")],
    },
    Cand {
        key: "filter.zz.process",
        kind: SpyKind::Pass,
        cfg: &[("filter.zz.process", "@spy")],
    },
    Cand {
        key: "filter.zz.smudge",
        kind: SpyKind::Pass,
        cfg: &[("filter.zz.smudge", "@spy")],
    },
                                                                                                  
    Cand {
        key: "hook.zz.enabled",
        kind: SpyKind::Quiet,
        cfg: &[
            ("hook.zz.command", "@spy"),
            ("hook.zz.event", "post-index-change"),
            ("hook.zz.enabled", "true"),
        ],
    },
                                                                  
    Cand {
        key: "hook.post-index-change.enabled",
        kind: SpyKind::Quiet,
        cfg: &[
            ("hook.zz.command", "@spy"),
            ("hook.zz.event", "post-index-change"),
            ("hook.zz.enabled", "true"),
            ("hook.post-index-change.enabled", "true"),
        ],
    },
                                                                                                   
                                    
    Cand {
        key: "core.attributesfile",
        kind: SpyKind::Pass,
        cfg: &[
            ("filter.zz.clean", "@spy"),
            ("core.attributesFile", "@attrs"),
        ],
    },
                                                                                         
    Cand {
        key: "attr.tree",
        kind: SpyKind::Pass,
        cfg: &[("filter.zz.clean", "@spy"), ("attr.tree", "HEAD")],
    },
    Cand {
        key: "gpg.program",
        kind: SpyKind::Sign,
        cfg: &[("commit.gpgSign", "true"), ("gpg.program", "@spy")],
    },
    Cand {
        key: "gpg.openpgp.program",
        kind: SpyKind::Sign,
        cfg: &[("commit.gpgSign", "true"), ("gpg.openpgp.program", "@spy")],
    },
    Cand {
        key: "gpg.x509.program",
        kind: SpyKind::Sign,
        cfg: &[
            ("commit.gpgSign", "true"),
            ("gpg.format", "x509"),
            ("gpg.x509.program", "@spy"),
        ],
    },
    Cand {
        key: "gpg.ssh.program",
        kind: SpyKind::Sign,
        cfg: &[
            ("commit.gpgSign", "true"),
            ("gpg.format", "ssh"),
            (
                "user.signingKey",
                "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2U",
            ),
            ("gpg.ssh.program", "@spy"),
        ],
    },
    Cand {
        key: "gpg.ssh.defaultkeycommand",
        kind: SpyKind::Sign,
        cfg: &[
            ("commit.gpgSign", "true"),
            ("gpg.format", "ssh"),
            ("gpg.ssh.defaultKeyCommand", "@spy"),
        ],
    },
    Cand {
        key: "core.pager",
        kind: SpyKind::Quiet,
        cfg: &[("core.pager", "@spy")],
    },
    Cand {
        key: "core.editor",
        kind: SpyKind::Quiet,
        cfg: &[("core.editor", "@spy")],
    },
    Cand {
        key: "sequence.editor",
        kind: SpyKind::Quiet,
        cfg: &[("sequence.editor", "@spy")],
    },
    Cand {
        key: "core.sshcommand",
        kind: SpyKind::Quiet,
        cfg: &[("core.sshCommand", "@spy")],
    },
    Cand {
        key: "core.askpass",
        kind: SpyKind::Quiet,
        cfg: &[("core.askPass", "@spy")],
    },
    Cand {
        key: "core.alternaterefscommand",
        kind: SpyKind::Quiet,
        cfg: &[("core.alternateRefsCommand", "@spy")],
    },
    Cand {
        key: "credential.helper",
        kind: SpyKind::Quiet,
        cfg: &[("credential.helper", "!@spy")],
    },
    Cand {
        key: "uploadpack.packobjectshook",
        kind: SpyKind::Quiet,
        cfg: &[("uploadpack.packObjectsHook", "@spy")],
    },
    Cand {
        key: "alias.status",
        kind: SpyKind::Quiet,
        cfg: &[("alias.status", "!@spy")],
    },
    Cand {
        key: "diff.external",
        kind: SpyKind::Quiet,
        cfg: &[("diff.external", "@spy")],
    },
    Cand {
        key: "diff.zz.command",
        kind: SpyKind::Quiet,
        cfg: &[("diff.zz.command", "@spy")],
    },
    Cand {
        key: "diff.zz.textconv",
        kind: SpyKind::Quiet,
        cfg: &[("diff.zz.textconv", "@spy")],
    },
    Cand {
        key: "merge.zz.driver",
        kind: SpyKind::Quiet,
        cfg: &[("merge.zz.driver", "@spy %O %A %B")],
    },
];

/// The §2.1 members whose value selects which execution happens instead of naming a program.
const SELECTORS: &[&str] = &["commit.gpgsign", "gpg.format", "hook.zz.event"];

/// The tracked declared path's committed baseline is six bytes; this run's write keeps that size,
/// so git's stat check is inconclusive and a clean filter must run to answer the dirt scan.
const SAME_SIZE: &[u8] = b"a\nb\nX\n";

/// §2.1 / row B4: the enumeration. Each `pF4_1` candidate is pointed at a spy, ratified, and the
/// production gate is driven over the fixture; the set of candidates whose spy ran must equal the
/// §2.1 tables restricted to the candidates.
///
/// What it claims: at this host's git, under the argv this gate issues, exactly the candidate keys
/// the tables call value-sensitive have a value git executes. Both directions redden: a table
/// member whose spy never runs is a surplus, a candidate that runs and is not in the tables is a
/// deficit, and a table form no candidate covers reddens the coverage assert before any leg runs.
/// Per leg, either the spy ran or the gate landed, so a leg that refused early cannot answer
/// "never ran" vacuously. What it does NOT claim: that no OTHER key outside this candidate set has
/// an executed value — the candidate set is `pF4_1`'s, and a key outside it is unmeasured here.
#[test]
fn the_gate_executes_exactly_the_program_valued_keys_the_tables_name() {
                                                                       
    let candidate_keys: BTreeSet<&str> = CANDIDATES.iter().map(|c| c.key).collect();
    let mut forms: Vec<String> = VALUE_SENSITIVE_EXACT
        .iter()
        .map(|k| k.to_string())
        .collect();
    forms.extend(
        VALUE_SENSITIVE_PATTERNED
            .iter()
            .map(|(s, v)| format!("{s}.{SUB}.{v}")),
    );
    let uncovered: Vec<&String> = forms
        .iter()
        .filter(|f| !SELECTORS.contains(&f.as_str()) && !candidate_keys.contains(f.as_str()))
        .collect();
    assert!(
        uncovered.is_empty(),
        "a §2.1 form no candidate leg covers: {uncovered:?}"
    );

    let mut ran: BTreeSet<&str> = BTreeSet::new();
    let mut expected: BTreeSet<&str> = BTreeSet::new();
    for cand in CANDIDATES {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            std::fs::write(
                root.join(".gitattributes"),
                "*.toml filter=zz diff=zz merge=zz\n",
            )
            .expect("w .gitattributes");
            git_out(root, &["add", "--", ".gitattributes"]);
            git_out(root, &["commit", "-qm", "the driver attributes"]);
        });
        let side = fx.at("..");
        let log = fx.at("../spy.log");
        let spy = write_spy(&side, "s", &log, cand.kind);
        let hooks = side.join("hooks");
        std::fs::create_dir_all(&hooks).expect("mk hooks");
        for name in [
            "post-index-change",
            "reference-transaction",
            "pre-commit",
            "fsmonitor-watchman",
        ] {
            let p = write_spy(&side, name, &log, cand.kind);
            std::fs::rename(&p, hooks.join(name)).expect("place the hook");
        }
                                                                                               
        let attrs = side.join("attrs");
        std::fs::write(&attrs, "*.toml filter=zz\n").expect("w attrs");
        for (k, v) in cand.cfg {
            let v = v
                .replace("@spy", &spy)
                .replace("@hooks", &hooks.display().to_string())
                .replace("@attrs", &attrs.display().to_string());
            git_out(&fx.root, &["config", k, &v]);
        }
        record_write(&fx, &mut records, TRACKED, SAME_SIZE, false);
        i.commit = true;
        let head_before = git_head(&fx.root);
        ratify_executing(&fx, &i);
        let _ = std::fs::remove_file(&log);

        let prompt = || panic!("the forwarded token commits with no prompt");
        let run = run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        let fired = std::fs::read_to_string(&log).unwrap_or_default();
        let landed = git_head(&fx.root) != head_before;
        let outcome = match &run.outcome {
            Ok(()) => "committed".to_string(),
            Err(e) => e.to_string(),
        };
        assert!(
            !fired.is_empty() || landed,
            "candidate {}: the spy never ran and the gate never landed, so this leg answers \
             nothing: {outcome}",
            cand.key
        );
        if !fired.is_empty() {
            ran.insert(cand.key);
        }
        if is_value_sensitive(cand.key) {
            expected.insert(cand.key);
        }
    }
    assert!(
        !expected.is_empty() && expected.len() < CANDIDATES.len(),
        "the tables call {} of {} candidates value-sensitive, so this arm separates nothing",
        expected.len(),
        CANDIDATES.len()
    );
    assert_eq!(
        ran, expected,
        "the candidates the gate executed are not the candidates the §2.1 tables name"
    );
}

/// One selector leg: the shared configuration, the selector key, and what each of its two values
/// makes the gate execute.
struct SelLeg {
    key: &'static str,
    kind: SpyKind,
    cfg: &'static [(&'static str, &'static str)],
    values: [(&'static str, &'static [&'static str]); 2],
}

/// §2.1 / row B4: the three selectors. Each leg holds the configuration fixed and changes only the
/// selector's value; the set of spies the gate executed changes with it, which is why the value of
/// a key naming no program is in the tables.
#[test]
fn the_three_selectors_change_the_executed_set_by_value_alone() {
    let legs: &[SelLeg] = &[
        SelLeg {
            key: "commit.gpgSign",
            kind: SpyKind::Sign,
            cfg: &[("gpg.program", "@spy")],
            values: [("false", &[]), ("true", &["s"])],
        },
        SelLeg {
            key: "gpg.format",
            kind: SpyKind::Sign,
            cfg: &[
                ("commit.gpgSign", "true"),
                ("gpg.program", "@spy"),
                ("gpg.x509.program", "@spy2"),
            ],
            values: [("openpgp", &["s"]), ("x509", &["t"])],
        },
        SelLeg {
            key: "hook.zz.event",
            kind: SpyKind::Quiet,
            cfg: &[("hook.zz.command", "@spy")],
            values: [("pre-commit", &[]), ("post-index-change", &["s"])],
        },
    ];
    for leg in legs {
        for (value, want) in &leg.values {
            let (fx, mut records, admitted, mut i, profile) = gate_fixture();
            let side = fx.at("..");
            let log = fx.at("../spy.log");
            let spy = write_spy(&side, "s", &log, leg.kind);
            let spy2 = write_spy(&side, "t", &log, leg.kind);
            for (k, v) in leg.cfg {
                let v = v.replace("@spy2", &spy2).replace("@spy", &spy);
                git_out(&fx.root, &["config", k, &v]);
            }
            git_out(&fx.root, &["config", leg.key, value]);
            record_write(&fx, &mut records, TRACKED, SAME_SIZE, false);
            i.commit = true;
            let head_before = git_head(&fx.root);
            ratify_executing(&fx, &i);
            let _ = std::fs::remove_file(&log);

            let prompt = || panic!("the forwarded token commits with no prompt");
            let run =
                run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
            let fired: BTreeSet<&str> = std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(|l| if l == "s" { "s" } else { "t" })
                .collect();
            let landed = git_head(&fx.root) != head_before;
            let outcome = match &run.outcome {
                Ok(()) => "committed".to_string(),
                Err(e) => e.to_string(),
            };
            assert!(
                !fired.is_empty() || landed,
                "selector {}={value}: no spy ran and the gate never landed, so this leg answers \
                 nothing: {outcome}",
                leg.key
            );
            let want: BTreeSet<&str> = want.iter().copied().collect();
            assert_eq!(
                fired, want,
                "selector {}={value}: the executed spy set is not the expected one ({outcome})",
                leg.key
            );
        }
    }
}

                                                                                                    

/// One new-member selector leg: the key, the spy shape, the configuration around it, and the two
/// values with the spy tags each is expected to execute.
struct NewSelLeg {
    key: &'static str,
    kind: SpyKind,
    cfg: &'static [(&'static str, &'static str)],
    values: [(&'static str, &'static [&'static str]); 2],
}

/// Delta v3.4 §3.1 / floor row C'1: each of the four members the v3.4 tables added decides a
/// program execution by its VALUE alone, with the key set unchanged.
///
/// What it claims: for `hook.<n>.enabled`, `hook.<event>.enabled`, `core.attributesFile` and
/// `attr.tree`, two gate runs whose configuration differs only in that key's value execute
/// different spy sets, driven through `run_gate_preratified` over a ratified baseline. The
/// `core.attributesFile` value is a path to an attribute file, and the `attr.tree` value is a
/// tree-ish; the fixture keeps `.gitattributes` out of the worktree and out of HEAD so the only
/// attribute source is the one the value names. What it does NOT claim: that these four are the
/// only value-deciding keys outside the tables — delta §8 DQ-2 records the disclosed remainder, and
/// `$GIT_DIR/info/attributes` is outside the declared space. Blind spots, named: the per-leg
/// expectation is a hand literal, so a git version that changes which of the two values runs the
/// program reddens the arm and is re-measured; the refusal half of row C'1 is
/// `a_value_swap_at_each_value_sensitive_form_refuses_naming_the_value_lines`, which drives all
/// sixteen table forms.
#[test]
fn the_four_new_value_axis_members_change_the_executed_set_by_value_alone() {
    let legs: &[NewSelLeg] = &[
        NewSelLeg {
            key: "hook.zz.enabled",
            kind: SpyKind::Quiet,
            cfg: &[
                ("hook.zz.command", "@spy"),
                ("hook.zz.event", "post-index-change"),
            ],
            values: [("false", &[]), ("true", &["s"])],
        },
        NewSelLeg {
            key: "hook.post-index-change.enabled",
            kind: SpyKind::Quiet,
            cfg: &[
                ("hook.zz.command", "@spy"),
                ("hook.zz.event", "post-index-change"),
                ("hook.zz.enabled", "true"),
            ],
            values: [("false", &[]), ("true", &["s"])],
        },
        NewSelLeg {
            key: "core.attributesFile",
            kind: SpyKind::Pass,
            cfg: &[("filter.zz.clean", "@spy")],
            values: [("@attrs_off", &[]), ("@attrs_on", &["s"])],
        },
        NewSelLeg {
            key: "attr.tree",
            kind: SpyKind::Pass,
            cfg: &[("filter.zz.clean", "@spy")],
            values: [("@tree_off", &[]), ("@tree_on", &["s"])],
        },
    ];

    for leg in legs {
        for (value, want) in &leg.values {
                                                                                                
                                                                                 
            let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
                std::fs::write(root.join(".gitattributes"), "*.toml filter=zz\n")
                    .expect("w .gitattributes");
                git_out(root, &["add", "--", ".gitattributes"]);
                git_out(root, &["commit", "-qm", "the driver attributes"]);
                std::fs::remove_file(root.join(".gitattributes")).expect("rm .gitattributes");
                git_out(root, &["add", "-A", "--", ".gitattributes"]);
                git_out(
                    root,
                    &["commit", "-qm", "the attributes out of the worktree"],
                );
            });
            let side = fx.at("..");
            let log = fx.at("../spy.log");
            let spy = write_spy(&side, "s", &log, leg.kind);
            let attrs_on = side.join("attrs-on");
            std::fs::write(&attrs_on, "*.toml filter=zz\n").expect("w attrs-on");
            let attrs_off = side.join("attrs-off");
            std::fs::write(&attrs_off, "# no driver\n").expect("w attrs-off");
            let tree_on = git_out(&fx.root, &["rev-parse", "HEAD~1"]);
            let tree_off = git_out(&fx.root, &["rev-parse", "HEAD"]);
            let subst = |v: &str| {
                v.replace("@spy", &spy)
                    .replace("@attrs_on", &attrs_on.display().to_string())
                    .replace("@attrs_off", &attrs_off.display().to_string())
                    .replace("@tree_on", &tree_on)
                    .replace("@tree_off", &tree_off)
            };
            for (k, v) in leg.cfg {
                git_out(&fx.root, &["config", k, &subst(v)]);
            }
            git_out(&fx.root, &["config", leg.key, &subst(value)]);

                                                                                                  
                                                   
            assert!(
                !fx.root.join(".gitattributes").exists(),
                "leg {}={value}: the worktree carries .gitattributes, so an attribute leg proves \
                 nothing",
                leg.key
            );
            assert!(
                git_out(&fx.root, &["ls-tree", "--name-only", "HEAD"])
                    .lines()
                    .all(|l| l != ".gitattributes"),
                "leg {}={value}: HEAD's tree carries .gitattributes, so an attribute leg proves \
                 nothing",
                leg.key
            );

            record_write(&fx, &mut records, TRACKED, SAME_SIZE, false);
            i.commit = true;
            let head_before = git_head(&fx.root);
            ratify_executing(&fx, &i);
            let _ = std::fs::remove_file(&log);

            let prompt = || panic!("the forwarded token commits with no prompt");
            let run =
                run_gate_preratified(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
            let fired: BTreeSet<&str> = std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(|_| "s")
                .collect();
            let landed = git_head(&fx.root) != head_before;
            let outcome = match &run.outcome {
                Ok(()) => "committed".to_string(),
                Err(e) => e.to_string(),
            };
            assert!(
                !fired.is_empty() || landed,
                "leg {}={value}: no spy ran and the gate never landed, so this leg answers \
                 nothing: {outcome}",
                leg.key
            );
            let want: BTreeSet<&str> = want.iter().copied().collect();
            assert_eq!(
                fired, want,
                "leg {}={value}: the executed spy set is not the expected one ({outcome})",
                leg.key
            );
        }
    }
}
