//! R16 fold-5 unit D' floor arms (delta v3.4 §4): the test tree's own process isolation. The
//! domain is source bytes, so both arms are static scans with their own self-tests.

use std::path::{Path, PathBuf};

/// One scanned source line: the file relative to `crates/orchard/tests/` and the trimmed text.
type Hit = (String, String);

/// The scan root, `crates/orchard/tests/`.
fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Every non-comment line under `dir` whose trimmed text contains one of `needles`, as
/// (file relative to `dir`, trimmed line), sorted by file then line.
fn scan(dir: &Path, needles: &[&str]) -> Vec<Hit> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
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
    files.sort();
    let mut hits = Vec::new();
    for p in &files {
        let rel = p
            .strip_prefix(dir)
            .expect("under the scan root")
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for line in text.lines() {
            let s = line.trim();
            if s.starts_with("//") {
                continue;
            }
            if needles.iter().any(|n| s.contains(n)) {
                hits.push((rel.clone(), s.to_string()));
            }
        }
    }
    hits
}

                                                                                                    

/// The files row D'2 quantifies over: the two declared-space suites and the shared helpers they
/// include.
const D2_DOMAIN: &[&str] = &[
    "ceremony_declared_space.rs",
    "ceremony_declared_value.rs",
    "common/admit.rs",
    "common/roles.rs",
    "common/shell_split.rs",
];

/// §4.1 / row D'2: the declared-space and declared-value suites reach the built binary's `admit`
/// through the one helper in `tests/common/admit.rs`, and that helper pins the child's global and
/// system git config.
///
/// What it claims, as the exact model checked: over the non-comment lines of the files named
/// in `D2_DOMAIN`, `CARGO_BIN_EXE_orchard` occurs exactly once and that occurrence is in
/// `common/admit.rs`; and `common/admit.rs` sets `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`,
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` on the child and removes `FRUIT_ARTIFACT_STORE` and
/// `ORCHARD_LOCK_TOKEN`. What it does NOT claim: that no other test binary spawns the built
/// binary — `ceremony_utf8_argv.rs` does, because row B'1 needs a crafted non-UTF-8 `OsString`
/// argv the helper's `&Path` signature cannot carry, and eleven other suites spawn it for their own
/// purposes. Blind spots, named: a spawn through a path bound before this scan's needle (a variable
/// holding the binary path passed in from elsewhere), a macro-emitted spawn, a line whose trimmed
/// form starts with `//`, and every file outside `D2_DOMAIN`.
#[test]
fn the_two_declared_space_suites_spawn_admit_through_one_pinned_helper() {
    let dir = tests_dir();
    let hits: Vec<Hit> = scan(&dir, &["CARGO_BIN_EXE_orchard"])
        .into_iter()
        .filter(|(f, _)| D2_DOMAIN.contains(&f.as_str()))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the two suites reach the built binary at more than one site: {hits:?}"
    );
    assert_eq!(
        hits[0].0, "common/admit.rs",
        "the one spawn site is not the shared helper: {hits:?}"
    );

                                                                                                  
    let helper = std::fs::read_to_string(dir.join("common/admit.rs")).expect("read the helper");
    for (needle, why) in [
        (".env(\"HOME\"", "HOME"),
        (".env(\"XDG_CONFIG_HOME\"", "XDG_CONFIG_HOME"),
        (".env(\"XDG_STATE_HOME\"", "XDG_STATE_HOME"),
        (".env(\"GIT_CONFIG_GLOBAL\"", "GIT_CONFIG_GLOBAL"),
        (".env(\"GIT_CONFIG_SYSTEM\"", "GIT_CONFIG_SYSTEM"),
        (
            ".env_remove(\"FRUIT_ARTIFACT_STORE\")",
            "FRUIT_ARTIFACT_STORE",
        ),
        (".env_remove(\"ORCHARD_LOCK_TOKEN\")", "ORCHARD_LOCK_TOKEN"),
    ] {
        assert!(
            helper.contains(needle),
            "the shared helper does not pin {why} on the child"
        );
    }
    for (name, value) in [
        ("GIT_CONFIG_GLOBAL", "empty_global"),
        ("GIT_CONFIG_SYSTEM", "empty_system"),
    ] {
        assert!(
            helper.contains(&format!(".env(\"{name}\", &{value})")),
            "the shared helper does not point the child's {name} at its empty file"
        );
    }
    assert!(
        helper.contains("std::fs::write(&empty_global, \"\")")
            && helper.contains("std::fs::write(&empty_system, \"\")"),
        "the shared helper does not write the two empty config files"
    );
}

                                                                                                    

/// This file, excluded from its own scan: the frozen inventory below quotes every site's source
/// line, so a scan including this file would report each entry twice and could not stabilize.
const SELF_FILE: &str = "ceremony_floor_isolation.rs";

/// The disposition of one frozen env-mutation site.
#[derive(Debug, PartialEq, Eq)]
enum Where {
    /// Inside a branch that only a dedicated role process reaches.
    Role,
    /// In a test binary's shared process, correct only under `--test-threads=1`.
    Shared,
}

/// §4.2 / row D'3: every `std::env::set_var` / `remove_var` site under `crates/orchard/tests/`,
/// frozen as an exact set with its disposition.
///
/// What it claims, as the exact model checked: over the non-comment lines of `tests/**/*.rs`, the
/// lines containing `set_var` or `remove_var` are exactly the (file, trimmed line) pairs below in
/// this order, and every such site in the four files of `D2_DOMAIN` carries the `Role` disposition.
/// A new site anywhere under `tests/` reddens this arm and forces a conscious entry with a
/// disposition. What it does NOT claim: that a site marked `Role` runs only in a role process — the
/// disposition is a reviewer's label this freeze carries, not a property it computes; and a text
/// scan checks membership in an enumerated spelling set and models no grammar. Blind spots, named:
/// an aliased or re-exported spelling (`use std::env::set_var as sv`), a macro-emitted call, a
/// mutation through a helper in another crate, `std::env::set_var` reached through a `Command`'s
/// own environment (which is per-child and not process-global), a line whose trimmed form starts
/// with `//` (the normalization this comparison relies on), and everything outside
/// `crates/orchard/tests/`, this file included (it quotes every entry, so it is excluded by name
/// and an env mutation written into it is unscanned). The `Shared` entries are the ones this delta did not touch; they are
/// correct only while their binaries run `--test-threads=1`, which row D'1 exercises at default
/// parallelism instead.
#[test]
fn the_env_mutation_sites_under_tests_are_frozen_and_the_declared_space_suites_are_role_only() {
    let hits: Vec<Hit> = scan(&tests_dir(), &["set_var", "remove_var"])
        .into_iter()
        .filter(|(f, _)| f != SELF_FILE)
        .collect();
    assert!(
        hits.len() >= 20,
        "the scan found {} env-mutation lines, so it is scanning nothing",
        hits.len()
    );
    let want: Vec<Hit> = FROZEN_ENV_MUTATIONS
        .iter()
        .map(|(f, l, _)| ((*f).to_string(), (*l).to_string()))
        .collect();
    assert_eq!(
        hits, want,
        "the env-mutation sites under crates/orchard/tests/ moved; re-freeze consciously, with a \
         disposition per entry"
    );
    let not_role: Vec<&(&str, &str, Where)> = FROZEN_ENV_MUTATIONS
        .iter()
        .filter(|(f, _, w)| D2_DOMAIN.contains(f) && *w != Where::Role)
        .collect();
    assert!(
        not_role.is_empty(),
        "a declared-space suite mutates the environment outside a role branch: {not_role:?}"
    );
    assert!(
        FROZEN_ENV_MUTATIONS
            .iter()
            .any(|(_, _, w)| *w == Where::Shared),
        "no entry is marked Shared, so the disposition column separates nothing"
    );
}

/// The frozen set for
/// [`the_env_mutation_sites_under_tests_are_frozen_and_the_declared_space_suites_are_role_only`]:
/// (file relative to `crates/orchard/tests/`, trimmed source line, disposition), in scan order.
const FROZEN_ENV_MUTATIONS: &[(&str, &str, Where)] = &[
                                                                                                 
    (
        "ceremony_declared_space.rs",
        "std::env::remove_var(\"GIT_CONFIG_GLOBAL\");",
        Where::Role,
    ),
    (
        "ceremony_declared_space.rs",
        "std::env::remove_var(\"GIT_CONFIG_SYSTEM\");",
        Where::Role,
    ),
    (
        "ceremony_declared_space.rs",
        "unsafe { std::env::set_var(\"GIT_NO_LAZY_FETCH\", \"0\") };",
        Where::Role,
    ),
    (
        "ceremony_declared_space.rs",
        "unsafe { std::env::remove_var(\"GIT_NO_LAZY_FETCH\") };",
        Where::Role,
    ),
                                                                           
    (
        "ceremony_gate.rs",
        "std::env::set_var(\"RECIPES_DOMAIN\", \"attacker.example\");",
        Where::Shared,
    ),
    (
        "ceremony_gate.rs",
        "std::env::remove_var(\"RECIPES_DOMAIN\");",
        Where::Shared,
    ),
    (
        "ceremony_gate.rs",
        "Some(t) => std::env::set_var(GATE_TARGET_ENV, t),",
        Where::Shared,
    ),
    (
        "ceremony_gate.rs",
        "None => std::env::remove_var(GATE_TARGET_ENV),",
        Where::Shared,
    ),
    (
        "ceremony_gate.rs",
        "std::env::remove_var(GATE_TARGET_ENV);",
        Where::Shared,
    ),
                                                                                      
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", empty.display().to_string()) };",
        Where::Shared,
    ),
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", &old_path) };",
        Where::Shared,
    ),
    (
        "ceremony_gate_commit.rs",
        "\"gitdir\" => std::env::set_var(\"GIT_DIR\", decoy.join(\".git\")),",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "\"indexfile\" => std::env::set_var(\"GIT_INDEX_FILE\", decoy.join(\".git/index\")),",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_CONFIG_COUNT\", \"1\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_CONFIG_KEY_0\", \"commit.gpgSign\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_CONFIG_VALUE_0\", \"notabool\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_AUTHOR_NAME\", \"Env Author\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_AUTHOR_EMAIL\", \"env-author@example.invalid\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_AUTHOR_DATE\", \"2026-01-02T03:04:05+00:00\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_COMMITTER_NAME\", \"Env Committer\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_COMMITTER_EMAIL\", \"env-committer@example.invalid\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::set_var(\"GIT_COMMITTER_DATE\", \"2026-01-02T03:04:05+00:00\");",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "\"globalconfig\" => std::env::set_var(\"GIT_CONFIG_GLOBAL\", &global_config),",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "std::env::remove_var(k);",
        Where::Role,
    ),
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", shimdir.display().to_string()) };",
        Where::Shared,
    ),
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", &old_path) };",
        Where::Shared,
    ),
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", shimdir.display().to_string()) };",
        Where::Shared,
    ),
    (
        "ceremony_gate_commit.rs",
        "unsafe { std::env::set_var(\"PATH\", &old_path) };",
        Where::Shared,
    ),
                                                                                         
    (
        "ceremony_typed_cure.rs",
        "unsafe { std::env::set_var(\"PATH\", &self.0) };",
        Where::Shared,
    ),
    (
        "ceremony_typed_cure.rs",
        "unsafe { std::env::set_var(\"PATH\", dir.display().to_string()) };",
        Where::Shared,
    ),
    (
        "ceremony_typed_cure.rs",
        "unsafe { std::env::set_var(\"TMPDIR\", ro.display().to_string()) };",
        Where::Shared,
    ),
    (
        "ceremony_typed_cure.rs",
        "Some(v) => std::env::set_var(\"TMPDIR\", v),",
        Where::Shared,
    ),
    (
        "ceremony_typed_cure.rs",
        "None => std::env::remove_var(\"TMPDIR\"),",
        Where::Shared,
    ),
                                                            
    (
        "common/roles.rs",
        "std::env::set_var(\"GIT_CONFIG_GLOBAL\", global);",
        Where::Role,
    ),
    (
        "common/roles.rs",
        "std::env::set_var(\"GIT_CONFIG_SYSTEM\", system);",
        Where::Role,
    ),
                                                                 
    (
        "grocer_publish_gate.rs",
        "std::env::remove_var(\"FRUIT_ARTIFACT_STORE\");",
        Where::Shared,
    ),
];

/// The self-test for both scans: a planted violation is reported with its file, and the same text
/// inside a `//` comment is not.
///
/// What it claims: over a scratch tree holding one `set_var` line and one `CARGO_BIN_EXE_orchard`
/// line, including one in a subdirectory, `scan` returns each of them; over a tree holding the same
/// text inside `//` comments it returns nothing. What it does NOT claim: anything about a spelling
/// outside the needle set; that set is the model rows D'2 and D'3 name.
#[test]
fn the_isolation_scanner_reddens_on_a_planted_violation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let live = tmp.path().join("live");
    std::fs::create_dir_all(live.join("sub")).expect("mk");
    std::fs::write(
        live.join("leaky.rs"),
        "fn f() {\n    unsafe { std::env::set_var(\"HOME\", \"/x\") };\n}\n",
    )
    .expect("w");
    std::fs::write(
        live.join("sub/spawner.rs"),
        "fn g() {\n    let p = env!(\"CARGO_BIN_EXE_orchard\");\n}\n",
    )
    .expect("w");
    assert_eq!(
        scan(&live, &["set_var", "remove_var"]),
        vec![(
            "leaky.rs".to_string(),
            "unsafe { std::env::set_var(\"HOME\", \"/x\") };".to_string()
        )],
        "the scanner did not report the planted env mutation"
    );
    assert_eq!(
        scan(&live, &["CARGO_BIN_EXE_orchard"]),
        vec![(
            "sub/spawner.rs".to_string(),
            "let p = env!(\"CARGO_BIN_EXE_orchard\");".to_string()
        )],
        "the scanner did not report the planted spawn site in a subdirectory"
    );

    let commented = tmp.path().join("commented");
    std::fs::create_dir_all(&commented).expect("mk");
    std::fs::write(
        commented.join("quiet.rs"),
        "fn f() {\n    // std::env::set_var(\"HOME\", \"/x\"); env!(\"CARGO_BIN_EXE_orchard\")\n}\n",
    )
    .expect("w");
    assert!(
        scan(
            &commented,
            &["set_var", "remove_var", "CARGO_BIN_EXE_orchard"]
        )
        .is_empty(),
        "the scanner reports a commented-out line, so its normalization does not hold"
    );
}
