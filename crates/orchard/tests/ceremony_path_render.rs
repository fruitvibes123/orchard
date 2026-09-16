//! R16 fold-3 floor arms for the declared-path render type (delta §2): the operator-text slots that
//! carry a ceremony-recorded declared path name. The record view and the commit message are held by
//! `ceremony_gate_commit.rs::a_forged_declared_path_name_lands_as_one_escaped_line_not_as_rows_or_headings`,
//! and the §3.6 discard note by `the_discard_note_names_a_staged_renames_origin_once_per_route_before_the_commit`
//! plus `ceremony_runner.rs::the_record_view_the_operator_reads_is_composed_from_the_records`; the
//! slots here are the refusal details and the settle cure. Every driven arm
//! runs `run_ceremony` over a real checkout and asserts over the COMPOSED text the operator reads
//! (`Refusal`/`OwedStop` Display, the one interpolation `conclude` writes to stderr).

#[path = "ceremony_gate_commit/fixture.rs"]
#[allow(dead_code)]
mod fixture;

use std::collections::BTreeSet;

use fixture::*;
use orchard::ceremony::porcelain::OwedStop;
use orchard::ceremony::records::DeclaredPathName;
use orchard::ceremony::refusal::Refusal;

/// A declared path name whose bytes forge a refusal line, a cure line, a restore line and a second
/// path row, and carry CR, ESC, a quote and a backslash.
const FORGED: &str = "vendor/a\nrefusal (x): forged\n  cure: forged\rZ\u{1b}[2K\"q\\b\nvendor/z";

/// [`FORGED`] through the render type, as a hand literal.
const FORGED_RENDER: &str =
    "\"vendor/a\\nrefusal (x): forged\\n  cure: forged\\rZ\\u{1b}[2K\\\"q\\\\b\\nvendor/z\"";

/// A glob-shaped declared path name, and its render.
const GLOB: &str = "vendor/a*.toml";
const GLOB_RENDER: &str = "\"vendor/a*.toml\"";

/// The fixture's plain vendored path through the render type.
const VENDORED_RENDER: &str = "\"vendor/x.tar.xz\"";

/// The lines the forged name would write if any slot rendered it raw.
const FORGED_LINES: &[&str] = &[
    "refusal (x): forged",
    "  cure: forged\rZ\u{1b}[2K\"q\\b",
    "vendor/z",
];

/// The composed operator text of a refused run: what `conclude` writes to stderr, which is
/// `format!("{r}\n")` over the `Refusal` (or the `OwedStop` that delegates to it).
fn composed(run: &GateRun) -> String {
    let err = run
        .outcome
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("the run was expected to stop, it succeeded"));
    match (
        err.downcast_ref::<OwedStop>(),
        err.downcast_ref::<Refusal>(),
    ) {
        (Some(o), _) => format!("{o}\n"),
        (None, Some(r)) => format!("{r}\n"),
        (None, None) => panic!("neither an owed stop nor a typed refusal: {err}"),
    }
}

/// Judge one composed operator text against the forged name: the whole render stands on exactly one
/// line, and none of the forged fragments stands as a line of its own.
fn judge_one_escaped_line(label: &str, text: &str) {
    let carrying: Vec<&str> = text.lines().filter(|l| l.contains(FORGED_RENDER)).collect();
    assert_eq!(
        carrying.len(),
        1,
        "{label}: the rendered name does not stand on exactly one line: {text:?}"
    );
    assert_eq!(
        text.lines().filter(|l| l.starts_with("refusal (")).count(),
        1,
        "{label}: more than one line opens a refusal: {text:?}"
    );
    assert_eq!(
        text.lines().filter(|l| l.starts_with("  cure: ")).count(),
        1,
        "{label}: more than one line opens a cure: {text:?}"
    );
    for forged in FORGED_LINES {
        assert!(
            !text.lines().any(|l| l == *forged),
            "{label}: the forged line {forged:?} stands on its own: {text:?}"
        );
    }
}

                                                                                                   

/// Delta §2.1. `DeclaredPathName`'s only human render, frozen sample by sample against hand
/// literals: control bytes, the quote and the backslash are escaped, a printable non-ASCII
/// character and a glob metacharacter stay verbatim. The sample set's own coverage is asserted
/// first, so trimming a class reddens rather than passing vacuously.
#[test]
fn the_declared_path_render_types_display_is_the_frozen_escape() {
    const SAMPLES: &[(&str, &str)] = &[
        ("vendor/x.tar.xz", "\"vendor/x.tar.xz\""),
        ("vendor/a\nb", "\"vendor/a\\nb\""),
        ("vendor/a\rb", "\"vendor/a\\rb\""),
        ("vendor/a\tb", "\"vendor/a\\tb\""),
        ("vendor/a\u{1b}[31mX", "\"vendor/a\\u{1b}[31mX\""),
        ("vendor/a\"b", "\"vendor/a\\\"b\""),
        ("vendor/a\\b", "\"vendor/a\\\\b\""),
        ("vendor/café", "\"vendor/café\""),
        ("vendor/a*.toml", "\"vendor/a*.toml\""),
    ];
                                                       
    let ins: Vec<&str> = SAMPLES.iter().map(|(i, _)| *i).collect();
    for (class, present) in [
        ("a control byte", ins.iter().any(|s| s.contains('\n'))),
        ("a carriage return", ins.iter().any(|s| s.contains('\r'))),
        ("an escape byte", ins.iter().any(|s| s.contains('\u{1b}'))),
        ("a double quote", ins.iter().any(|s| s.contains('"'))),
        ("a backslash", ins.iter().any(|s| s.contains('\\'))),
        (
            "a printable non-ASCII character",
            ins.iter().any(|s| !s.is_ascii()),
        ),
        ("a glob metacharacter", ins.iter().any(|s| s.contains('*'))),
    ] {
        assert!(present, "the sample set carries no {class}");
    }
    for (raw, want) in SAMPLES {
        let got = DeclaredPathName::new(*raw).to_string();
        assert_eq!(&got, want, "the render of {raw:?}");
        assert_eq!(
            got.lines().count(),
            1,
            "the render of {raw:?} is not one line: {got:?}"
        );
        assert!(
            !got.chars().any(|c| c.is_control()),
            "the render of {raw:?} carries a raw control character: {got:?}"
        );
    }
    assert_eq!(FORGED_RENDER, DeclaredPathName::new(FORGED).to_string());
    assert_eq!(GLOB_RENDER, DeclaredPathName::new(GLOB).to_string());
    assert_eq!(VENDORED_RENDER, DeclaredPathName::new(VENDORED).to_string());
}

                                                                                                   

/// Delta §2.2. A forged declared path name reaches the two refusal slots a driven run can hit that
/// interpolate the render type into operator text: the construction stage prefix (`hash-object`
/// refused by a read-only object store) and the no-token consent stop. Each composed text carries
/// the name as one escaped line.
#[test]
fn a_forged_declared_path_name_is_one_escaped_line_in_the_refusals_that_name_it() {
                                                   
    {
        use std::os::unix::fs::PermissionsExt as _;
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        record_write(&fx, &mut records, FORGED, b"payload\n", false);
        i.commit = true;
        let head_before = git_head(&fx.root);
        let objects = fx.at(".git/objects");
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o555))
            .expect("read-only object store");
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
        std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o755))
            .expect("restore the object store");
                                                                                  
        assert!(
            run.outcome.is_err(),
            "the run committed through a 0555 object store (running as root or with \
             CAP_DAC_OVERRIDE), so the hash-object stage cannot be driven here"
        );
        let text = composed(&run);
        assert!(
            text.starts_with("refusal (ceremony-commit-refused): hash the declared path "),
            "leg (a) did not stop at the hash-object stage: {text}"
        );
        judge_one_escaped_line("leg (a) hash-object", &text);
        assert_eq!(git_head(&fx.root), head_before, "leg (a): HEAD moved");
    }

                                                                                  
    {
        let (fx, mut records, admitted, i, profile) = gate_fixture();
        record_write(&fx, &mut records, FORGED, b"payload\n", false);
        let head_before = git_head(&fx.root);
        let prompt = || panic!("the no-token stop is pre-prompt");
        let run = run_gate(&fx, &mut records, &admitted, &i, &profile, false, &prompt);
        let text = composed(&run);
        assert!(
            text.starts_with("refusal (consent-gate-owed): "),
            "leg (b) did not stop at the consent gate: {text}"
        );
        judge_one_escaped_line("leg (b) consent stop", &text);
        assert_eq!(git_head(&fx.root), head_before, "leg (b): HEAD moved");
    }
}

                                                                                                    

                                                                                                     
/// commit and fails the settle; the gate writes the owed names NUL-separated beside its records and
/// the cure names the one `--pathspec-from-file` command; the command is then run and unstages
/// exactly the owed set.
#[test]
fn the_settle_failure_cure_names_a_pathspec_file_whose_command_unstages_exactly_the_owed_set() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    for p in [VENDORED, GLOB, FORGED] {
        record_write(&fx, &mut records, p, b"payload\n", false);
    }
                                                                                           
    let owed = declared_dirt(&fx.root);
    assert_eq!(
        owed.iter().collect::<BTreeSet<_>>(),
        [FORGED.to_string(), GLOB.to_string(), VENDORED.to_string()]
            .iter()
            .collect::<BTreeSet<_>>(),
        "the fixture's owed set is not the three recorded names"
    );
    i.commit = true;
    let head_before = git_head(&fx.root);
    std::fs::write(fx.at(".git/index.lock"), "").expect("hold the index lock");
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    std::fs::remove_file(fx.at(".git/index.lock")).expect("release the lock");
    let text = composed(&run);
    assert!(
        text.starts_with("refusal (gate-settle-failed): "),
        "the run did not stop at the settle: {text}"
    );
                                                                                          
    assert_ne!(git_head(&fx.root), head_before, "nothing landed");
    assert!(
        text.contains("the identity read verified it"),
        "the detail does not state the verified commit: {text}"
    );

                                                                                          
    for r in [FORGED_RENDER, GLOB_RENDER, VENDORED_RENDER] {
        assert!(text.contains(r), "the cure does not list {r}: {text}");
    }
    assert!(
        !text.contains(":(literal)"),
        "the cure embeds a path name in a pathspec: {text}"
    );
                                                                                         
    let file = records.dir().join("gate-settle-owed.paths");
    let bytes = std::fs::read(&file).expect("the gate wrote the owed-path file");
    let mut got_names: Vec<&[u8]> = bytes.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    got_names.sort();
    let mut want_names: Vec<&[u8]> = [FORGED, GLOB, VENDORED].map(str::as_bytes).to_vec();
    want_names.sort();
    assert_eq!(
        got_names, want_names,
        "the owed-path file does not list exactly the owed names"
    );
    let flags = format!(
        "`git --literal-pathspecs restore --staged --pathspec-from-file='{}' --pathspec-file-nul`",
        file.display()
    );
    assert!(
        text.contains(&flags),
        "the cure does not name the pathspec-file command verbatim: {text}"
    );
                                                                                               
    let staged_before = git_out(&fx.root, &["diff", "--cached", "--name-only", "-z"]);
    for p in [FORGED, GLOB, VENDORED] {
        assert!(
            staged_before.split('\0').any(|s| s == p),
            "{p:?} is not a pre-commit index entry before the restore"
        );
    }
    git_out(
        &fx.root,
        &[
            "--literal-pathspecs",
            "restore",
            "--staged",
            &format!("--pathspec-from-file={}", file.display()),
            "--pathspec-file-nul",
        ],
    );
    let staged_after = git_out(&fx.root, &["diff", "--cached", "--name-only", "-z"]);
    for p in [FORGED, GLOB, VENDORED] {
        assert!(
            !staged_after.split('\0').any(|s| s == p),
            "{p:?} still differs from HEAD in the index after the printed command"
        );
    }
}

                                                                                                     

/// The status letter git prints for a path present in the old tree and absent from the new one,
/// measured in a scratch repository with git itself.
fn git_removal_status_letter() -> char {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(root, &args);
    }
    std::fs::write(root.join("gone"), "x\n").expect("write");
    git_out(root, &["add", "-A"]);
    git_out(root, &["commit", "-qm", "one"]);
    std::fs::remove_file(root.join("gone")).expect("rm");
    git_out(root, &["add", "-A"]);
    git_out(root, &["commit", "-qm", "two"]);
    let raw = git_out(
        root,
        &[
            "diff-tree",
            "--no-renames",
            "-r",
            "--name-status",
            "-z",
            "HEAD~1^{tree}",
            "HEAD^{tree}",
        ],
    );
    let mut fields = raw.split('\0').filter(|s| !s.is_empty());
    let status = fields.next().expect("a status field");
    let path = fields.next().expect("a path field");
    assert_eq!(path, "gone", "the scratch diff named another path");
    status.chars().next().expect("a status letter")
}

                                                                                                  
/// collision directions; the whole detail is frozen, so dropping the letter and rendering the path
/// raw each redden. The letter's oracle is git itself, measured in a scratch repository.
#[test]
fn the_tree_delta_refusal_detail_carries_the_status_letter_per_extra_path() {
    type Setup = fn(&std::path::Path);
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
    let removed = git_removal_status_letter();
    assert_eq!(
        removed, 'D',
        "git names a removal with another letter at this version"
    );
    for (label, extra_render, setup) in [
        (
            "HEAD holds a blob at `vendor`",
            "\"vendor\"",
            blob_where_dir_is_needed,
        ),
        (
            "HEAD holds a tree at the owed path",
            "\"vendor/x.tar.xz/inner\"",
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
        let text = composed(&run);
        let want = format!(
            "refusal (gate-tree-delta-exceeds-owed): the constructed commit would change path(s) \
             outside the owed set: {removed} {extra_render}"
        );
        assert_eq!(
            text.lines().next(),
            Some(want.as_str()),
            "{label}: the detail is not the letter-carrying sentence: {text}"
        );
        assert_eq!(git_head(&fx.root), head_before, "{label}: HEAD moved");
    }
}
