//! R16 fold-5 unit A' floor arms (delta v3.4 §1): the git seam's byte domain and the `Exit`
//! reading of each terminal's consumer. The driven arms run the production entry points over real
//! checkouts; the one static arm's domain is source bytes.

                                                                                                   
#[allow(dead_code)]
#[path = "ceremony_gate_commit/fixture.rs"]
mod fixture;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use fixture::*;

/// The composed operator text of a refusal, as `Refusal`'s `Display` writes it.
fn composed(id: &str, detail: &str, cure: &str) -> String {
    format!("refusal ({id}): {detail}\n  cure: {cure}")
}

/// The §1.8 `NonUtf8Output` cure for a commit-gate read, as a hand literal. Deriving it from
/// `GitReadFailure::cure()` would compare the mechanism against itself.
fn cure_nonutf8(op: &str) -> String {
    format!(
        "git's `{op}` output for the commit gate holds bytes outside UTF-8; the ceremony \
         requires UTF-8 paths and configuration keys; rename the path or key the sample \
         names to UTF-8, then re-run"
    )
}

/// Write `name_bytes` as a file name under `dir`; returns the path.
fn plant_named(dir: &Path, name_bytes: &[u8]) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mk dir");
    let p = dir.join(OsStr::from_bytes(name_bytes));
    std::fs::write(&p, b"planted\n").expect("write the planted name");
    p
}

                                                                                                     

                                                                                                  
/// with `git-state-unreadable`, the detail carrying the escaped `\xNN` sample; nothing lands and
/// the planted file is untouched.
///
/// What it claims: for a bad name under the declared `vendor/` directory and for one under an
/// undeclared `tools/` directory, the whole composed refusal is the hand literal below, HEAD is
/// unmoved and the planted file keeps its bytes; and an ASCII name in the same place commits. What
/// it does NOT claim: that every non-UTF-8 byte sequence in every git output refuses — the decode
/// is one call (`utf8`) and this arm drives one command through it. The sample is the NUL- or
/// LF-delimited record around the first invalid byte (§1.7), not the whole listing. Blind spots, named: a
/// name outside UTF-8 that git C-quotes rather than emitting verbatim (the scan uses `-z`, where
/// git emits the raw bytes); the sibling gate's own route through the same `git_dirty_paths` site,
/// which this arm does not drive; a git version that changes the `--porcelain=v1 -z` record shape
/// or the fixture's own dirt set, which reddens the literal and is re-frozen consciously.
#[test]
fn a_non_utf8_untracked_name_stops_the_commit_gate_with_the_escaped_sample() {
    for subdir in ["vendor", "tools"] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        i.commit = true;
        let bad = plant_named(&fx.root.join(subdir), b"bad-\xff.txt");
        let head_before = git_head(&fx.root);

                                                                                                
                                                    
        let raw = std::process::Command::new("git")
            .current_dir(&fx.root)
            .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
            .output()
            .expect("git status");
        assert!(
            raw.status.success() && raw.stdout.contains(&0xff),
            "{subdir}: git's own listing does not carry the planted byte, so this arm proves nothing"
        );

        let run = run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile);
        let root = fx.root.display();
        let op = format!("status (in {root})");
        assert_eq!(
            run.refusal().to_string(),
            composed(
                "git-state-unreadable",
                &format!(
                    "cannot read the checkout {root}'s git state to decide the commit gate: \
                     `git {op}` emitted bytes outside UTF-8 (?? {subdir}/bad-\\xff.txt)"
                ),
                &cure_nonutf8(&op),
            ),
            "{subdir}: the composed refusal is not the non-UTF-8 read failure"
        );
        assert!(
            !run.refusal().detail.contains('\u{fffd}'),
            "{subdir}: the detail carries a U+FFFD substitution: {}",
            run.refusal().detail
        );
        assert_eq!(git_head(&fx.root), head_before, "{subdir}: HEAD moved");
        assert_eq!(
            std::fs::read(&bad).expect("the planted file is still on disk"),
            b"planted\n",
            "{subdir}: the refused run touched the planted file"
        );
    }

                                                                                               
                                                                                                 
                                                  
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    i.commit = true;
    let _ = plant_named(&fx.root.join("tools"), b"bad-ff.txt");
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
    run.outcome
        .unwrap_or_else(|e| panic!("an ASCII untracked name refuses the gate: {e}"));
    assert_ne!(
        git_head(&fx.root),
        head_before,
        "the ASCII control did not land"
    );
}

                                                                                                     

/// §1.5 / row A'4: `git_head`'s `Exit` reading is `None`, driven through `admission::measure`.
///
/// What it claims: over a repository with no commits, `measure(root).head` is `None`, and over the
/// same repository after one commit it is git's own `rev-parse HEAD` answer. What it does NOT
/// claim: the reading of a spawn failure (no git on PATH), which this arm does not drive. Blind
/// spot, named: `measure` collapses `DirtScan::Unevaluable` to an empty `dirty` list by design
/// (`admission::measure`'s own doc), so this arm says nothing about the dirt half.
#[test]
fn git_head_reads_a_non_zero_rev_parse_as_no_head() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(&root, &args);
    }

                                                                                              
                                                                      
    let (ok, out, _) = git_try(&root, &["rev-parse", "HEAD"]);
    assert!(
        !ok,
        "arm sanity: rev-parse HEAD succeeded in an empty repository"
    );
    assert_eq!(
        out, "HEAD",
        "arm sanity: git's stdout on the failing read moved, so the arm's mutation target moved"
    );

    assert_eq!(
        orchard::ceremony::admission::measure(&root).head,
        None,
        "a non-zero `rev-parse HEAD` did not read as no HEAD"
    );

    std::fs::write(root.join("a.txt"), "x\n").expect("w");
    git_out(&root, &["add", "-A"]);
    git_out(&root, &["commit", "-qm", "one"]);
    assert_eq!(
        orchard::ceremony::admission::measure(&root).head,
        Some(git_out(&root, &["rev-parse", "HEAD"])),
        "the measured HEAD is not git's own answer"
    );
}

/// §1.5 / row A'4: `head_content_state`'s `Exit` reading is `Absent`, driven through the public
/// `records::head_content_state`.
///
/// What it claims: a path absent from HEAD reads `Absent`, and a path present at HEAD reads
/// `Sha256` whose digest is `sha256sum`'s answer over the committed bytes. What it does NOT claim:
/// the spawn-failure reading. Blind spot, named: the oracle is the host's `sha256sum`; a host
/// without it fails the arm at its own `expect`, which is a loud stop, never a silent pass.
#[test]
fn head_content_state_reads_a_non_zero_show_as_absent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git_out(&root, &args);
    }
    std::fs::write(root.join("tracked.txt"), "committed\n").expect("w");
    git_out(&root, &["add", "-A"]);
    git_out(&root, &["commit", "-qm", "one"]);
    std::fs::write(root.join("untracked.txt"), "never committed\n").expect("w");

                                                                                                    
    let (absent_ok, _, _) = git_try(&root, &["show", "HEAD:untracked.txt"]);
    let (present_ok, _, _) = git_try(&root, &["show", "HEAD:tracked.txt"]);
    assert!(
        !absent_ok && present_ok,
        "arm sanity: git's own `show HEAD:<rel>` exits did not split as this arm claims"
    );

    use orchard::ceremony::records::{ContentState, head_content_state};
    assert_eq!(
        head_content_state(&root, "untracked.txt"),
        ContentState::Absent,
        "a path absent from HEAD did not read as Absent"
    );
    let sum = std::process::Command::new("sha256sum")
        .arg(root.join("tracked.txt"))
        .output()
        .expect("sha256sum answers the oracle");
    let want = String::from_utf8_lossy(&sum.stdout)
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_string();
    match head_content_state(&root, "tracked.txt") {
        ContentState::Sha256 { sha256, exec } => {
            assert_eq!(sha256, want, "the HEAD content digest is not sha256sum's");
            assert!(!exec, "the committed 100644 entry read as executable");
        }
        other => panic!("a path present at HEAD did not read as Sha256, got {other:?}"),
    }
}

/// §1.5 / row A'4: `read_core_file_mode`'s `Exit` reading is `true`, driven through the public
/// `RunRecords::with_checkout` and observed at the exec witness.
///
/// What it claims: a records handle bound to a root whose `config --type=bool --default=true
/// core.fileMode` read exits non-zero takes the WORKTREE exec bit into the witness, which is the
/// `true` reading; a handle bound to a real checkout at `core.fileMode=false` takes git's index
/// mode instead. What it does NOT claim: anything about a checkout whose `core.fileMode` is a
/// malformed boolean — git 2.55.0 then fails every command in that checkout, so the reading cannot
/// be isolated there; nor anything about the spawn-failure reading. Blind spots, named: the bound
/// root here is absent, which is the one shape that fails this read alone (an existing non-repo
/// directory answers `true` at exit 0, so it would leave the branch untested); the unbound handle
/// (`checkout: None`) also reads the worktree bit, so the positive leg is distinguished only by the
/// `core.fileMode=false` control beside it.
#[test]
fn read_core_file_mode_reads_a_non_zero_config_read_as_true() {
    use orchard::ceremony::records::{
        ContentState, RunRecords, classify_and_witness, finalize_path_record, open_path_record,
    };
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tempdir");

                                                                                                   
                                                                                             
    let unanswerable = tmp.path().join("no-such-checkout");
    let probe = std::process::Command::new("git")
        .args(["--no-replace-objects", "-C"])
        .arg(&unanswerable)
        .args(["config", "--type=bool", "--default=true", "core.fileMode"])
        .output()
        .expect("git config");
    assert!(
        !probe.status.success(),
        "arm sanity: git answered the production config read at an absent root, so the Exit \
         branch is untested: {}",
        String::from_utf8_lossy(&probe.stdout)
    );
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).expect("mk dir");
    let f = work.join("consume-pins.toml");
    std::fs::write(&f, "pin = 1\n").expect("w");
    let mut rec = RunRecords::open_dir(&tmp.path().join("unanswerable.d"), "run-1")
        .expect("open records")
        .with_checkout(&unanswerable);
    let tok = open_path_record(&mut rec, &f).expect("open");
    std::fs::write(&f, "pin = 1\n").expect("ceremony write");
    let mut perm = std::fs::metadata(&f).expect("stat").permissions();
    perm.set_mode(perm.mode() | 0o111);
    std::fs::set_permissions(&f, perm).expect("chmod +x");
    finalize_path_record(&mut rec, tok).expect("finalize");
    match classify_and_witness(&rec, &f).1.expect("a witness").post {
        ContentState::Sha256 { exec, .. } => assert!(
            exec,
            "the witness dropped the worktree exec bit, so the unreadable config read did not \
             default to core.fileMode=true"
        ),
        other => panic!("a regular file records a Sha256 post, got {other:?}"),
    }

                                                                                               
                                    
    let repo = tmp.path().join("modeoff");
    std::fs::create_dir_all(&repo).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["config", "core.fileMode", "false"],
    ] {
        git_out(&repo, &args);
    }
    let g = repo.join("consume-pins.toml");
    std::fs::write(&g, "pin = 1\n").expect("w");
    git_out(&repo, &["add", "-A"]);
    git_out(&repo, &["commit", "-qm", "tracked"]);
    let mut rec2 = RunRecords::open_dir(&tmp.path().join("modeoff.d"), "run-1")
        .expect("open records")
        .with_checkout(&repo);
    let tok2 = open_path_record(&mut rec2, &g).expect("open");
    std::fs::write(&g, "pin = 1\n").expect("ceremony write");
    let mut perm2 = std::fs::metadata(&g).expect("stat").permissions();
    perm2.set_mode(perm2.mode() | 0o111);
    std::fs::set_permissions(&g, perm2).expect("chmod +x");
    finalize_path_record(&mut rec2, tok2).expect("finalize");
    assert!(
        git_out(&repo, &["ls-files", "-s", "--", "consume-pins.toml"]).starts_with("100644"),
        "arm sanity: git's index does not hold the non-exec mode, so the control proves nothing"
    );
    match classify_and_witness(&rec2, &g).1.expect("a witness").post {
        ContentState::Sha256 { exec, .. } => assert!(
            !exec,
            "the control witness took the worktree bit, so the two readings are not distinguished"
        ),
        other => panic!("a regular file records a Sha256 post, got {other:?}"),
    }
}

                                                                                                     

/// One scanned source line: the file relative to `src/ceremony/`, the 1-based line number, and the
/// trimmed text.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    file: String,
    line: usize,
    text: String,
}

/// Every non-comment line under `dir` whose trimmed text contains one of `needles`.
fn scan_lines(dir: &Path, needles: &[&str]) -> Vec<Hit> {
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
        for (n, line) in text.lines().enumerate() {
            let s = line.trim();
            if s.starts_with("//") {
                continue;
            }
            if needles.iter().any(|x| s.contains(x)) {
                hits.push(Hit {
                    file: rel.clone(),
                    line: n + 1,
                    text: s.to_string(),
                });
            }
        }
    }
    hits.sort();
    hits
}

/// Row A'3's self-test: the scanner finds a planted violation, and reports nothing over a source
/// tree that carries none.
///
/// What it claims: over a scratch tree holding one planted `Command::new("git")` line, one planted
/// `.output()` line and one planted `from_utf8_lossy(&out.stdout)` line, `scan_lines` returns each
/// of them with its file and line number; over a scratch tree holding the same text inside `//`
/// comments it returns nothing. What it does NOT claim: anything about a spawn or a decode spelled
/// outside the needle set; that set is the model row A'3 names.
#[test]
fn the_git_seam_scanner_reddens_on_a_planted_violation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let live = tmp.path().join("live");
    std::fs::create_dir_all(live.join("sub")).expect("mk");
    std::fs::write(
        live.join("evader.rs"),
        "fn f() {\n    let c = std::process::Command::new(\"git\");\n    let o = c.output();\n}\n",
    )
    .expect("w");
    std::fs::write(
        live.join("sub/decoder.rs"),
        "fn g(out: &[u8]) -> String {\n    String::from_utf8_lossy(&out.stdout).to_string()\n}\n",
    )
    .expect("w");
    let hits = scan_lines(
        &live,
        &[
            "Command::new(\"git\")",
            ".output()",
            ".spawn()",
            "from_utf8_lossy",
        ],
    );
    let seen: Vec<(String, usize)> = hits.iter().map(|h| (h.file.clone(), h.line)).collect();
    assert_eq!(
        seen,
        vec![
            ("evader.rs".to_string(), 2),
            ("evader.rs".to_string(), 3),
            ("sub/decoder.rs".to_string(), 2),
        ],
        "the scanner did not report the planted violations at their lines: {hits:?}"
    );

    let commented = tmp.path().join("commented");
    std::fs::create_dir_all(&commented).expect("mk");
    std::fs::write(
        commented.join("quiet.rs"),
        "fn f() {\n    // std::process::Command::new(\"git\").output()\n    let x = 1;\n}\n",
    )
    .expect("w");
    assert!(
        scan_lines(
            &commented,
            &["Command::new(\"git\")", ".output()", "from_utf8_lossy"]
        )
        .is_empty(),
        "the scanner reports a commented-out line, so its normalization does not hold"
    );
}
