//! R16 fold-5 unit B' floor arms (delta v3.4 §2): the path types at the command line and the argv
//! hop. Every arm drives the built binary or the production `RunInvocation::argv`/`conduct` seam.

#[allow(dead_code)]
#[path = "common/admit.rs"]
mod admit;

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use orchard::ceremony::Utf8PathBuf;

/// The test-built `orchard` binary.
fn orchard_bin() -> &'static str {
    env!("CARGO_BIN_EXE_orchard")
}

/// Run `git` in `root`, panicking on a non-zero exit.
fn git(root: &Path, args: &[&str]) {
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
}

/// An `OsString` carrying `bytes` verbatim.
fn raw(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

/// Every path under `dir` with its bytes, for a byte-identity comparison across a run.
fn dir_bytes(dir: &Path) -> Vec<(OsString, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        out.push((e.file_name(), std::fs::read(e.path()).unwrap_or_default()));
    }
    out.sort();
    out
}

                                                                                                     

/// §2.2 + delta v3.5 §1.2 / rows B'1, F1: `orchard guide`, `run`, `admit` and `vendor` refuse a
/// non-UTF-8 path argument at the parser, with a non-zero exit and no command run.
///
/// What it claims: over the built binary, each of the eleven argv shapes below, given an argument
/// carrying byte 0xFF, exits non-zero with clap's own `invalid UTF-8` line, prints no ceremony
/// output, and leaves the key directory byte-identical; the same argv with that byte replaced by an
/// ASCII character gets past the parse (the control asserts the process no longer stops on the
/// parse). The eleven shapes are the eleven `Utf8PathBuf`-typed fields of `cli.rs`: the four
/// globals, `guide`'s and `run`'s profile and `--repo-form-dir`, `vendor --store`, and `admit`'s
/// `--box` and `--repo-form-dir`. What it does NOT claim: that a path argument this arm does not
/// name is refused, and nothing about a path that parses — the resolver's own UTF-8 domain is
/// `context_matrix.rs`'s. Blind spots, named: the four globals are driven on `run` only; a typed
/// field added after these eleven has no leg here; a field re-typed to `PathBuf` is caught only for
/// the argv shapes driven.
#[test]
fn a_non_utf8_path_argument_is_refused_at_the_parser_at_every_typed_field() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("repo-form");
    std::fs::create_dir_all(&dir).expect("mk repo-form");
    std::fs::write(dir.join("executing.keys"), "local\tzz.k\n").expect("seed a ratified file");
    let before = dir_bytes(&dir);

    let bad_profile = raw(b"boxes/bad-\xff.toml");
    let bad_dir = raw(b"repo-form-\xff");
    let bad_ctx = raw(b"ctx-\xff");
                                                                               
    let run_with = |flag: &str, value: &OsString| -> Vec<OsString> {
        vec![
            "run".into(),
            "boxes/alpha.toml".into(),
            "--target".into(),
            "203.0.113.5".into(),
            flag.into(),
            value.clone(),
        ]
    };
    let legs: Vec<(&str, Vec<OsString>)> = vec![
        ("guide profile", vec!["guide".into(), bad_profile.clone()]),
        (
            "guide --repo-form-dir",
            vec![
                "guide".into(),
                "boxes/alpha.toml".into(),
                "--repo-form-dir".into(),
                bad_dir.clone(),
            ],
        ),
        (
            "run profile",
            vec![
                "run".into(),
                bad_profile.clone(),
                "--target".into(),
                "203.0.113.5".into(),
            ],
        ),
        (
            "run --repo-form-dir",
            vec![
                "run".into(),
                "boxes/alpha.toml".into(),
                "--target".into(),
                "203.0.113.5".into(),
                "--repo-form-dir".into(),
                bad_dir.clone(),
            ],
        ),
        (
            "admit --box",
            vec!["admit".into(), "--box".into(), bad_profile.clone()],
        ),
        (
            "admit --repo-form-dir",
            vec![
                "admit".into(),
                "--box".into(),
                "boxes/alpha.toml".into(),
                "--repo-form-dir".into(),
                bad_dir.clone(),
            ],
        ),
        ("run --repo-root", run_with("--repo-root", &bad_ctx)),
        (
            "run --artifact-store",
            run_with("--artifact-store", &bad_ctx),
        ),
        ("run --repo-manifest", run_with("--repo-manifest", &bad_ctx)),
        ("run --context", run_with("--context", &bad_ctx)),
        (
            "vendor --store",
            vec!["vendor".into(), "--store".into(), bad_ctx.clone()],
        ),
    ];

    for (label, args) in &legs {
                                                                                    
        assert!(
            args.iter().any(|a| a.as_bytes().contains(&0xff)),
            "{label}: the leg carries no non-UTF-8 byte, so it proves nothing"
        );
        let out = std::process::Command::new(orchard_bin())
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path().join(".config"))
            .env("XDG_STATE_HOME", tmp.path().join(".state"))
            .env_remove("FRUIT_ARTIFACT_STORE")
            .env_remove("ORCHARD_LOCK_TOKEN")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn orchard");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.status.success(),
            "{label}: the binary exited 0 on a non-UTF-8 path argument:\n{text}"
        );
        assert!(
            text.contains("invalid UTF-8 was detected in one or more arguments"),
            "{label}: the stop is not the parser's own refusal:\n{text}"
        );
        assert!(
            !text.contains("refusal (") && !text.contains("step\tstep="),
            "{label}: a ceremony ran before the parse refused:\n{text}"
        );
        assert_eq!(
            dir_bytes(&dir),
            before,
            "{label}: the refused invocation changed the key directory"
        );
    }

                                                                                                   
                                              
    for (label, args) in &legs {
        let fixed: Vec<OsString> = args
            .iter()
            .map(|a| match a.as_bytes().contains(&0xff) {
                true => OsString::from(
                    String::from_utf8_lossy(a.as_bytes())
                        .replace('\u{fffd}', "z")
                        .to_string(),
                ),
                false => a.clone(),
            })
            .collect();
        assert!(
            fixed.iter().all(|a| !a.as_bytes().contains(&0xff)),
            "control {label}: the control argv still carries the byte"
        );
        let out = std::process::Command::new(orchard_bin())
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path().join(".config"))
            .env("XDG_STATE_HOME", tmp.path().join(".state"))
            .env_remove("FRUIT_ARTIFACT_STORE")
            .env_remove("ORCHARD_LOCK_TOKEN")
            .args(&fixed)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn orchard");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !text.contains("invalid UTF-8 was detected in one or more arguments"),
            "control {label}: a UTF-8 argument was refused at the parser:\n{text}"
        );
    }
}

                                                                                                  

/// §2.3 / rows B'2, E6: `orchard admit --repo-form-dir <d>` and the guided child `run` address the
/// same ratified file for a UTF-8 non-ASCII directory name, at an absolute `<d>` and at a relative
/// `<d>` resolved under the flag-tier repo root.
///
/// What it claims: over the two legs below, the built binary's `admit` writes
/// `<root>/<d>/executing.keys` and names that path, and `inv.ratified_file(&ctx.repo_root,
/// "executing")` — the same call `run_admit` and the commit gate address the file through — equals
/// it byte for byte, where `inv` is built from the `--repo-form-dir` the guide's composed argv
/// carries as clap parses it back. The repo root reaches both sides through `--repo-root` (the flag
/// tier), so a resolution against anything else lands elsewhere for the relative leg. The two
/// paths are also asserted to name one file by content. What it does NOT claim: that the two read
/// the same declared space (this compares the addressed path and the file identity), nor anything
/// about a directory spelling outside these two. Blind spots, named: the child argv is
/// `RunInvocation::argv`'s output parsed by clap in-process, not a spawned child; both legs run
/// against one checkout, so a per-run state difference is unmeasured.
#[test]
fn admit_and_the_guided_child_address_one_ratified_file_over_a_non_ascii_directory() {
    use clap::Parser as _;

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk repo");
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        git(&root, &args);
    }
    std::fs::write(root.join("repo-manifest.toml"), "schema-version = 1\n").expect("manifest");
    let profile = tmp.path().join("alpha.toml");
    std::fs::write(&profile, "ip = \"203.0.113.5\"\ndomain = \"box.test\"\n").expect("profile");

    let root_u8 = Utf8PathBuf::from(root.to_str().expect("utf8 test path"));
    let ctx = orchard::deploy::context::ResolvedContext {
        repo_root: root_u8.clone(),
        artifact_store: Utf8PathBuf::from(root.join("store").to_str().expect("utf8")),
        repo_manifest: Utf8PathBuf::from(root.join("repo-manifest.toml").to_str().expect("utf8")),
        sources: orchard::deploy::context::ContextSources {
            repo_root: orchard::deploy::context::ValueSource::Flag,
            artifact_store: orchard::deploy::context::ValueSource::Flag,
            repo_manifest: orchard::deploy::context::ValueSource::Flag,
            context_file: None,
        },
    };

                                                                                    
    let legs: Vec<(&str, PathBuf, &str)> = vec![
        (
            "absolute directory",
            root.join("boxes/repo-förm-café"),
            "boxes/repo-förm-café",
        ),
        (
            "relative directory under the flag-tier root",
            PathBuf::from("boxes/ratifié-förm"),
            "boxes/ratifié-förm",
        ),
    ];
    for (label, dir_arg, dir_field) in &legs {
        let written = root.join(dir_field).join("executing.keys");
                                                                                                  
                                         
        assert!(
            !dir_field.is_ascii() && !written.exists(),
            "{label}: the leg is ASCII or already ratified, so it proves nothing"
        );
        let (ok, text) = admit::run_admit(&root, &profile, dir_arg, "admit\n");
        assert!(ok, "{label}: admit did not exit 0:\n{text}");
        assert!(
            written.is_file(),
            "{label}: admit wrote no ratified file at {}:\n{text}",
            written.display()
        );
        assert!(
            text.contains(&format!("wrote {}", written.display())),
            "{label}: admit does not name the written path:\n{text}"
        );

                                                                                                
        let argv = orchard::ceremony::RunInvocation {
            profile_path: Utf8PathBuf::from("boxes/alpha.toml"),
            target: Some("203.0.113.5".to_string()),
            repo_form_dir: Some(Utf8PathBuf::from(*dir_field)),
            ..Default::default()
        }
        .argv(&ctx);
        let mut full = vec!["orchard".to_string()];
        full.extend(argv.iter().cloned());
        let cli = orchard::cli::Cli::try_parse_from(&full).expect("the child argv parses");
        let repo_form_dir = match cli.command {
            orchard::cli::OrchardCmd::Run { repo_form_dir, .. } => repo_form_dir,
            _ => panic!("{label}: the child argv the guide composes is not a run: {argv:?}"),
        };
        let inv = orchard::ceremony::RunInvocation {
            profile_path: Utf8PathBuf::from("boxes/alpha.toml"),
            repo_form_dir,
            ..Default::default()
        };
        let addressed = inv.ratified_file(&ctx.repo_root, "executing");
        assert_eq!(
            addressed.as_os_str().as_bytes(),
            written.as_os_str().as_bytes(),
            "{label}: the guided child addresses {} where admit wrote {}",
            addressed.display(),
            written.display()
        );

                                                                                                 
                            
        let name = dir_field
            .rsplit('/')
            .next()
            .expect("a last segment")
            .as_bytes();
        assert!(
            name.iter().any(|b| *b >= 0x80)
                && written
                    .as_os_str()
                    .as_bytes()
                    .windows(name.len())
                    .any(|w| w == name),
            "{label}: the written path does not carry the directory's bytes, so this leg proves \
             nothing: {}",
            written.display()
        );
        assert_eq!(
            std::fs::read(&written).expect("read the ratified file"),
            std::fs::read(PathBuf::from(OsStr::from_bytes(
                addressed.as_os_str().as_bytes()
            )))
            .expect("read the addressed file"),
            "{label}: the two paths do not name one file"
        );
    }
}
