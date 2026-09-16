                                                                                   
//! flag > profile > env > context file > builtin CWD default, source printing, and the two
                                                                                     
                                                                
//!
//! Unit arms drive `resolve_context_from` with injected inputs (no process-env races);
//! binary arms drive the real `orchard` binary via `--print-context` with a controlled
//! environment (HOME/XDG_CONFIG_HOME point into the fixture; the store env var is cleared
//! unless the arm sets it).

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use orchard::ceremony::{RefusalId, Utf8PathBuf};
use orchard::deploy::context::{
    ContextFlags, ContextInputs, ValueSource, manifest_default, merge_same_tier,
    resolve_context_from, store_default,
};
use orchard::deploy::profile::Profile;

/// Build a `Utf8PathBuf` from a test path (tmp paths are UTF-8).
fn u8(p: impl AsRef<Path>) -> Utf8PathBuf {
    Utf8PathBuf::from(p.as_ref().to_str().expect("utf8 test path"))
}

                                                                                                   

struct Fx {
    _tmp: tempfile::TempDir,
    /// An orchard-root-shaped dir: `crates/image-builder/` + `repo-manifest.toml`.
    root: PathBuf,
    /// An existing sibling store dir (NOT at `root/../artifact-store`).
    store: PathBuf,
    /// A HOME for the spawned binary (its XDG config base lives under it).
    home: PathBuf,
}

fn fx() -> Fx {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(root.join("crates/image-builder")).expect("mk root");
    std::fs::write(root.join("repo-manifest.toml"), "").expect("mk manifest");
    let store = tmp.path().join("store-elsewhere");
    std::fs::create_dir_all(&store).expect("mk store");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    Fx {
        _tmp: tmp,
        root,
        store,
        home,
    }
}

/// Inputs with every tier empty except what the arm sets. cwd = the fixture root.
fn bare_inputs<'a>(
    fx: &Fx,
    flags: &'a ContextFlags,
    profile: Option<&'a Profile>,
) -> ContextInputs<'a> {
    ContextInputs {
        flags,
        profile,
        env_store: None,
        cwd: fx.root.clone(),
        config_base: None,
    }
}

fn write_context_file(base: &Path, body: &str) -> PathBuf {
    let dir = base.join("recipes-deploy");
    std::fs::create_dir_all(&dir).expect("mk config dir");
    let p = dir.join("orchard-context.toml");
    std::fs::write(&p, body).expect("write context file");
    p
}

                                                                                                   

#[test]
fn canonical_checkout_resolves_via_cwd_default() {
    let fx = fx();
    let flags = ContextFlags::default();
    let ctx = resolve_context_from(&bare_inputs(&fx, &flags, None)).expect("resolves");
    assert_eq!(ctx.repo_root, u8(&fx.root));
    assert_eq!(ctx.artifact_store, u8(store_default(&fx.root)));
    assert_eq!(ctx.repo_manifest, u8(manifest_default(&fx.root)));
    assert_eq!(ctx.sources.repo_root, ValueSource::CwdDefault);
    assert_eq!(ctx.sources.artifact_store, ValueSource::CwdDefault);
    assert_eq!(ctx.sources.repo_manifest, ValueSource::CwdDefault);
}

#[test]
fn worktree_store_resolves_via_env() {
    let fx = fx();
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.env_store = Some(fx.store.clone());
    let ctx = resolve_context_from(&inp).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::Env);
}

#[test]
fn worktree_store_resolves_via_context_file() {
    let fx = fx();
    write_context_file(
        &fx.home.join(".config"),
        &format!("artifact_store = {:?}\n", fx.store.display().to_string()),
    );
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(fx.home.join(".config"));
    let ctx = resolve_context_from(&inp).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::File);
}

#[test]
fn env_overridden_store_wins_over_context_file() {
    let fx = fx();
    let file_store = fx.root.parent().unwrap().join("file-store");
    std::fs::create_dir_all(&file_store).expect("mk file store");
    write_context_file(
        &fx.home.join(".config"),
        &format!("artifact_store = {:?}\n", file_store.display().to_string()),
    );
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.env_store = Some(fx.store.clone());
    inp.config_base = Some(fx.home.join(".config"));
    let ctx = resolve_context_from(&inp).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::Env);
}

#[test]
fn profile_carried_store_wins_over_env() {
    let fx = fx();
    let profile = Profile {
        artifact_store: Some(fx.store.clone()),
        ..Profile::default()
    };
    let flags = ContextFlags::default();
    let env_store = fx.root.parent().unwrap().join("env-store");
    std::fs::create_dir_all(&env_store).expect("mk env store");
    let mut inp = bare_inputs(&fx, &flags, Some(&profile));
    inp.env_store = Some(env_store);
    let ctx = resolve_context_from(&inp).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::Profile);
}

#[test]
fn flag_wins_over_profile() {
    let fx = fx();
    let profile_store = fx.root.parent().unwrap().join("profile-store");
    std::fs::create_dir_all(&profile_store).expect("mk profile store");
    let profile = Profile {
        artifact_store: Some(profile_store),
        ..Profile::default()
    };
    let flags = ContextFlags {
        artifact_store: Some(u8(&fx.store)),
        ..ContextFlags::default()
    };
    let ctx = resolve_context_from(&bare_inputs(&fx, &flags, Some(&profile))).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::Flag);
}

#[test]
fn repo_manifest_default_follows_the_resolved_root() {
                                                                                            
    let fx = fx();
    let other = fx.root.parent().unwrap().join("other-root");
    std::fs::create_dir_all(other.join("crates/image-builder")).expect("mk other root");
    std::fs::write(other.join("repo-manifest.toml"), "").expect("mk other manifest");
    let flags = ContextFlags {
        repo_root: Some(u8(&other)),
        ..ContextFlags::default()
    };
    let ctx = resolve_context_from(&bare_inputs(&fx, &flags, None)).expect("resolves");
    assert_eq!(ctx.repo_root, u8(&other));
    assert_eq!(ctx.repo_manifest, u8(manifest_default(&other)));
}

                                                                                            

#[test]
fn unresolvable_named_store_refuses_naming_the_path_per_source() {
    let fx = fx();
    let gone = fx.root.parent().unwrap().join("no-such-store");

           
    let flags = ContextFlags {
        artifact_store: Some(u8(&gone)),
        ..ContextFlags::default()
    };
    let e = resolve_context_from(&bare_inputs(&fx, &flags, None))
        .unwrap_err()
        .to_string();
    assert!(e.contains("no-such-store"), "{e}");
    assert!(e.contains("--artifact-store") || e.contains("flag"), "{e}");

          
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.env_store = Some(gone.clone());
    let e = resolve_context_from(&inp).unwrap_err().to_string();
    assert!(
        e.contains("no-such-store") && e.contains("FRUIT_ARTIFACT_STORE"),
        "{e}"
    );

                   
    write_context_file(
        &fx.home.join(".config"),
        &format!("artifact_store = {:?}\n", gone.display().to_string()),
    );
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(fx.home.join(".config"));
    let e = resolve_context_from(&inp).unwrap_err().to_string();
    assert!(e.contains("no-such-store"), "{e}");
}

#[test]
fn unresolvable_named_repo_root_and_manifest_refuse() {
    let fx = fx();
                                                                          
    let not_root = fx.root.parent().unwrap().join("not-a-root");
    std::fs::create_dir_all(&not_root).expect("mk not-root");
    let flags = ContextFlags {
        repo_root: Some(u8(&not_root)),
        ..ContextFlags::default()
    };
    let e = resolve_context_from(&bare_inputs(&fx, &flags, None))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("not-a-root") && e.contains("crates/image-builder"),
        "{e}"
    );

                                                                  
    let flags = ContextFlags {
        repo_manifest: Some(u8(fx.root.join("no-such-manifest.toml"))),
        ..ContextFlags::default()
    };
    let e = resolve_context_from(&bare_inputs(&fx, &flags, None))
        .unwrap_err()
        .to_string();
    assert!(e.contains("no-such-manifest.toml"), "{e}");
}

#[test]
fn explicit_context_file_missing_refuses_default_location_absent_is_fine() {
    let fx = fx();
    let flags = ContextFlags {
        context_file: Some(u8(fx.root.join("gone-context.toml"))),
        ..ContextFlags::default()
    };
    let e = resolve_context_from(&bare_inputs(&fx, &flags, None))
        .unwrap_err()
        .to_string();
    assert!(e.contains("gone-context.toml"), "{e}");

                                                           
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(fx.home.join(".config"));                   
    assert!(resolve_context_from(&inp).is_ok());
}

#[test]
fn unknown_key_in_context_file_refuses_naming_it() {
    let fx = fx();
    write_context_file(&fx.home.join(".config"), "frobnicate = \"x\"\n");
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(fx.home.join(".config"));
    let e = resolve_context_from(&inp).unwrap_err().to_string();
    assert!(e.contains("frobnicate") || e.contains("unknown"), "{e}");
}

#[test]
fn relative_context_file_value_resolves_against_the_file_dir() {
    let fx = fx();
    let base = fx.home.join(".config");
    let file = write_context_file(&base, "artifact_store = \"rel-store\"\n");
    let rel_store = file.parent().unwrap().join("rel-store");
    std::fs::create_dir_all(&rel_store).expect("mk rel store");
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(base);
    let ctx = resolve_context_from(&inp).expect("resolves");
    assert_eq!(ctx.artifact_store, u8(&rel_store));
}

#[test]
fn relative_profile_context_path_refuses() {
    let fx = fx();
    let profile = Profile {
        artifact_store: Some(PathBuf::from("relative/store")),
        ..Profile::default()
    };
    let flags = ContextFlags::default();
    let e = resolve_context_from(&bare_inputs(&fx, &flags, Some(&profile)))
        .unwrap_err()
        .to_string();
    assert!(e.contains("absolute"), "{e}");
}

#[test]
fn non_repo_cwd_default_refuses_with_the_override_cure() {
    let fx = fx();
    let elsewhere = fx.root.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mk elsewhere");
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.cwd = elsewhere;
    let e = resolve_context_from(&inp).unwrap_err().to_string();
    assert!(e.contains("--repo-root"), "cure names the override: {e}");
}

/// The cure line of a rendered refusal. Fail-closed: a detail that also carried a `cure: ` line
/// would make the extraction ambiguous, so more or fewer than one match is a red.
fn cure_line(render: &str) -> &str {
    let hits: Vec<&str> = render
        .lines()
        .filter_map(|l| l.strip_prefix("  cure: "))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one cure line in the render: {render}"
    );
    hits[0]
}

/// The one `context-file-invalid` cure, frozen whole.
const CONTEXT_FILE_INVALID_CURE: &str = "the context file must exist (an explicitly named \
     --context file has no silent fallback) and be readable (check its ownership and \
     permissions), and its schema is exactly {repo_root, artifact_store, repo_manifest}";

                                                                                                
/// cure has to name a remedy for each; the read-I/O producer (an EACCES on a present, well-formed
/// file) is the one the schema+existence cure was false at.
///
/// The claim is over the COMPOSED refusal an operator receives at each producer: the detail names
/// that producer's own cause, and the one cure carries all three remedies. The cure is frozen
/// whole (exact equality), so an edit dropping a clause reddens here rather than at the site that
/// stops rendering its remedy.
///
/// What this does NOT hold: that `deploy/context.rs` has exactly these three producers. The count
/// is held by `ceremony_selftests`' per-file `RefusalId` census; a FOURTH producer with a remedy
/// class outside the union would be a new finding, not a red here.
#[test]
fn every_context_file_invalid_producer_renders_the_remedy_for_its_own_cause() {
    use std::os::unix::fs::PermissionsExt;

    let fx = fx();
    let missing = fx.home.join("gone-context.toml");
    let unreadable = fx.home.join("unreadable-context.toml");
    std::fs::write(&unreadable, "repo_root = \"/tmp\"\n").expect("write unreadable fixture");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let bad_schema = fx.home.join("bad-schema-context.toml");
    std::fs::write(&bad_schema, "frobnicate = \"x\"\n").expect("write bad-schema fixture");

                                                                                                 
                                                                                          
    if std::fs::read_to_string(&unreadable).is_ok() {
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
        panic!(
            "a 0o000 file is still readable here (running as root, or a mount that ignores the \
             mode), so this arm cannot express an unreadable context file"
        );
    }

                                                                                               
                                                                                            
                                                                       
    let legs: [(&str, &PathBuf, &str, &str); 3] = [
        (
            "read I/O",
            &unreadable,
            "read context file ",
            "be readable (check its ownership and permissions)",
        ),
        (
            "existence",
            &missing,
            "--context names ",
            "the context file must exist",
        ),
        (
            "parse",
            &bad_schema,
            "context file ",
            "its schema is exactly {repo_root, artifact_store, repo_manifest}",
        ),
    ];
    for (producer, path, detail_head, remedy) in legs {
        let flags = ContextFlags {
            context_file: Some(u8(path)),
            ..ContextFlags::default()
        };
        let e = resolve_context_from(&bare_inputs(&fx, &flags, None))
            .expect_err("an unusable context file refuses");
        assert_eq!(
            e.id.token(),
            "context-file-invalid",
            "{producer}: {}",
            e.detail
        );
        assert!(
            e.detail.starts_with(detail_head),
            "{producer}: another producer refused, so this leg proves nothing about {producer}: {}",
            e.detail
        );
        let render = e.to_string();
        let cure = cure_line(&render);
        assert!(
            cure.contains(remedy),
            "{producer}: the cure this producer renders carries no remedy for its own cause \
             ({remedy:?}): {render}"
        );
        assert_eq!(
            cure, CONTEXT_FILE_INVALID_CURE,
            "{producer}: the composed cure moved: {render}"
        );
    }

                                                                                             
                                                                                 
    let flags = ContextFlags {
        context_file: Some(u8(&unreadable)),
        ..ContextFlags::default()
    };
    let e = resolve_context_from(&bare_inputs(&fx, &flags, None)).expect_err("EACCES refuses");
    assert!(
        e.detail.contains("Permission denied"),
        "the read-I/O leg reached the io::Error producer: {}",
        e.detail
    );
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).expect("unseal");
    let after = std::fs::read_to_string(&unreadable).expect("the fixture file was well-formed");
    assert_eq!(
        after, "repo_root = \"/tmp\"\n",
        "the file the EACCES leg refused exists and holds valid schema, so 'must exist' and \
         'schema is exactly' were both satisfied at that site"
    );
}

                                                                                      
/// merge; two directories refuse.
///
/// What it claims: over `merge_same_tier`, two values whose text differs but whose `Path`
/// components are equal (a trailing separator, a doubled separator, a `.` component) merge in both
/// argument orders and return the first argument verbatim, while `/a` against `/b` and two
/// directories under one prefix refuse `context-conflict` naming both flags and both values. The
/// merged value is read through `as_str()`, so the assertion is not made with the equality it
/// measures. What it does NOT claim: normalization — `Path` compares components without resolving
/// `..` or symlinks, so `/p/a/../store` and `/p/store` are two directories here; nothing about
/// case, which is a byte comparison on a case-sensitive filesystem. Blind spots, named: the merge
/// is driven at this function, and the one production call site
/// (`ContextFlags::with_store_override`) is driven by
/// `two_same_tier_spellings_of_one_store_resolve_through_the_binary`.
#[test]
fn merge_same_tier_refuses_two_disagreeing_flags() {
    let a = Utf8PathBuf::from("/a");
    let b = Utf8PathBuf::from("/b");
    let refused = merge_same_tier(
        "--artifact-store",
        Some(a.clone()),
        "--store",
        Some(b.clone()),
    )
    .unwrap_err();
    assert_eq!(refused.id, RefusalId::ContextConflict, "{refused}");
    let e = refused.to_string();
    assert!(
        e.contains("/a") && e.contains("/b"),
        "names both values: {e}"
    );
    assert!(
        e.contains("--artifact-store") && e.contains("--store"),
        "{e}"
    );
    assert_eq!(
        merge_same_tier(
            "--artifact-store",
            Some(a.clone()),
            "--store",
            Some(a.clone())
        )
        .unwrap(),
        Some(a.clone())
    );
    assert_eq!(
        merge_same_tier("--artifact-store", None, "--store", Some(b.clone())).unwrap(),
        Some(b)
    );
    assert_eq!(
        merge_same_tier("--artifact-store", Some(a.clone()), "--store", None).unwrap(),
        Some(a)
    );

                                                                       
    let plain = Utf8PathBuf::from("/p/store");
    for spelling in ["/p/store/", "/p//store", "/p/./store"] {
        let spelled = Utf8PathBuf::from(spelling);
                                                                                         
        assert_ne!(
            spelled.as_str(),
            plain.as_str(),
            "the leg's two values are one text, so the leg measures nothing"
        );
        let merged = merge_same_tier(
            "--artifact-store",
            Some(spelled.clone()),
            "--store",
            Some(plain.clone()),
        )
        .unwrap_or_else(|e| panic!("{spelling} against /p/store refused: {e}"));
        assert_eq!(
            merged.as_ref().map(Utf8PathBuf::as_str),
            Some(spelling),
            "the merge of {spelling} and /p/store returned another value"
        );
        let merged = merge_same_tier(
            "--artifact-store",
            Some(plain.clone()),
            "--store",
            Some(spelled.clone()),
        )
        .unwrap_or_else(|e| panic!("/p/store against {spelling} refused: {e}"));
        assert_eq!(
            merged.as_ref().map(Utf8PathBuf::as_str),
            Some(plain.as_str()),
            "the merge of /p/store and {spelling} returned another value"
        );
    }
                                                     
    let refused = merge_same_tier(
        "--artifact-store",
        Some(plain.clone()),
        "--store",
        Some(Utf8PathBuf::from("/p/store2")),
    )
    .unwrap_err();
    assert_eq!(refused.id, RefusalId::ContextConflict, "{refused}");
}

                                                                                                    

/// `<parent>/<name>-\xff`, created. The returned path is not UTF-8.
fn non_utf8_dir(parent: &Path, name: &str) -> PathBuf {
    let mut bytes = parent.join(name).into_os_string().into_vec();
    bytes.extend_from_slice(b"-\xff");
    let p = PathBuf::from(OsString::from_vec(bytes));
    std::fs::create_dir_all(&p).expect("mk a non-UTF-8 dir");
    assert!(
        p.to_str().is_none(),
        "the fixture dir is UTF-8, so the leg it carries proves nothing"
    );
    p
}

/// A fixture path as text, refusing a byte `escape_ascii` would escape: the expected samples below
/// are hand literals and stay hand literals only while the tmp prefix escapes to itself.
fn ascii_prefix(p: &Path) -> String {
    let s = p.to_str().expect("utf8 fixture path").to_string();
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b)),
        "the fixture prefix {s} carries a byte escape_ascii would escape"
    );
    s
}

const NOT_UTF8_CURE: &str = "rename the path the detail names so it is UTF-8 text, or supply a \
     UTF-8 path at a higher tier (the flag, the profile, the env var, the context file), then \
     re-run";

/// The whole refusal an operator receives, as a hand literal.
fn not_utf8_refusal(key: &str, tier: &str, sample: &str) -> String {
    format!(
        "refusal (context-not-utf8): the {key} resolved from the {tier} tier is not UTF-8 text: \
         {sample}\n  cure: {NOT_UTF8_CURE}"
    )
}

/// delta v3.5 §1.4 / row F2: `resolve_context_from` refuses a resolved context path that is not
/// UTF-8, at each tier whose value can carry OS bytes, naming the key, the winning tier and the
/// escaped sample.
///
/// What it claims: over `ContextInputs`, a non-UTF-8 winner at the CWD-default tier (`cwd`), the
/// env tier (`env_store`), the file tier (a relative context-file value under a non-UTF-8 config
/// base) and the flag tier (a relative `--repo-root` absolutized against a non-UTF-8 `cwd`, §7
/// Q-cwd-absolutize) each returns `Err` whose whole composed refusal equals the literal above,
/// and no `ResolvedContext` is produced; the same four constructions with an ASCII directory name
/// resolve, so each leg measures the encoding and not the shape. What it does NOT claim: anything
/// about a path the tier's own existence check rejects first — `utf8_context_path` runs after the
/// pick's check, so a non-existent non-UTF-8 path refuses `context-unresolvable`; and nothing about
/// the profile tier, whose values are toml strings (§7 Q-profile-tier). Blind spots, named: the
/// sample's length cut is not driven, the fixture paths being shorter than it; the escape of a byte
/// other than 0xFF is not driven; each of the three keys is driven at one tier only, so a
/// tier-and-key combination other than the five below is unseen.
#[test]
fn a_non_utf8_resolved_context_path_refuses_naming_the_key_the_tier_and_the_sample() {
    let fx = fx();
    let base = fx.root.parent().expect("tmp base").to_path_buf();
    let prefix = ascii_prefix(&base);

                                                                                                   
                              
    let bad_cwd = non_utf8_dir(&base, "root");
    std::fs::create_dir_all(bad_cwd.join("crates/image-builder")).expect("mk root shape");
    let flags = ContextFlags::default();
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.cwd = bad_cwd.clone();
    let e = resolve_context_from(&inp).expect_err("a non-UTF-8 cwd default must refuse");
    assert_eq!(e.id, RefusalId::ContextNotUtf8, "{e}");
    assert_eq!(
        e.to_string(),
        not_utf8_refusal("repo root", "cwd default", &format!("{prefix}/root-\\xff"))
    );

                                                                 
    let ok_cwd = base.join("root-ok");
    std::fs::create_dir_all(ok_cwd.join("crates/image-builder")).expect("mk root shape");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.cwd = ok_cwd.clone();
    let ctx = resolve_context_from(&inp).expect("the ASCII control resolves");
    assert_eq!(ctx.repo_root, u8(&ok_cwd));
    assert_eq!(ctx.sources.repo_root, ValueSource::CwdDefault);

                                                                                          
                  
    let bad_store = non_utf8_dir(&base, "store");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.env_store = Some(bad_store.clone());
    let e = resolve_context_from(&inp).expect_err("a non-UTF-8 env store must refuse");
    assert_eq!(e.id, RefusalId::ContextNotUtf8, "{e}");
    assert_eq!(
        e.to_string(),
        not_utf8_refusal("artifact store", "env", &format!("{prefix}/store-\\xff"))
    );

                     
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.env_store = Some(fx.store.clone());
    let ctx = resolve_context_from(&inp).expect("the ASCII control resolves");
    assert_eq!(ctx.artifact_store, u8(&fx.store));
    assert_eq!(ctx.sources.artifact_store, ValueSource::Env);

                                                                                                    
                                                              
    let bad_base = non_utf8_dir(&base, "cfg");
    write_context_file(&bad_base, "repo_root = \"root\"\n");
    let file_root = bad_base.join("recipes-deploy/root");
    std::fs::create_dir_all(file_root.join("crates/image-builder")).expect("mk file root");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(bad_base.clone());
    let e = resolve_context_from(&inp).expect_err("a non-UTF-8 file-tier value must refuse");
    assert_eq!(e.id, RefusalId::ContextNotUtf8, "{e}");
    assert_eq!(
        e.to_string(),
        not_utf8_refusal(
            "repo root",
            "file",
            &format!("{prefix}/cfg-\\xff/recipes-deploy/root")
        )
    );

                                                               
    let ok_base = base.join("cfg-ok");
    write_context_file(&ok_base, "repo_root = \"root\"\n");
    let ok_file_root = ok_base.join("recipes-deploy/root");
    std::fs::create_dir_all(ok_file_root.join("crates/image-builder")).expect("mk file root");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(ok_base);
    let ctx = resolve_context_from(&inp).expect("the ASCII control resolves");
    assert_eq!(ctx.repo_root, u8(&ok_file_root));
    assert_eq!(ctx.sources.repo_root, ValueSource::File);

                                                                                                   
                                                   
    std::fs::create_dir_all(bad_cwd.join("sub/crates/image-builder")).expect("mk flag root");
    let flags_rel = ContextFlags {
        repo_root: Some(Utf8PathBuf::from("sub")),
        ..ContextFlags::default()
    };
    let mut inp = bare_inputs(&fx, &flags_rel, None);
    inp.cwd = bad_cwd.clone();
    let e = resolve_context_from(&inp).expect_err("a relative flag under a non-UTF-8 cwd refuses");
    assert_eq!(e.id, RefusalId::ContextNotUtf8, "{e}");
    assert_eq!(
        e.to_string(),
        not_utf8_refusal("repo root", "flag", &format!("{prefix}/root-\\xff/sub"))
    );

                                                                
    std::fs::create_dir_all(ok_cwd.join("sub/crates/image-builder")).expect("mk flag root");
    let mut inp = bare_inputs(&fx, &flags_rel, None);
    inp.cwd = ok_cwd.clone();
    let ctx = resolve_context_from(&inp).expect("the ASCII control resolves");
    assert_eq!(ctx.repo_root, u8(ok_cwd.join("sub")));
    assert_eq!(ctx.sources.repo_root, ValueSource::Flag);

                                                                                               
                                                                                                 
    let man_base = non_utf8_dir(&base, "man");
    let man_file = write_context_file(&man_base, "repo_manifest = \"m.toml\"\n");
    std::fs::write(man_file.parent().expect("file dir").join("m.toml"), "")
        .expect("mk file manifest");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(man_base);
    let e = resolve_context_from(&inp).expect_err("a non-UTF-8 file-tier manifest must refuse");
    assert_eq!(e.id, RefusalId::ContextNotUtf8, "{e}");
    assert_eq!(
        e.to_string(),
        not_utf8_refusal(
            "repo manifest",
            "file",
            &format!("{prefix}/man-\\xff/recipes-deploy/m.toml")
        )
    );

                                                               
    let ok_man_base = base.join("man-ok");
    let ok_man_file = write_context_file(&ok_man_base, "repo_manifest = \"m.toml\"\n");
    let ok_man = ok_man_file.parent().expect("file dir").join("m.toml");
    std::fs::write(&ok_man, "").expect("mk file manifest");
    let mut inp = bare_inputs(&fx, &flags, None);
    inp.config_base = Some(ok_man_base);
    let ctx = resolve_context_from(&inp).expect("the ASCII control resolves");
    assert_eq!(ctx.repo_manifest, u8(&ok_man));
    assert_eq!(ctx.sources.repo_manifest, ValueSource::File);
}

/// delta v3.5 §1.4 / row F2 at the live binding: `orchard` refuses a non-UTF-8 context path read
/// from the process environment or the working directory, with the refusal exit class and the
/// whole refusal on stderr.
///
/// What it claims: the built binary given `FRUIT_ARTIFACT_STORE` carrying byte 0xFF, and the built
/// binary run in a repo-root-shaped working directory carrying byte 0xFF, each exit 2 with the
/// whole composed refusal on stderr and no context printed on stdout. Its margin over the arm
/// above is the live binding: `resolve_context` reads both through the OS-byte APIs
/// (`non_empty_var_os`, `current_dir`), so a read narrowed to `String` would drop the variable to
/// the next tier silently instead of refusing. What it does NOT claim: anything about the other
/// two tiers, which this arm does not drive. Blind spots, named: the exit code 2 is the refusal
/// exit class, pinned here as a literal; the arm does not verify which tier the value would fall
/// through to if it were dropped.
#[test]
fn a_non_utf8_env_store_or_cwd_refuses_through_the_binary() {
    let fx = fx();
    let base = fx.root.parent().expect("tmp base").to_path_buf();
    let prefix = ascii_prefix(&base);

    let bad_store = non_utf8_dir(&base, "store");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .env("FRUIT_ARTIFACT_STORE", &bad_store)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains(&not_utf8_refusal(
            "artifact store",
            "env",
            &format!("{prefix}/store-\\xff")
        )),
        "the env-tier refusal is not the composed text: {stderr}"
    );
    assert!(
        !stdout.contains("context ("),
        "a context was printed: {stdout}"
    );

    let bad_cwd = non_utf8_dir(&base, "root");
    std::fs::create_dir_all(bad_cwd.join("crates/image-builder")).expect("mk root shape");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .current_dir(&bad_cwd)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains(&not_utf8_refusal(
            "repo root",
            "cwd default",
            &format!("{prefix}/root-\\xff")
        )),
        "the cwd-tier refusal is not the composed text: {stderr}"
    );
    assert!(
        !stdout.contains("context ("),
        "a context was printed: {stdout}"
    );
}

                                                                                                   

fn orchard(fx: &Fx) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_orchard"));
    c.current_dir(&fx.root)
        .env_remove("FRUIT_ARTIFACT_STORE")
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env_remove("RECIPES_DHA_WEIGHTS_GGUF")
        .env_remove("RECIPES_DHA_MMPROJ_GGUF")
        .env("HOME", &fx.home)
        .env("XDG_CONFIG_HOME", fx.home.join(".config"))
        .env("XDG_STATE_HOME", fx.home.join(".state"))
                                                                
        .env("ORCHARD_LOCK_DIR", fx.home.join(".ceremony-lock"));
    c
}

fn run(c: &mut Command) -> (bool, String, String) {
    let out = c.output().expect("spawn orchard");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Like `run`, but returns the exact exit CODE (records assert on the code, not just success).
fn run_code(c: &mut Command) -> (Option<i32>, String, String) {
    let out = c.output().expect("spawn orchard");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Count porcelain records of a kind on stdout. A record is tab-separated (`result\tverb=…`), so
/// the first tab-field is the kind token.
fn count_record(stdout: &str, kind: &str) -> usize {
    stdout
        .lines()
        .filter(|l| l.split('\t').next() == Some(kind))
        .count()
}

#[test]
fn print_context_canonical_prints_cwd_default_sources() {
    let fx = fx();
    let (ok, stdout, stderr) = run(orchard(&fx).args(["--print-context", "vendor"]));
    assert!(ok, "exit 0; stderr: {stderr}");
    assert!(stdout.contains("repo_root"), "{stdout}");
    assert!(stdout.contains(&fx.root.display().to_string()), "{stdout}");
    assert_eq!(stdout.matches("(cwd default)").count(), 3, "{stdout}");
}

#[test]
fn print_context_env_store_prints_env_source() {
    let fx = fx();
    let (ok, stdout, _) = run(orchard(&fx)
        .env("FRUIT_ARTIFACT_STORE", &fx.store)
        .args(["--print-context", "vendor"]));
    assert!(ok);
    assert!(stdout.contains(&fx.store.display().to_string()), "{stdout}");
    assert!(stdout.contains("(env)"), "{stdout}");
}

#[test]
fn print_context_porcelain_success_suppresses_the_result_record() {
                                                                                                   
                                                                                                  
                                                                                                  
                                                               
    let fx = fx();
    let (code, stdout, stderr) =
        run_code(orchard(&fx).args(["--print-context", "vendor", "--porcelain"]));
    assert_eq!(
        code,
        Some(0),
        "clean print-context exits 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("repo_root"),
        "the context is printed: {stdout}"
    );
    assert_eq!(
        count_record(&stdout, "result"),
        0,
        "no result record for an unrun verb: {stdout}"
    );
    assert_eq!(
        count_record(&stdout, "refusal"),
        0,
        "a clean print-context does not refuse: {stdout}"
    );
}

#[test]
fn print_context_porcelain_refusal_still_emits_both_records() {
                                                                                       
                                                                                                  
                                                                                               
                                                                                                 
                                                                      
    let fx = fx();
    let profile = fx.root.join("skew.toml");
    std::fs::write(&profile, "schema_version = 99\n").expect("write skew profile");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .args(["--print-context", "build", "--porcelain"])
            .arg("--profile")
            .arg(&profile),
    );
    assert_eq!(
        code,
        Some(2),
        "a refusal is exit 2 (refusal-with-cure); stderr: {stderr}"
    );
    assert_eq!(
        count_record(&stdout, "refusal"),
        1,
        "the refusal record carries the id + cure a porcelain consumer needs: {stdout}"
    );
    assert_eq!(
        count_record(&stdout, "result"),
        1,
        "the result record still closes the run: {stdout}"
    );
    assert!(
        stdout.contains("profile-schema-skew") || stdout.contains("schema"),
        "the refusal names the schema-skew id: {stdout}"
    );
}

#[test]
fn print_context_folds_the_profile_tier_for_every_profile_carrying_verb() {
                                                                                                  
                                                                                                 
                                                                                                       
                                                                                                     
                                                                                                  
                                                                                         
                                                                            
      
                                                                                                  
                                                                                                   
                                                                                           
                                                               
      
                                                                                                     
                                                                                                   
                                                                        
    use clap::CommandFactory;
    let fx = fx();
    let root = orchard::cli::Cli::command();
    let profile_verbs: Vec<String> = root
        .get_subcommands()
        .filter(|c| c.get_arguments().any(|a| a.get_id().as_str() == "profile"))
        .map(|c| c.get_name().to_string())
        .collect();
    assert!(
        ["build", "prod", "run", "guide"]
            .iter()
            .all(|w| profile_verbs.iter().any(|v| v == w)),
        "the derivation must reach build/prod (--profile) and run/guide (positional): \
         {profile_verbs:?}"
    );
                                                                                                   
                                                                                       
    let profile = fx.root.join("box.toml");
    std::fs::write(
        &profile,
        format!("artifact_store = {:?}\n", fx.store.display().to_string()),
    )
    .expect("write profile");
    for verb in &profile_verbs {
        let node = root
            .get_subcommands()
            .find(|c| c.get_name() == verb)
            .expect("the verb node");
        let profile_is_positional = node
            .get_positionals()
            .any(|p| p.get_id().as_str() == "profile");
        let mut args: Vec<String> = vec!["--print-context".into(), verb.clone()];
        for pos in node.get_positionals() {
            if pos.get_id().as_str() == "profile" {
                args.push(profile.display().to_string());
            } else if pos.is_required_set() {
                args.push("203.0.113.9".into());
            }
        }
        if !profile_is_positional {
            args.push("--profile".into());
            args.push(profile.display().to_string());
        }
        let (code, stdout, stderr) = run_code(orchard(&fx).args(&args));
        assert_eq!(code, Some(0), "{args:?} must print the context: {stderr}");
        assert!(
            stdout.contains(&fx.store.display().to_string()),
            "{verb}: --print-context does not report the PROFILE's artifact_store, so it is \
             reporting a context this verb will not use. Extend \
             `main.rs::profile_path_of` with this verb.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("(profile)"),
            "{verb}: the render carries no `(profile)` source label — the profile tier was not \
             folded.\nstdout: {stdout}"
        );
    }
}

#[test]
fn machine_stdout_survives_a_closed_downstream_pipe() {
                                                                                               
                                                                                                
                                                                                                   
                                                                                                     
                                                                                          
    let fx = fx();
    let mut child = orchard(&fx)
        .args(["--print-context", "vendor"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard");
    drop(child.stdout.take());                      
    let status = child.wait().expect("wait");
    assert_ne!(
        status.code(),
        Some(101),
        "a closed stdout pipe must not panic the machine surface to 101 (revert to println!)"
    );
    assert!(
        status.code().is_some(),
        "the process was killed by a signal — SIGPIPE is not SIG_IGN (a global SIG_DFL regressed)"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "print-context still exits 0 with the pipe closed"
    );
}

#[test]
fn empty_env_path_vars_are_treated_as_unset_not_cwd_relative() {
                                                                                                  
                                                                                                    
                                                                                           
    let fx = fx();
    let planted = fx.root.join("recipes-deploy").join("orchard-context.toml");
    std::fs::create_dir_all(planted.parent().unwrap()).expect("mk planted dir");
    std::fs::write(
        &planted,
        format!("artifact_store = {:?}\n", fx.store.display().to_string()),
    )
    .expect("write planted context");

                                                                                                         
    let (ok, out, err) = run(orchard(&fx)
        .env("XDG_CONFIG_HOME", "")
        .args(["--print-context", "vendor"]));
    assert!(ok, "stderr: {err}");
    assert!(
        !out.contains("(file)"),
        "empty XDG_CONFIG_HOME must not load a CWD-relative context file: {out}"
    );
    assert!(
        !out.contains(&fx.store.display().to_string()),
        "the planted CWD store must not win via an empty XDG base: {out}"
    );

                                                                           
    let (ok2, out2, _) = run(orchard(&fx)
        .env("FRUIT_ARTIFACT_STORE", "")
        .args(["--print-context", "vendor"]));
    assert!(ok2);
    assert!(
        !out2.contains("(env)"),
        "empty FRUIT_ARTIFACT_STORE must be unset, not resolve the store to the CWD as (env): {out2}"
    );
}

/// A repo-root-shaped dir: `crates/image-builder/`, a `[workspace]` Cargo.toml, a manifest.
fn make_repo_shaped(dir: &Path) {
    std::fs::create_dir_all(dir.join("crates/image-builder")).expect("mk repo");
    std::fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n").expect("mk Cargo.toml");
    std::fs::write(dir.join("repo-manifest.toml"), "").expect("mk manifest");
}

#[test]
fn artifact_root_pin_writer_honors_the_resolved_root_not_the_cwd() {
                                                                                                   
                                                                                                   
                                                                                                      
                                                                                                     
                                                                                             
                                                                                                      
                                             
    let fx = fx();
    make_repo_shaped(&fx.root);
    let b = fx.root.parent().unwrap().join("checkout-b");
    make_repo_shaped(&b);
    let keys = fx.root.parent().unwrap().join("keys");

    let (code, out, err) = run_code(
        orchard(&fx)
            .arg("--repo-root")
            .arg(&b)
            .args(["generate-keys", "--artifact-signing", "software"])
            .arg("--output-dir")
            .arg(&keys),
    );
    assert_eq!(
        code,
        Some(0),
        "generate-keys --artifact-signing software; stderr: {err}\nstdout: {out}"
    );

    let pin_b = b.join("crates/image-builder/pinned-artifact-root.toml");
    let pin_a = fx
        .root
        .join("crates/image-builder/pinned-artifact-root.toml");
    assert!(
        pin_b.is_file(),
        "the pin lands under the RESOLVED root B: {}",
        pin_b.display()
    );
    assert!(
        !pin_a.exists(),
        "the pin must NOT land under the CWD A: {}",
        pin_a.display()
    );

                                                                                                 
            
    let (pc, pcout, pcerr) = run_code(
        orchard(&fx)
            .arg("--repo-root")
            .arg(&b)
            .args(["--print-context", "generate-keys"]),
    );
    assert_eq!(pc, Some(0), "stderr: {pcerr}");
    assert!(
        pcout.contains(&b.display().to_string()),
        "print-context reports the resolved root B: {pcout}"
    );
}

#[test]
fn clap_usage_error_exits_failed_not_clap_default_two() {
                                                                                                    
                                                                                                 
                                                                                                       
                                                                                                     
                                                                                                 
                                                                                           
                                                                                           
    let fx = fx();
    for argv in [
        &[][..],
        &["market"],
        &["market", "store"],
        &["--no-such-global-flag"],
        &["no-such-verb"],
    ] {
        let (code, _, err) = run_code(orchard(&fx).args(argv));
        assert_eq!(
            code,
            Some(1),
            "argv {argv:?} is a usage error → failed/1, not clap's 2; stderr: {err}"
        );
    }
                                                                                                 
    let (help, help_out, _) = run_code(orchard(&fx).arg("--help"));
    assert_eq!(help, Some(0), "--help exits 0");
    assert!(
        help_out.contains("orchard") || help_out.contains("Usage"),
        "{help_out}"
    );
    let (version, _, _) = run_code(orchard(&fx).arg("--version"));
    assert_eq!(version, Some(0), "--version exits 0");
}

#[test]
fn xdg_config_home_locates_the_context_file() {
                                                                                 
    let fx = fx();
    write_context_file(
        &fx.home.join(".config"),
        &format!("artifact_store = {:?}\n", fx.store.display().to_string()),
    );
    let (ok, stdout, stderr) = run(orchard(&fx).args(["--print-context", "vendor"]));
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(&fx.store.display().to_string()), "{stdout}");
    assert!(stdout.contains("(file)"), "{stdout}");
}

#[test]
fn profile_carried_store_wins_over_env_through_the_binary() {
    let fx = fx();
    let env_store = fx.root.parent().unwrap().join("env-store");
    std::fs::create_dir_all(&env_store).expect("mk env store");
    let profile = fx.root.join("box.toml");
    std::fs::write(
        &profile,
        format!(
            "domain = \"box.test\"\nartifact_store = {:?}\n",
            fx.store.display().to_string()
        ),
    )
    .expect("write profile");
    let (ok, stdout, stderr) = run(orchard(&fx)
        .env("FRUIT_ARTIFACT_STORE", &env_store)
        .args(["--print-context", "build"])
        .arg("--profile")
        .arg(&profile));
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(&fx.store.display().to_string()), "{stdout}");
    assert!(stdout.contains("(profile)"), "{stdout}");
}

#[test]
fn same_tier_disagreement_refuses_naming_both_values() {
    let fx = fx();
    let other = fx.root.parent().unwrap().join("other-store");
    std::fs::create_dir_all(&other).expect("mk other store");

                              
    let (ok, _, stderr) = run(orchard(&fx)
        .arg("--print-context")
        .arg("--artifact-store")
        .arg(&fx.store)
        .args(["vendor", "--store"])
        .arg(&other));
    assert!(!ok);
    assert!(
        stderr.contains(&fx.store.display().to_string())
            && stderr.contains(&other.display().to_string()),
        "names both: {stderr}"
    );

                                                              
    let (ok, _, stderr) = run(orchard(&fx)
        .arg("--artifact-store")
        .arg(&fx.store)
        .args(["vendor", "--store"])
        .arg(&other));
    assert!(!ok);
    assert!(
        stderr.contains(&fx.store.display().to_string())
            && stderr.contains(&other.display().to_string()),
        "names both: {stderr}"
    );
}

                                                                                              
/// shape: the file line, then one `value  (source)` line per key.
fn printed_context(file_line: &str, values: [(&str, &str); 3]) -> String {
    format!(
        "context ({file_line})\n  repo_root      = {}  ({})\n  artifact_store = {}  ({})\n  \
         repo_manifest  = {}  ({})\n",
        values[0].0, values[0].1, values[1].0, values[1].1, values[2].0, values[2].1
    )
}

/// A fixture path as text.
fn text(p: &Path) -> &str {
    p.to_str().expect("utf8 fixture path")
}

/// delta v3.6 §5 row H1 at the live binding: the global `--artifact-store` and the verb-local
/// `vendor --store` naming ONE directory in two spellings resolve.
///
/// What it claims: the built binary given `--artifact-store <P>/store-elsewhere/` (and the
/// doubled-separator and `.`-component spellings) beside `vendor --store <P>/store-elsewhere`
/// exits 0 and prints the whole context, `artifact_store` carrying the GLOBAL flag's spelling
/// verbatim at the flag tier; the same argv over two different directories exits 2. Its margin
/// over `merge_same_tier_refuses_two_disagreeing_flags` is the production call site: the merge
/// runs inside `ContextFlags::with_store_override`, and the merged value then passes the store's
/// existence check and reaches the print. What it does NOT claim: the two-directory refusal's
/// composed text, held by `same_tier_disagreement_refuses_naming_both_values`. Blind spots, named:
/// the exit code 2 is the refusal exit class, pinned here as a literal; the store is the only key
/// with a verb-local same-tier flag, so no other key is driven; the expected stdout re-spells the
                                                                                            
/// outside its claim.
#[test]
fn two_same_tier_spellings_of_one_store_resolve_through_the_binary() {
    let fx = fx();
    let plain = text(&fx.store).to_string();
    let parent = text(fx.store.parent().expect("a store parent"));
    let name = fx
        .store
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a utf8 store name");
    let file_line = format!(
        "context file: {}/.config/recipes-deploy/orchard-context.toml (absent)",
        text(&fx.home)
    );
    let root = text(&fx.root).to_string();
    let manifest = format!("{root}/repo-manifest.toml");

    for spelled in [
        format!("{parent}/{name}/"),
        format!("{parent}//{name}"),
        format!("{parent}/./{name}"),
    ] {
                                                                                       
        assert_ne!(
            spelled, plain,
            "the leg's two spellings are one text, so the leg measures nothing"
        );
        let (code, stdout, stderr) = run_code(
            orchard(&fx)
                .arg("--print-context")
                .arg("--artifact-store")
                .arg(&spelled)
                .args(["vendor", "--store"])
                .arg(&fx.store),
        );
        assert_eq!(
            code,
            Some(0),
            "{spelled}: stdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            stdout,
            printed_context(
                &file_line,
                [
                    (&root, "cwd default"),
                    (&spelled, "flag"),
                    (&manifest, "cwd default"),
                ],
            ),
            "{spelled}: the printed context is not the composed text"
        );
    }

                                                                  
    let other = fx.root.parent().expect("tmp base").join("other-store");
    std::fs::create_dir_all(&other).expect("mk other store");
    let (code, stdout, _) = run_code(
        orchard(&fx)
            .arg("--print-context")
            .arg("--artifact-store")
            .arg(&other)
            .args(["vendor", "--store"])
            .arg(&fx.store),
    );
    assert_eq!(code, Some(2), "two directories resolved: {stdout}");
}

#[test]
fn named_flag_store_unresolvable_refuses_through_the_binary() {
    let fx = fx();
    let gone = fx.root.parent().unwrap().join("no-such-store");
    let (ok, _, stderr) = run(orchard(&fx)
        .arg("--print-context")
        .arg("--artifact-store")
        .arg(&gone)
        .arg("vendor"));
    assert!(!ok);
    assert!(stderr.contains("no-such-store"), "{stderr}");
}

#[test]
fn build_refuses_a_stale_weights_env_var_naming_the_flag() {
                                                                                              
    let fx = fx();
    let (ok, _, stderr) = run(orchard(&fx)
        .env("RECIPES_DHA_WEIGHTS_GGUF", "/nonexistent.gguf")
        .args(["build", "--domain", "box.test"]));
    assert!(!ok);
    assert!(
        stderr.contains("--dha-weights-gguf"),
        "cure names the flag: {stderr}"
    );
    assert!(stderr.contains("RECIPES_DHA_WEIGHTS_GGUF"), "{stderr}");
}

#[test]
fn doctor_prints_the_context_section() {
    let fx = fx();
    let (ok, stdout, _) = run(orchard(&fx).arg("doctor"));
    assert!(ok, "doctor stays advisory exit 0");
    assert!(stdout.contains("repo_root"), "{stdout}");
    assert!(stdout.contains("(cwd default)"), "{stdout}");
}

                                                                                                   
  
                                                                                                
                                                                                               
                                                                                                
                                                                                                
                                                                        
  
                                                                                                
                                                                                      
                                                                                         
                                                                                                 
                                                                                            
                                                                                                 
                                                                                                 
                                                                                                
                                                                                                 
                                                                                                
                         
  
                                                                                  
                                                                                                 
                                                                                     
                                                                                                 
                                                                                         
                                                                            
  
                                                                                             
                                                                                     
                                                                                                 
                                                                                             
               
  
                                                                                            
                                                                                               
                                                                                                
                                                      
                                                                                                    
                                                                                                
               
                                                                                                  
                                                                                                  
                                                                
                                                                                                  
                                                                                   
  
                                                                                  
                                                                                                
                                                                                                    
                                                                                          
   

/// One needle rule for the rewire tripwire.
struct NeedleRule {
    /// The literal searched for, verbatim.
    needle: &'static str,
    /// File suffixes permitted to carry it.
    allowed: &'static [&'static str],
    /// The home this needle MUST still appear in, so a rename or refactor that moves the read out
    /// reddens loudly instead of leaving the rule matching nothing (Principle 6, drift direction).
    /// `None` marks a REACH-EXTENSION needle whose only current hit is incidental.
    must_appear_at: Option<&'static str>,
}

const CONTEXT_NEEDLES: &[NeedleRule] = &[
    NeedleRule {
        needle: "\"FRUIT_ARTIFACT_STORE\"",
        allowed: &["deploy/context.rs"],
        must_appear_at: Some("deploy/context.rs"),
    },
    NeedleRule {
        needle: "\"repo-manifest.toml\"",
        allowed: &["deploy/context.rs"],
        must_appear_at: Some("deploy/context.rs"),
    },
    NeedleRule {
        needle: "\"../artifact-store\"",
        allowed: &["deploy/context.rs"],
        must_appear_at: Some("deploy/context.rs"),
    },
                                                                           
                                                                                                    
                                                                                                  
                                                                                    
    NeedleRule {
        needle: "join(\"artifact-store\")",
        allowed: &["deploy/context.rs", "deploy/market.rs"],
        must_appear_at: None,
    },
    NeedleRule {
        needle: "\"RECIPES_DHA_WEIGHTS_GGUF\"",
        allowed: &["main.rs"],
        must_appear_at: Some("main.rs"),
    },
    NeedleRule {
        needle: "\"RECIPES_DHA_MMPROJ_GGUF\"",
        allowed: &["main.rs"],
        must_appear_at: Some("main.rs"),
    },
                                                                                          
                                                                                                
                                                                                          
                                                                                                
                                 
    NeedleRule {
        needle: "current_dir()",
        allowed: &["deploy/context.rs", "main.rs", "deploy/artifact_keys.rs"],
        must_appear_at: Some("deploy/context.rs"),
    },
];

/// `(display path, raw text)` for every `.rs` file under `crates/orchard/src`. Fails closed: a walk
/// that finds an implausibly small tree panics rather than scanning nothing and passing.
fn orchard_src_texts() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            out.push((path.display().to_string(), text));
        }
    }
    assert!(
        out.len() >= 20,
        "the src/ walk found only {} files — the walk broke (fail closed)",
        out.len()
    );
    out
}

#[test]
fn no_direct_context_reads_outside_the_allowlist() {
    let files = orchard_src_texts();
    let mut offenders: Vec<String> = Vec::new();
    for rule in CONTEXT_NEEDLES {
        let mut home_seen = false;
        for (rel, text) in &files {
            if !text.contains(rule.needle) {
                continue;
            }
            if let Some(home) = rule.must_appear_at
                && rel.ends_with(home)
            {
                home_seen = true;
            }
            if !rule.allowed.iter().any(|a| rel.ends_with(a)) {
                offenders.push(format!("{rel}: {}", rule.needle));
            }
        }
                                                                                                    
                                                                                               
        if let Some(home) = rule.must_appear_at {
            assert!(
                home_seen,
                "the needle {} no longer appears at its home {home} — the rule now matches \
                 nothing, so it would pass over a tree that moved the read elsewhere. Re-anchor \
                 the rule consciously",
                rule.needle
            );
        }
    }
    assert!(
        offenders.is_empty(),
        "context-bearing names outside their allowlisted homes (route the read through \
         deploy::context):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn context_needle_scanner_is_non_vacuous_and_specific() {
                                                                                                
                                                                                            
                                                                                                  
                                                                                      
    let matches = |needle: &str, text: &str| text.contains(needle);
    let n = |needle: &str| {
        CONTEXT_NEEDLES
            .iter()
            .find(|r| r.needle == needle)
            .unwrap_or_else(|| panic!("rule {needle} is gone — the self-test's subject moved"))
            .needle
    };
                                                          
    for (needle, sample) in [
        (
            n("\"FRUIT_ARTIFACT_STORE\""),
            "const STORE_VAR: &str = \"FRUIT_ARTIFACT_STORE\";\nstd::env::var_os(STORE_VAR)",
        ),
        (
            n("\"FRUIT_ARTIFACT_STORE\""),
            "std::env::var_os(\"FRUIT_ARTIFACT_STORE\")",
        ),
        (
            n("join(\"artifact-store\")"),
            "root.join(\"..\").join(\"artifact-store\")",
        ),
        (
            n("\"repo-manifest.toml\""),
            "let mut p = root.to_path_buf();\np.push(\"repo-manifest.toml\");",
        ),
        (
            n("\"RECIPES_DHA_WEIGHTS_GGUF\""),
            "const W_VAR: &str = \"RECIPES_DHA_WEIGHTS_GGUF\";\nstd::env::var_os(W_VAR)",
        ),
    ] {
        assert!(
            matches(needle, sample),
            "the scanner is VACUOUS for {needle}: it does not match {sample:?}"
        );
    }
                                                                                                 
                                                                                             
    for (needle, sample) in [
        (
            n("\"FRUIT_ARTIFACT_STORE\""),
            "\"…the profile, $FRUIT_ARTIFACT_STORE, or the context file\"",
        ),
        (
            n("\"repo-manifest.toml\""),
            "Some(Path::new(\"/eco/orchard/repo-manifest.toml\"))",
        ),
        (
            n("\"../artifact-store\""),
            "Path::new(\"/eco/orchard/../artifact-store/blob\")",
        ),
    ] {
        assert!(
            !matches(needle, sample),
            "the scanner is UNSPECIFIC for {needle}: it matches the benign {sample:?}, which \
             would be an unfixable red on this tree"
        );
    }
}

                                                                                           

#[test]
fn generate_keys_repo_independent_legs_run_outside_a_repo() {
                                                                                                   
                                                                                                    
                                                                                                      
                                                                               
    let fx = fx();
    let notrepo = fx.home.join("notrepo");
    std::fs::create_dir_all(&notrepo).expect("mk notrepo");
    let keys = fx.home.join("gk-out");
    let (code, _out, err) = run_code(
        orchard(&fx)
            .current_dir(&notrepo)
            .args(["generate-keys", "--regenerate-master-key"])
            .arg("--output-dir")
            .arg(&keys),
    );
    assert_eq!(
        code,
        Some(0),
        "a repo-independent leg must run from a non-repo CWD; stderr: {err}"
    );
}

                                                                                          

#[test]
fn keys_dir_refuses_without_a_config_base() {
                                                                                                     
                                                                                                  
                                                                                                    
                                                                                             
    let fx = fx();
                                                                                                      
                                                                              
    std::fs::write(fx.root.join("Cargo.toml"), "[workspace]\nmembers = []\n")
        .expect("mk Cargo.toml");
    let (code, _out, err) = run_code(
        orchard(&fx)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .args(["generate-keys", "--artifact-signing", "software"]),
    );
    let cwd_keys = fx
        .root
        .join(".config/recipes-deploy/keys/artifact-root.key");
    assert!(
        !cwd_keys.exists(),
        "the operator key set landed in the CWD ({}); default_keys_dir must fail closed",
        cwd_keys.display()
    );
    assert_ne!(
        code,
        Some(0),
        "must refuse without a config base; stderr: {err}"
    );
    assert!(
        err.contains("--output-dir"),
        "the refusal must name the --output-dir cure: {err}"
    );
}

                                                                                         

#[test]
fn prod_consumes_profile_firmware() {
                                                                                              
                                                                                                    
                                                                                                 
                                                                                            
                                                                                                      
                 
    let fx = fx();
    let dummy = fx.home.join("dummy");
    std::fs::write(&dummy, "x").expect("dummy");
    let profile = fx.home.join("fw.toml");
    std::fs::write(
        &profile,
        "firmware = \"bogus-firmware\"\ndomain = \"box.test\"\n",
    )
    .expect("profile");
    let (code, _out, err) = run_code(
        orchard(&fx)
            .args(["prod", "203.0.113.9"])
            .arg("--pubkey")
            .arg(&dummy)
            .arg("--ssh-identity")
            .arg(&dummy)
            .arg("--profile")
            .arg(&profile),
    );
    assert_ne!(
        code,
        Some(0),
        "prod must refuse a bad profile firmware; stderr: {err}"
    );
    assert!(
        err.contains("unknown firmware") || err.contains("firmware"),
        "prod must name the bad firmware, not walk past to build the wrong layout: {err}"
    );
}

                                                                                          

#[test]
fn machine_stderr_survives_a_closed_downstream_pipe() {
                                                                                                    
                                                                                                 
                                                                                                    
                                                                                                  
                                          
    let fx = fx();
    let mut child = orchard(&fx)
        .args([
            "--artifact-store",
            "/no/such/store/dir",
            "vendor",
            "--porcelain",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard");
    drop(child.stderr.take());                                              
    let status = child.wait().expect("wait");
    assert_ne!(
        status.code(),
        Some(101),
        "a closed stderr pipe must not panic the machine surface to 101 (route through emit_stderr)"
    );
    assert_eq!(
        status.code(),
        Some(2),
        "the refusal class (2) survives a closed stderr with the lock env set"
    );
}

#[test]
fn refusal_with_lock_env_survives_both_streams_closed() {
                                                                                                 
                                                                                                   
                                                                                              
    let fx = fx();
    let mut child = orchard(&fx)
        .args([
            "--artifact-store",
            "/no/such/store/dir",
            "vendor",
            "--porcelain",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard");
    drop(child.stdout.take());
    drop(child.stderr.take());
    let status = child.wait().expect("wait");
    assert_ne!(
        status.code(),
        Some(101),
        "both streams closed must not panic to 101"
    );
    assert_eq!(
        status.code(),
        Some(2),
        "the refusal class survives both streams closed"
    );
}

#[test]
fn doctor_render_survives_a_closed_stdout_pipe() {
                                                                                                   
                                                                                               
                                                                                       
    let fx = fx();
    let mut child = orchard(&fx)
        .arg("doctor")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orchard");
    drop(child.stdout.take());
    let status = child.wait().expect("wait");
    assert_ne!(
        status.code(),
        Some(101),
        "doctor must not panic to 101 on a closed stdout pipe"
    );
    assert!(
        status.code().is_some(),
        "doctor killed by a signal — SIGPIPE is not SIG_IGN"
    );
}

                                                                                          

#[test]
fn host_lock_dir_ignores_tmpdir() {
                                                                                                      
                                                                                                     
                                                                                                       
                                                                                                    
                                                                                                      
                                                                                                    
                                                                                         
    let fx = fx();
    let probe = fx.home.join("probe-tmp");
    std::fs::create_dir_all(&probe).expect("mk probe-tmp");
                                                                                                   
    let _ = run_code(
        orchard(&fx)
            .env_remove("ORCHARD_LOCK_DIR")
            .env("TMPDIR", &probe)
            .args(["build", "--domain", "box.test"]),
    );
    assert!(
        !probe.join("recipes-ceremony-locks").exists(),
        "the host lock followed $TMPDIR ({}); it must be the fixed literal",
        probe.display()
    );
}

#[test]
fn host_lock_dir_override_discloses_itself() {
                                                                                             
                                                                                                
                                                                                                    
                                                                                               
                                                                                           
                                            
    let fx = fx();
                                                                             
    let dir = fx.home.join("disclosed-lock");
    let (_, _, stderr) = run_code(orchard(&fx).env("ORCHARD_LOCK_DIR", &dir).arg("doctor"));
    assert!(
        stderr.contains("ORCHARD_LOCK_DIR="),
        "the override must disclose itself on stderr: {stderr}"
    );
    assert!(
        stderr.contains(&dir.display().to_string()),
        "the disclosure must name the DIR IN EFFECT, not just the variable: {stderr}"
    );
    assert!(
        stderr.contains("host serialization"),
        "the disclosure must say what the override costs: {stderr}"
    );
                                                                                                 
                   
    let (_, _, stderr) = run_code(orchard(&fx).env_remove("ORCHARD_LOCK_DIR").arg("doctor"));
    assert!(
        !stderr.contains("ORCHARD_LOCK_DIR="),
        "no override is in effect, so nothing may be disclosed: {stderr}"
    );
                                                                                                
                                                                                          
    let (_, _, stderr) = run_code(orchard(&fx).env("ORCHARD_LOCK_DIR", "").arg("doctor"));
    assert!(
        !stderr.contains("ORCHARD_LOCK_DIR="),
        "an EMPTY override is filtered, so the fixed literal is in effect and the disclosure \
         would be false: {stderr}"
    );
}

#[test]
fn deploy_lock_dir_ignores_tmpdir() {
                                                                                                        
                                                                                                  
                                                                                                    
                                                                                                        
                                                                                                      
                                                               
    let fx = fx();
    let probe = fx.home.join("probe-tmp2");
    std::fs::create_dir_all(&probe).expect("mk probe-tmp2");
    let dummy = fx.home.join("dummy2");
    std::fs::write(&dummy, "x").expect("dummy");
    let _ = run_code(
        orchard(&fx)
            .env("TMPDIR", &probe)
            .args(["prod", "203.0.113.9"])
            .arg("--pubkey")
            .arg(&dummy)
            .arg("--ssh-identity")
            .arg(&dummy),
    );
    assert!(
        !probe.join("recipes-deploy-locks").exists(),
        "the deploy lock followed $TMPDIR ({}); it must be the fixed literal",
        probe.display()
    );
}

                                                                                                   

/// The `context-unresolvable` cure the CWD-default producer renders, frozen whole.
const CONTEXT_UNRESOLVABLE_CURE: &str = "run from a working directory that exists, or fix the \
     named path, or supply the value via its flag (--repo-root / --artifact-store / \
     --repo-manifest), the profile, $FRUIT_ARTIFACT_STORE, or the context file";

/// The whole refusal an operator receives on stderr, as a hand literal.
fn composed_refusal(token: &str, detail: &str, cure: &str) -> String {
    format!("refusal ({token}): {detail}\n  cure: {cure}\n")
}

/// The context-file line of a config base that is not UTF-8, as a hand literal built from the
/// fixture's own bytes.
fn absent_file_line(escaped_base: &str) -> String {
    format!("context file: {escaped_base}/recipes-deploy/orchard-context.toml (absent)")
}

                                                                                       
/// its escaped form, not as U+FFFD.
///
/// What it claims: the built binary run under `XDG_CONFIG_HOME` = `<P>/cfg-\xff` prints the whole
/// context with the file line carrying `\xff`, exits 0, and prints no U+FFFD; the same run under a
/// UTF-8 config base prints that base verbatim, so the leg measures the encoding and not the
/// shape. What it does NOT claim: anything about the module's other byte-domain render sites (the
/// refusal details below drive three of them; the scan holds the site count). Blind
                                                                                             
/// render-shape change reds this arm for a reason outside its claim; only byte 0xFF is driven.
#[test]
fn the_print_context_file_line_renders_a_non_utf8_config_base_escaped() {
    let fx = fx();
    let base = fx.root.parent().expect("tmp base").to_path_buf();
    let prefix = ascii_prefix(&base);
    let root = text(&fx.root).to_string();
    let store = format!("{root}/../artifact-store");
    let manifest = format!("{root}/repo-manifest.toml");

    let cfg = non_utf8_dir(&base, "cfg");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .env("XDG_CONFIG_HOME", &cfg)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(0), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        printed_context(
            &absent_file_line(&format!("{prefix}/cfg-\\xff")),
            [
                (root.as_str(), "cwd default"),
                (store.as_str(), "cwd default"),
                (manifest.as_str(), "cwd default"),
            ],
        ),
        "the printed context is not the composed text"
    );
    assert!(
        !stdout.contains('\u{fffd}'),
        "the printed context carries U+FFFD: {stdout}"
    );

                                                        
    let ok_cfg = base.join("cfg-ok");
    std::fs::create_dir_all(&ok_cfg).expect("mk a UTF-8 config base");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .env("XDG_CONFIG_HOME", &ok_cfg)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(0), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        printed_context(
            &absent_file_line(&format!("{prefix}/cfg-ok")),
            [
                (root.as_str(), "cwd default"),
                (store.as_str(), "cwd default"),
                (manifest.as_str(), "cwd default"),
            ],
        ),
        "the UTF-8 control's printed context is not the composed text"
    );
}

                                                                                    
/// path as its escaped form.
///
/// What it claims: at three producers driven through the built binary — the CWD-not-a-repo-root
/// refusal under a working directory carrying 0xFF, the `--context`-names-no-file refusal over a
/// RELATIVE `--context` value absolutized against that working directory, and the context-file
/// parse refusal under a config base carrying 0xFF — the whole composed refusal an operator
/// receives carries the path with `\xff` and no U+FFFD, at exit 2. What it does NOT claim: the
/// `context-not-utf8` sample, held by `a_non_utf8_env_store_or_cwd_refuses_through_the_binary`;
/// the `pick_explicit` check-failure and profile-relative details, which no leg drives. Blind
/// spots, named: the parse leg asserts its first line and the cure, not the toml crate's own
/// error body, which is a dependency's text; the exit code 2 is the refusal exit class, pinned
/// here as a literal; a non-UTF-8 `--context` VALUE is refused at the parser before this site
/// (`ceremony_utf8_argv`), so the leg reaches the site through the working directory.
#[test]
fn the_context_refusal_details_render_a_non_utf8_path_escaped() {
    let fx = fx();
    let base = fx.root.parent().expect("tmp base").to_path_buf();
    let prefix = ascii_prefix(&base);
    let bad_cwd = non_utf8_dir(&base, "cwd");
    let escaped_cwd = format!("{prefix}/cwd-\\xff");

                                                                                       
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .current_dir(&bad_cwd)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stderr,
        composed_refusal(
            "context-unresolvable",
            &format!(
                "{escaped_cwd} is not an orchard repo root (./crates/image-builder not found) — \
                 run from the repo root, or pass --repo-root / set `repo_root` in the context file"
            ),
            CONTEXT_UNRESOLVABLE_CURE,
        ),
        "the CWD-not-a-root refusal is not the composed text"
    );

                                                                                        
    let (code, stdout, stderr) = run_code(orchard(&fx).current_dir(&bad_cwd).args([
        "--context",
        "nope.toml",
        "--print-context",
        "vendor",
    ]));
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stderr,
        composed_refusal(
            "context-file-invalid",
            &format!(
                "--context names {escaped_cwd}/nope.toml which is not a file — the explicitly \
                 named context file must exist (no silent fallback)"
            ),
            CONTEXT_FILE_INVALID_CURE,
        ),
        "the --context-not-a-file refusal is not the composed text"
    );

                                                                                    
    let cfg = non_utf8_dir(&base, "cfg");
    let dir = cfg.join("recipes-deploy");
    std::fs::create_dir_all(&dir).expect("mk the config dir");
    std::fs::write(dir.join("orchard-context.toml"), "bogus = 1\n").expect("write");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .env("XDG_CONFIG_HOME", &cfg)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stderr.lines().next(),
        Some(
            format!(
                "refusal (context-file-invalid): context file {prefix}/cfg-\\xff/recipes-deploy/\
                 orchard-context.toml: TOML parse error at line 1, column 1"
            )
            .as_str()
        ),
        "the parse refusal's first line is not the composed text: {stderr}"
    );
    assert_eq!(
        cure_line(&stderr),
        CONTEXT_FILE_INVALID_CURE,
        "the parse refusal's cure moved: {stderr}"
    );
    assert!(
        !stderr.contains('\u{fffd}'),
        "the parse refusal carries U+FFFD: {stderr}"
    );
}

/// `<base>/<n × 'x'>-\xff`, created, with its escaped text. The name is padded so the escaped
/// `0xFF` begins past the sample cut whatever the temp base is; the assertion below is the check.
fn long_non_utf8_dir(base: &Path, prefix: &str) -> (PathBuf, String) {
    let name = "x".repeat(99.max(130_usize.saturating_sub(prefix.len() + 2)));
    let dir = non_utf8_dir(base, &name);
    let escaped = format!("{prefix}/{name}-\\xff");
    assert!(
        escaped
            .find("\\xff")
            .expect("the escaped fixture path carries the byte")
            > 120,
        "the fixture's escaped 0xFF is inside the first 120 characters, so the leg measures \
         nothing: {escaped}"
    );
    (dir, escaped)
}

/// delta v3.6 §5 row H2, the long-path leg (§6 Q-cap): a path whose escaped form is longer than
/// the git seam's sample cut renders whole.
///
/// What it claims: under a long directory name carrying 0xFF, positioned so the escaped byte
/// begins past that cut, the `--print-context` file line, the CWD-not-a-repo-root refusal and
/// `utf8_context_path`'s `context-not-utf8` sample each render the WHOLE escaped path, ending in
/// `\xff`. At `b97cf3e` the first two printed the path cut at the sample cut, with no `\xff` and
/// no marker, and the sample went through the git seam's cut helper. What it
/// does NOT claim: any bound on the path — the render is whole, and the sources are the operator's
/// own argv, environment, working directory and context file (§6 Q-cap); nor anything about
/// `non_utf8_sample`, which keeps its cut at the git seam. Blind spots, named: three of the
/// module's render sites are driven at this length; only byte 0xFF is driven.
#[test]
fn a_non_utf8_path_past_the_sample_cut_renders_whole() {
    let fx = fx();
    let base = fx.root.parent().expect("tmp base").to_path_buf();
    let prefix = ascii_prefix(&base);
    let (long, escaped) = long_non_utf8_dir(&base, &prefix);
    let root = text(&fx.root).to_string();
    let store = format!("{root}/../artifact-store");
    let manifest = format!("{root}/repo-manifest.toml");

                                                       
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .env("XDG_CONFIG_HOME", &long)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(0), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        printed_context(
            &absent_file_line(&escaped),
            [
                (root.as_str(), "cwd default"),
                (store.as_str(), "cwd default"),
                (manifest.as_str(), "cwd default"),
            ],
        ),
        "the file line does not carry the whole escaped path"
    );

                                                                         
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .current_dir(&long)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stderr,
        composed_refusal(
            "context-unresolvable",
            &format!(
                "{escaped} is not an orchard repo root (./crates/image-builder not found) — run \
                 from the repo root, or pass --repo-root / set `repo_root` in the context file"
            ),
            CONTEXT_UNRESOLVABLE_CURE,
        ),
        "the CWD refusal does not carry the whole escaped path"
    );

                                                                                        
    std::fs::create_dir_all(long.join("crates/image-builder")).expect("mk root shape");
    let (code, stdout, stderr) = run_code(
        orchard(&fx)
            .current_dir(&long)
            .args(["--print-context", "vendor"]),
    );
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stderr,
        composed_refusal(
            "context-not-utf8",
            &format!(
                "the repo root resolved from the cwd default tier is not UTF-8 text: {escaped}"
            ),
            NOT_UTF8_CURE,
        ),
        "the context-not-utf8 sample does not carry the whole escaped path"
    );
}

                                                                                                  
  
                                                                                              
                                                                                                
                                                                                                
                                                                                          
                                                                                                    
                                                                                                
                                                                                                 
                                                                                            
                                                         

/// Each byte-domain → text conversion literal and the number of times `fn path_text`'s body holds
/// it. Every occurrence in the module must be inside that body: the file count and the body count
/// are asserted equal, so both a new site and a lost one redden.
const CONVERSION_NEEDLES: &[(&str, usize)] = &[
    (".display()", 0),
    ("to_string_lossy", 0),
    ("from_utf8_lossy", 0),
    ("escape_ascii", 1),
    ("to_str()", 1),
    ("as_encoded_bytes", 1),
];

/// The context module's source text. Fails closed: a read failure or an implausibly short file
/// panics rather than scanning nothing and passing.
fn context_module_src() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/deploy/context.rs");
    let text = std::fs::read_to_string(&path).expect("read deploy/context.rs");
    assert!(
        text.len() > 10_000,
        "deploy/context.rs is {} bytes — the read broke (fail closed)",
        text.len()
    );
    text
}

/// The text with every comment-only line dropped.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `fn path_text`'s signature and body, from the signature to the first line-start `}`.
fn path_text_body(code: &str) -> Option<&str> {
    let start = code.find("fn path_text(")?;
    let rest = &code[start..];
    let end = rest.find("\n}")?;
    Some(&rest[..end + 2])
}

/// Every conversion literal outside `fn path_text`'s body, and every frozen body count that moved.
fn conversion_offenders(text: &str) -> Vec<String> {
    let code = code_only(text);
    let Some(body) = path_text_body(&code) else {
        return vec![
            "`fn path_text(` is absent, or its body is not closed by a line-start `}` — the scan \
             has no renderer to anchor on, so it would measure nothing"
                .to_string(),
        ];
    };
    let mut offenders = Vec::new();
    for (needle, frozen) in CONVERSION_NEEDLES {
        let in_body = body.matches(needle).count();
        let in_file = code.matches(needle).count();
        if in_body != *frozen {
            offenders.push(format!(
                "path_text holds {in_body} × {needle}, the frozen count is {frozen}"
            ));
        }
        if in_file != in_body {
            offenders.push(format!(
                "{} × {needle} outside path_text",
                in_file.saturating_sub(in_body)
            ));
        }
    }
    offenders
}

/// delta v3.6 §5 row H2's scan: `deploy/context.rs` converts a byte-domain path to text in
/// `fn path_text` and nowhere else.
///
/// What it claims: over the module's code lines, each literal of [`CONVERSION_NEEDLES`] occurs
/// exactly as often as the frozen table says inside `fn path_text`'s body and never outside it —
/// so `.display()` occurs nowhere, and `path_text`'s own `to_str()` / `escape_ascii` /
/// `as_encoded_bytes` are each still there. What it does NOT claim: that no lossy render is
/// possible. The model is a literal count; a conversion spelled another way, or written inside a
/// trailing comment or a string literal, is outside it, and the driven arms above are what hold
/// the sites they drive. Blind spots, named: the module is named as a path literal, so moving the
/// file reds the read rather than the property; a needle inside a string literal counts as code.
#[test]
fn the_context_module_converts_a_byte_path_only_in_path_text() {
    let offenders = conversion_offenders(&context_module_src());
    assert!(
        offenders.is_empty(),
        "byte-domain path conversions in deploy/context.rs outside its one renderer (route the \
         render through `path_text`):\n{}",
        offenders.join("\n")
    );
}

/// A module the scanner is measured against: one `path_text`, one caller that routes through it,
/// a comment and an `impl Display` that must not be read as conversions.
const SCANNER_SAMPLE: &str = r#"
//! A module doc that mentions display() and to_str() in prose.

/// Render a byte-domain path as text.
fn path_text(p: &Path) -> String {
    match p.to_str() {
        Some(s) => s.to_string(),
        None => p.as_os_str().as_encoded_bytes().escape_ascii().to_string(),
    }
}

fn refuse(p: &Path) -> String {
    // never render a byte path with display() here
    format!("names {}", path_text(p))
}

impl std::fmt::Display for Thing {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
"#;

/// Principle 6 self-test: the scanner is measured against planted violations and against the
/// near-misses that must not be flagged. A scanner asserted only against the tree it was written
/// for can be vacuous or unspecific without either showing up.
#[test]
fn the_conversion_scanner_is_non_vacuous_and_specific() {
                                                                                      
    assert_eq!(
        conversion_offenders(SCANNER_SAMPLE),
        Vec::<String>::new(),
        "the scanner is UNSPECIFIC: it flags a module that routes every render through path_text"
    );

                                                   
    for (label, planted) in [
        (
            "a display() render at a call site",
            SCANNER_SAMPLE.replace(
                r#"format!("names {}", path_text(p))"#,
                r#"format!("names {}", p.display())"#,
            ),
        ),
        (
            "a to_string_lossy render at a call site",
            SCANNER_SAMPLE.replace(
                r#"format!("names {}", path_text(p))"#,
                r#"format!("names {}", p.to_string_lossy())"#,
            ),
        ),
        (
            "a second renderer beside path_text",
            format!(
                "{SCANNER_SAMPLE}\nfn other(p: &Path) -> String {{\n    p.to_str().unwrap_or(\"?\").to_string()\n}}\n"
            ),
        ),
        (
            "path_text's escaped arm dropped",
            SCANNER_SAMPLE.replace(
                "None => p.as_os_str().as_encoded_bytes().escape_ascii().to_string(),",
                "None => String::new(),",
            ),
        ),
        (
            "path_text renamed away",
            SCANNER_SAMPLE.replace("fn path_text(", "fn render_path("),
        ),
    ] {
        assert!(
            !conversion_offenders(&planted).is_empty(),
            "the scanner is VACUOUS for {label}: it flags nothing in {planted}"
        );
    }
}
