                                                                                           
                                                                                             
//! API-level concurrency arms (runnable without boots and without the not-yet-built `run` verb;
                                                                                                  
//! join this binary in Task 6.

#[allow(dead_code)]
#[path = "common/shell_split.rs"]
mod shell_split;

use std::path::Path;

use orchard::ceremony::lock::{acquire_at, acquire_for_at};
use orchard::ceremony::records::{
    DeclaredPathName, DirtClass, RunRecords, S5Confirmation, classify_and_witness,
    classify_executing_dirt, enumerate_boxes, finalize_path_record, open_path_record,
    records_dir_of, sibling_output_recognized,
};
use orchard::deploy::profile::{PROFILE_KEYS, load_str, scan_for_forbidden_content};

                                                                             

#[test]
fn the_2026_07_profile_fixture_parses_unchanged() {
                                                                                     
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile-2026-07.toml"),
    )
    .expect("read fixture");
    let p = load_str(&text).expect("2026-07 profile parses");
    assert_eq!(p.ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(p.port, Some(2222));
    assert_eq!(p.domain.as_deref(), Some("box.example.com"));
    assert_eq!(p.out_dir.as_deref(), Some(Path::new("/tmp/box-images")));
    assert_eq!(p.schema_version, None, "absent = v1");
}

#[test]
fn ceremony_keys_parse_and_the_destructive_refusal_is_retained() {
                            
    let p = load_str(
        "firmware = \"seabios-gpt\"\nimage_version = 3\ntenant_repo = \"recipes\"\n\
         gate_target = \"boot-gate\"\nschema_version = 1\n",
    )
    .expect("ceremony keys parse");
    assert_eq!(p.firmware.as_deref(), Some("seabios-gpt"));
    assert_eq!(p.image_version, Some(3));
                                                                                          
                                    
    let e = load_str("wipe_confirmed = true\n").unwrap_err();
    assert!(e.contains("destructive intent"), "{e}");
    assert!(load_str("frobnicate = 1\n").is_err());
}

#[test]
fn unknown_field_refusal_names_the_schema_skew_cure() {
                                                                                       
    let e = load_str("a_newer_orchard_key = true\n").unwrap_err();
    assert!(
        e.contains("unknown field") || e.contains("a_newer_orchard_key"),
        "{e}"
    );
    assert!(e.contains("upgrade orchard"), "{e}");
                                                      
    let e = load_str("schema_version = 99\n").unwrap_err();
    assert!(e.contains("newer") && e.contains("upgrade orchard"), "{e}");
                 
    assert!(load_str("schema_version = 1\n").is_ok());
}

#[test]
fn newer_schema_with_a_new_key_refuses_as_schema_skew_not_unknown_field() {
                                                                                            
                                                                                                  
                                                                                                    
                                                                                                  
    use orchard::deploy::profile::SCHEMA_SKEW_PREFIX;
    let e = load_str("schema_version = 2\nnew_key_from_a_future_orchard = true\n").unwrap_err();
    assert!(
        e.starts_with(SCHEMA_SKEW_PREFIX),
        "version+key must raise the schema-skew sentinel (→ ProfileSchemaSkew, exit 2), not a plain \
         unknown-field parse error: {e}"
    );
                                                                               
    let e2 = load_str("schema_version = 2\n").unwrap_err();
    assert!(
        e2.starts_with(SCHEMA_SKEW_PREFIX),
        "version-only skew unchanged: {e2}"
    );
}

#[test]
fn no_profile_suppliable_key_keeps_a_clap_default() {
                                                                                   
                                                                                               
                                                                                              
                                                                                                    
                                                                                                
                                       
    use clap::CommandFactory;
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
                                                                                              
    let renames: &[(&str, &str, &str)] = &[("operator_pubkey", "prod", "pubkey")];
                                                                                                 
                                                                                  
    let arg_default_free = |verb: &str, key: &str, flag: &str| -> Option<bool> {
        let node = root.get_subcommands().find(|c| c.get_name() == verb)?;
        let arg = node.get_arguments().find(|a| {
            a.get_long() == Some(flag) || (a.get_long().is_none() && a.get_id().as_str() == key)
        })?;
        Some(arg.get_default_values().is_empty())
    };
    let mut checked = 0usize;
    for key in PROFILE_KEYS {
        let conv = key.replace('_', "-");
        for verb in &profile_verbs {
            if let Some(default_free) = arg_default_free(verb, key, &conv) {
                assert!(
                    default_free,
                    "profile-suppliable {key} on {verb} carries a clap default"
                );
                checked += 1;
            }
        }
        for (k, verb, flag) in renames {
            if k == key
                && let Some(default_free) = arg_default_free(verb, key, flag)
            {
                assert!(
                    default_free,
                    "profile-suppliable --{flag} on {verb} carries a clap default"
                );
                checked += 1;
            }
        }
    }
                                                                                 
    assert!(
        checked >= 15,
        "profile-derivation reached only {checked} args — the convention broke"
    );
}

                                                                                                   

#[test]
fn forbidden_content_scan_catches_the_three_classes() {
    assert_eq!(scan_for_forbidden_content("ip = \"1.2.3.4\"\n"), None);
    assert!(
        scan_for_forbidden_content("wipe_confirmed = true\n")
            .expect("destructive key caught")
            .contains("wipe_confirmed")
    );
    assert!(
        scan_for_forbidden_content("x = \"-----BEGIN OPENSSH PRIVATE KEY-----\"\n")
            .expect("key material caught")
            .contains("key material")
    );
    assert!(
        scan_for_forbidden_content("resume = \"orchard run --wipe-confirmed\"\n")
            .expect("typed token caught")
            .contains("wipe-confirmed")
    );
                                                                                        
    assert_eq!(
        scan_for_forbidden_content("note = \"the wipe_confirmed flag is never stored\"\n"),
        None
    );
                                                                                             
                                                               
    for form in [
        "wipe_confirmed\t= true\n",                       
        "\"wipe_confirmed\" = true\n",                  
        "wipe_confirmed  =  true\n",                         
        "restore_from\t= \"/x\"\n",                                       
        "[section]\nallow_dirty = true\n",                     
    ] {
        assert!(
            scan_for_forbidden_content(form).is_some(),
            "must catch the destructive key in {form:?}"
        );
    }
                                                   
    assert_eq!(
        scan_for_forbidden_content("[box]\nip = \"1.2.3.4\"\n"),
        None
    );
}

                                                                                                   

#[test]
fn two_phase_records_classify_the_three_dirt_classes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/alpha.d");
    let target = tmp.path().join("checkout/consume-pins.toml");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mk checkout");

                                                            
    let mut rec = RunRecords::open_dir(&dir, "run-1").expect("open records");
    std::fs::write(&target, "operator bytes").expect("write");
    assert_eq!(classify_executing_dirt(&rec, &target), DirtClass::Ambiguous);

                                                                              
    let tok = open_path_record(&mut rec, &target).expect("open");
    std::fs::write(&target, "ceremony bytes v1").expect("ceremony write");
    finalize_path_record(&mut rec, tok).expect("finalize");
    assert_eq!(
        classify_executing_dirt(&rec, &target),
        DirtClass::CleanOrRecorded
    );

                                                                                        
                                                                                         
                               
    std::fs::write(&target, "later operator bytes").expect("operator overwrite");
    let rec2 = RunRecords::open_dir(&dir, "run-2").expect("reload");
    assert_eq!(
        classify_executing_dirt(&rec2, &target),
        DirtClass::Ambiguous
    );

                                                                                  
    let other = tmp.path().join("checkout/pins.toml");
    let mut rec3 = RunRecords::open_dir(&dir, "run-3").expect("reload");
    let _tok = open_path_record(&mut rec3, &other).expect("open");
    std::fs::write(&other, "torn write").expect("write");
    drop(rec3);                                                            
    let rec4 = RunRecords::open_dir(&dir, "run-4").expect("reload");
    assert_eq!(
        classify_executing_dirt(&rec4, &other),
        DirtClass::Interrupted
    );
}

                                                                                            
/// killed (open-only) entry must supersede the Interrupted verdict — reverting
/// `classify_executing_dirt` to the existential `any(post.is_none())` predicate reddens here.
#[test]
fn a_later_finalized_write_supersedes_an_earlier_interrupted_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/beta.d");
    let target = tmp.path().join("checkout/pins.toml");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mk checkout");

                                                                        
    let mut r1 = RunRecords::open_dir(&dir, "run-1").expect("open");
    let _tok = open_path_record(&mut r1, &target).expect("open");
    std::fs::write(&target, "torn v1").expect("write");
    drop(r1);
    let interrupted = RunRecords::open_dir(&dir, "run-1b").expect("reload");
    assert_eq!(
        classify_executing_dirt(&interrupted, &target),
        DirtClass::Interrupted
    );

                                                                                    
    let mut r2 = RunRecords::open_dir(&dir, "run-2").expect("reload");
    let tok = open_path_record(&mut r2, &target).expect("open");
    std::fs::write(&target, "clean v2").expect("ceremony write");
    finalize_path_record(&mut r2, tok).expect("finalize");
                                                                                              
                                                                                               
                                                                                               
                                                                                           
    let after = RunRecords::open_dir(&dir, "run-3").expect("reload");
    assert_eq!(
        classify_executing_dirt(&after, &target),
        DirtClass::PriorRunRecorded,
        "a later clean finalized write supersedes the earlier killed entry, and a different run's \
         finalized write reads PriorRunRecorded"
    );
}

                                                                                                  
/// verifies. The mechanism holding it is a type gate on the opened fd (`!is_file()` answers
/// `NonRegular` for every type that is not a regular file), so the property is total in the code;
/// this arm SAMPLES three inode shapes of it rather than enumerating inode types. Three shapes,
/// each with its verified pre-state as arm sanity — a symlink whose
/// TARGET holds the recorded bytes, a DANGLING symlink at a path whose finalized post is `Absent`
/// (`fs::read` answers `NotFound` there, which the pre-fold read as `Absent` and matched), and a
                                                                                                  
/// no witness the path cannot reach the commit chokepoint with anything to verify against.
///
/// Measured, git-independent: `open(O_NOFOLLOW|O_NONBLOCK)` answers `ELOOP` for a dangling and for
/// a resolvable symlink alike, so the type gate sees the link in both.
#[test]
fn no_non_regular_inode_at_a_declared_path_ever_verifies() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/nonreg.d");
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("mk checkout");
    let mut rec = RunRecords::open_dir(&dir, "run-1").expect("open records");

                                                           
    let linked = checkout.join("consume-pins.toml");
    std::fs::write(&linked, "recorded bytes").expect("write");
    let tok = open_path_record(&mut rec, &linked).expect("open");
    std::fs::write(&linked, "recorded bytes").expect("ceremony write");
    finalize_path_record(&mut rec, tok).expect("finalize");
    assert_eq!(
        classify_executing_dirt(&rec, &linked),
        DirtClass::CleanOrRecorded,
        "arm sanity: the regular file with the recorded bytes verifies before the swap"
    );
    let target = tmp.path().join("elsewhere.toml");
    std::fs::write(&target, "recorded bytes").expect("target write");
    std::fs::remove_file(&linked).expect("rm");
    symlink(&target, &linked).expect("symlink");
    assert_eq!(
        std::fs::read(&linked).expect("the target is readable through the link"),
        b"recorded bytes",
        "arm sanity: a path-following read would see the recorded bytes and match the record"
    );
    assert_eq!(
        classify_executing_dirt(&rec, &linked),
        DirtClass::Ambiguous,
        "a symlink at a declared path never verifies, whatever its target holds"
    );
    assert!(
        classify_and_witness(&rec, &linked).1.is_none(),
        "no witness for a symlink, so the chokepoint has nothing it could verify against"
    );

                                                                                              
    let gone = checkout.join("vendor-gone.tar.xz");
    std::fs::write(&gone, "about to be deleted").expect("write");
    let tok = open_path_record(&mut rec, &gone).expect("open");
    std::fs::remove_file(&gone).expect("the ceremony's own deletion");
    finalize_path_record(&mut rec, tok).expect("finalize");
    assert_eq!(
        classify_executing_dirt(&rec, &gone),
        DirtClass::CleanOrRecorded,
        "arm sanity: a recorded deletion verifies while the path is really absent"
    );
    symlink("/nonexistent/target", &gone).expect("dangling symlink");
    assert!(
        std::fs::read(&gone).is_err(),
        "arm sanity: a path-following read of a dangling link answers NotFound, which the \
         pre-fold shape mapped to Absent — the same value the record holds"
    );
    assert_eq!(
        classify_executing_dirt(&rec, &gone),
        DirtClass::Ambiguous,
        "a dangling symlink over a recorded Absent is not an Absent match"
    );
    assert!(
        classify_and_witness(&rec, &gone).1.is_none(),
        "no witness for the link"
    );

                                                                                                      
    let dirified = checkout.join("pins.toml");
    std::fs::write(&dirified, "pin = 1").expect("write");
    let tok = open_path_record(&mut rec, &dirified).expect("open");
    std::fs::write(&dirified, "pin = 2").expect("ceremony write");
    finalize_path_record(&mut rec, tok).expect("finalize");
    assert_eq!(
        classify_executing_dirt(&rec, &dirified),
        DirtClass::CleanOrRecorded,
        "arm sanity: the file verifies before it becomes a directory"
    );
    std::fs::remove_file(&dirified).expect("rm");
    std::fs::create_dir(&dirified).expect("mkdir at the declared path");
    std::fs::write(dirified.join("inner"), "x").expect("inner");
    assert_eq!(
        classify_executing_dirt(&rec, &dirified),
        DirtClass::Ambiguous,
        "a directory at a declared path never verifies"
    );
    assert!(
        classify_and_witness(&rec, &dirified).1.is_none(),
        "no witness for the directory"
    );
}

                                                                                              
/// computed, so every recording site renders the remedy for the class it met. Driven through the
/// three real recording entry points over real inodes; the cures are hand literals, so a rotation
/// of the production match reds this arm. Not driven: the `Io` class, which needs a read failure
/// this harness cannot force.
#[test]
fn a_recording_site_renders_the_cure_for_the_inode_class_it_met() {
    use orchard::ceremony::records::{ContentState, record_completed_write};
    const SYMLINK_CURE: &str =
        "replace the symlink with the regular file it points at, or remove it, then re-run";
    const DIRECTORY_CURE: &str =
        "the declared path is a file; remove the directory or restore the file, then re-run";
    const SPECIAL_CURE: &str = "remove the special file at the declared path, then re-run";
    let distinct: std::collections::BTreeSet<&str> = [SYMLINK_CURE, DIRECTORY_CURE, SPECIAL_CURE]
        .into_iter()
        .collect();
    assert_eq!(distinct.len(), 3, "three classes, three routes");

    type MakeInode = fn(&Path);
    let symlink: MakeInode = |p| std::os::unix::fs::symlink("/nonexistent/target", p).expect("ln");
    let directory: MakeInode = |p| std::fs::create_dir(p).expect("mkdir");
    let fifo: MakeInode = |p| {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("cstr");
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o644) },
            0,
            "mkfifo {}",
            p.display()
        );
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("mk checkout");
    let mut n = 0usize;
    for (label, want_cure, make) in [
        ("symlink", SYMLINK_CURE, symlink),
        ("directory", DIRECTORY_CURE, directory),
        ("FIFO", SPECIAL_CURE, fifo),
    ] {
        let mut rec =
            RunRecords::open_dir(&tmp.path().join(format!("boxes/{n}.d")), "run-1").expect("open");
        n += 1;

                                                                              
        let pre_path = checkout.join(format!("{n}-pre.toml"));
        make(&pre_path);
        let e = open_path_record(&mut rec, &pre_path)
            .expect_err("{label}: a non-regular pre-state refuses");
        assert_eq!(e.id.token(), "declared-path-unhashable", "{label} pre");
        assert_eq!(e.cure().as_str(), want_cure, "{label} pre");

                                                                                                 
                                                                                        
        let post_path = checkout.join(format!("{n}-post.toml"));
        std::fs::write(&post_path, "pin = 1").expect("write");
        let tok = open_path_record(&mut rec, &post_path).expect("a regular file records");
        std::fs::remove_file(&post_path).expect("rm");
        make(&post_path);
        let e = finalize_path_record(&mut rec, tok)
            .expect_err("{label}: a non-regular post-state refuses");
        assert_eq!(e.id.token(), "declared-path-unhashable", "{label} post");
        assert_eq!(e.cure().as_str(), want_cure, "{label} post");

                                                                          
        let done_path = checkout.join(format!("{n}-done.toml"));
        make(&done_path);
        let e = record_completed_write(&mut rec, &done_path, ContentState::Absent)
            .expect_err("{label}: a non-regular completed write refuses");
        assert_eq!(
            e.id.token(),
            "declared-path-unhashable",
            "{label} completed"
        );
        assert_eq!(e.cure().as_str(), want_cure, "{label} completed");
    }
}

                                                                                                   
/// checkouts: with `core.fileMode=true` a mode-only `chmod +x` at a byte-identical recorded path
/// stops verifying; with `core.fileMode=false` git ignores the worktree bit, so the same flip
/// leaves the path verified and the witness carries git's index answer. Both halves read git's own
/// verdict (`status --porcelain`, `ls-files -s`) as the arm-sanity oracle, so neither half is
/// asserting the implementation's own opinion of what git would say.
#[test]
fn the_exec_bit_is_in_the_witness_and_gits_index_owns_it_when_core_filemode_is_off() {
    use orchard::ceremony::records::ContentState;
    use std::os::unix::fs::PermissionsExt as _;

    fn recorded_repo(tmp: &Path, name: &str, file_mode: bool) -> (std::path::PathBuf, RunRecords) {
        let root = tmp.join(name);
        std::fs::create_dir_all(&root).expect("mk root");
        git_init_baseline(&root);
        if !file_mode {
            git_out(&root, &["config", "core.fileMode", "false"]);
        }
        let f = root.join("consume-pins.toml");
        std::fs::write(&f, "pin = 1\n").expect("write");
        git_out(&root, &["add", "-A"]);
        git_out(&root, &["commit", "-qm", "tracked"]);
        let mut rec = RunRecords::open_dir(&tmp.join(format!("{name}.d")), "run-1")
            .expect("open records")
            .with_checkout(&root);
        let tok = open_path_record(&mut rec, &f).expect("open");
        std::fs::write(&f, "pin = 1\n").expect("ceremony write");
        finalize_path_record(&mut rec, tok).expect("finalize");
        (root, rec)
    }

    fn chmod_x(p: &Path) {
        let mut perm = std::fs::metadata(p).expect("stat").permissions();
        perm.set_mode(perm.mode() | 0o111);
        std::fs::set_permissions(p, perm).expect("chmod +x");
    }

    let tmp = tempfile::tempdir().expect("tempdir");

                                                                      
    let (root_t, rec_t) = recorded_repo(tmp.path(), "modeon", true);
    let f_t = root_t.join("consume-pins.toml");
    assert_eq!(
        classify_executing_dirt(&rec_t, &f_t),
        DirtClass::CleanOrRecorded,
        "arm sanity: the recorded non-exec file verifies before the flip"
    );
    match classify_and_witness(&rec_t, &f_t)
        .1
        .expect("a witness")
        .post
    {
        ContentState::Sha256 { exec, .. } => assert!(!exec, "the recorded bit is non-exec"),
        other => panic!("a regular file records a Sha256 post, got {other:?}"),
    }
    chmod_x(&f_t);
    assert!(
        !git_out(&root_t, &["status", "--porcelain"]).is_empty(),
        "arm sanity: at core.fileMode=true git itself reports the mode-only flip"
    );
    assert_eq!(
        classify_executing_dirt(&rec_t, &f_t),
        DirtClass::Ambiguous,
        "a mode-only flip at a bytes-identical recorded path matches no record"
    );
    assert!(
        classify_and_witness(&rec_t, &f_t).1.is_none(),
        "no witness for the flipped path, so it cannot be committed under the token"
    );

                                                                                              
    let (root_f, rec_f) = recorded_repo(tmp.path(), "modeoff", false);
    let f_f = root_f.join("consume-pins.toml");
    chmod_x(&f_f);
    assert_eq!(
        git_out(&root_f, &["status", "--porcelain"]),
        "",
        "arm sanity: at core.fileMode=false git reports no entry for the flip"
    );
    let index_mode = git_out(&root_f, &["ls-files", "-s", "--", "consume-pins.toml"]);
    assert!(
        index_mode.starts_with("100644"),
        "arm sanity: git's index still holds the non-exec mode: {index_mode}"
    );
    assert_eq!(
        classify_executing_dirt(&rec_f, &f_f),
        DirtClass::CleanOrRecorded,
        "the exec domain is git's: a flip git ignores leaves the recorded path verified"
    );
    match classify_and_witness(&rec_f, &f_f)
        .1
        .expect("a witness")
        .post
    {
        ContentState::Sha256 { exec, .. } => assert!(
            !exec,
            "the witness carries git's index answer (100644), not the worktree bit"
        ),
        other => panic!("a regular file records a Sha256 post, got {other:?}"),
    }
}

                                                                                                 
/// runs finalizing the same bytes attribute to the later one. Dropping the newest-first search
/// re-points both the class and the witness at the older run.
#[test]
fn the_latest_finalized_record_for_the_current_bytes_is_the_one_that_speaks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/latest.d");
    let target = tmp.path().join("checkout/consume-pins.toml");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mk checkout");

    let mut first = RunRecords::open_dir(&dir, "run-first").expect("open");
    let tok = open_path_record(&mut first, &target).expect("open");
    std::fs::write(&target, "identical bytes").expect("write");
    finalize_path_record(&mut first, tok).expect("finalize");
    drop(first);

    let mut second = RunRecords::open_dir(&dir, "run-second").expect("reload");
    let tok = open_path_record(&mut second, &target).expect("open");
    std::fs::write(&target, "identical bytes").expect("the same bytes again");
    finalize_path_record(&mut second, tok).expect("finalize");

                                                                                                  
                                                                              
    let raw = std::fs::read_to_string(dir.join("paths.toml")).expect("read records");
    assert_eq!(
        raw.matches("[[record]]").count(),
        2,
        "two finalized entries for the path: {raw}"
    );

    assert_eq!(
        classify_executing_dirt(&second, &target),
        DirtClass::CleanOrRecorded,
        "the later run's own finalized write is the match, so the class is this run's"
    );
    assert_eq!(
        classify_and_witness(&second, &target)
            .1
            .expect("a witness")
            .run_id,
        "run-second",
        "the witness names the LATER matching run"
    );
    let third = RunRecords::open_dir(&dir, "run-third").expect("reload");
    assert_eq!(
        classify_executing_dirt(&third, &target),
        DirtClass::PriorRunRecorded,
        "a third run sees prior-run content"
    );
    assert_eq!(
        classify_and_witness(&third, &target)
            .1
            .expect("a witness")
            .run_id,
        "run-second",
        "and still attributes it to the later of the two prior runs"
    );
}

                                                                                                
/// v2 stamp refuses `records-schema-outdated` with the archive cure; the pre-fold `ContentState`
/// newtype shape and an unknown field each fail to parse (`records-unreadable`); and a v2 round
/// trip keeps the exec bit, so the witness survives a resume.
///
/// Each fixture is derived from a file the production writer produced, so none of them is a
/// hand-guessed encoding of the schema.
#[test]
fn a_records_file_that_is_not_v2_refuses_and_the_v2_round_trip_keeps_the_exec_bit() {
    use orchard::ceremony::records::ContentState;
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/schema.d");
    let target = tmp.path().join("checkout/tool.sh");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mk checkout");

    let mut rec = RunRecords::open_dir(&dir, "run-1").expect("open");
    let tok = open_path_record(&mut rec, &target).expect("open");
    std::fs::write(&target, "#!/bin/sh\n").expect("write");
    let mut perm = std::fs::metadata(&target).expect("stat").permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&target, perm).expect("chmod +x");
    finalize_path_record(&mut rec, tok).expect("finalize");
    drop(rec);

    let v2 = std::fs::read_to_string(dir.join("paths.toml")).expect("read paths.toml");
    assert!(
        v2.contains("schema-version = 2"),
        "arm sanity: the writer stamps the v2 schema version: {v2}"
    );
    assert!(
        v2.contains("exec = true"),
        "arm sanity: the finalized post carries the exec bit: {v2}"
    );

                                                                                          
    let reopened = RunRecords::open_dir(&dir, "run-2").expect("reload a v2 dir");
    assert_eq!(
        classify_executing_dirt(&reopened, &target),
        DirtClass::PriorRunRecorded,
        "the round-tripped record still speaks for the executable file"
    );
    match classify_and_witness(&reopened, &target)
        .1
        .expect("a witness")
        .post
    {
        ContentState::Sha256 { exec, .. } => {
            assert!(exec, "the exec bit survived the toml round trip")
        }
        other => panic!("expected a Sha256 post, got {other:?}"),
    }

    let refuses = |body: &str, want_id: &str| -> orchard::ceremony::refusal::Refusal {
        std::fs::write(dir.join("paths.toml"), body).expect("write the fixture");
        let err = RunRecords::open_dir(&dir, "run-x").expect_err("the fixture refuses");
        assert_eq!(err.id.token(), want_id, "detail: {}", err.detail);
        err
    };

                                                         
    let unstamped: String = v2
        .lines()
        .filter(|l| !l.starts_with("schema-version"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(
        toml::from_str::<toml::Value>(&unstamped).is_ok(),
        "arm sanity: the unstamped fixture is valid toml, so the refusal is the version check's \
         and not a parse failure"
    );
    let outdated = refuses(&unstamped, "records-schema-outdated");
    let cure = outdated.cure().as_str().to_string();
    assert!(
        cure.contains("archive it") && cure.contains(&dir.display().to_string()),
        "the cure names the archive route and the resolved records dir: {cure}"
    );

                                                                                     
    let legacy = v2.replace("exec = true", "").replace(
        "[record.post.Sha256]",
        "[record.post]\nSha256 = \"deadbeef\"\n#",
    );
    assert_ne!(
        legacy, v2,
        "arm sanity: the legacy rewrite changed the file"
    );
    refuses(&legacy, "records-unreadable");

                                                                    
    let extra = v2.replace("[[record]]", "[[record]]\nmode = \"100755\"");
    assert_ne!(extra, v2, "arm sanity: the unknown-field rewrite landed");
    refuses(&extra, "records-unreadable");
}

                                                                                            
/// DIFFERENT set whose entry at that index is another path — the token carries its own path +
/// run and the check compares BOTH (not the receiving set's own run, which is a tautology). The
/// refusal uses the internal-invariant-violated id (a mis-bound handle token is an internal
/// invariant failure, not an operator-facing read or write failure). The
/// wholesale-persist clobber of two LIVE sets over one dir is a separate single-instance concern
/// owned by the runner (Task 6); both directions of it fail closed toward the gate (noted).
#[test]
fn a_finalize_token_from_another_record_set_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().join("checkout");
    std::fs::create_dir_all(&base).expect("mk checkout");
    let a_path = base.join("a.toml");
    let b_path = base.join("b.toml");
    std::fs::write(&a_path, "seed-a").expect("write a");
    std::fs::write(&b_path, "seed-b").expect("write b");

                                                                     
    let mut a = RunRecords::open_dir(&tmp.path().join("boxes/a.d"), "run-1").expect("open A");
    let tok_a = open_path_record(&mut a, &a_path).expect("open A entry");
                                                                                   
    let mut b = RunRecords::open_dir(&tmp.path().join("boxes/b.d"), "run-2").expect("open B");
    let _tok_b = open_path_record(&mut b, &b_path).expect("open B entry");
                                                                                               
                                                                                                  
    let e = finalize_path_record(&mut b, tok_a).unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains("internal-invariant-violated"),
        "mis-bound token uses the internal-invariant-violated id, not a read/write-failure id: {msg}"
    );
    assert!(
        msg.contains("different run-records handle"),
        "the refusal names the handle-identity mismatch: {msg}"
    );
}

                                                                                                   
/// index 0 is run-A's own entry, and the token's run_id equals that entry's run_id), then hands
/// run-B run-A's token. The pre-R10 identity check (run + path + still-open) all passed; the
/// set_id check refuses it. Without the guard this finalized run-B's bytes into run-A's entry.
#[test]
fn a_finalize_token_refuses_against_a_reopen_of_the_same_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/a.d");
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("mk checkout");
    let declared = checkout.join("declared.txt");
    std::fs::write(&declared, "AAA").expect("seed");

    let mut a = RunRecords::open_dir(&dir, "run-A").expect("open A");
    let tok_a = open_path_record(&mut a, &declared).expect("open entry");

                                                                                                    
                                                            
    drop(a);
    let mut b = RunRecords::open_dir(&dir, "run-A").expect("reopen as B");
    std::fs::write(&declared, "BBB-written-by-run-B").expect("run-B writes");

    let e = finalize_path_record(&mut b, tok_a).unwrap_err();
    assert!(
        e.to_string().contains("different run-records handle"),
        "a token from a re-opened handle must refuse via set_id: {e}"
    );
}

                                                                                              
/// rewrite the file wholesale from its open-time snapshot (which silently deleted the first's
/// rows, including the S5 confirmation).
#[test]
fn a_second_live_handle_refuses_to_clobber_the_first() {
    use orchard::ceremony::records::{S5Confirmation, StepRecord};
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/a.d");

    let mut a = RunRecords::open_dir(&dir, "run-A").expect("open A");
    let mut b = RunRecords::open_dir(&dir, "run-A").expect("open B");

    a.record_step(StepRecord {
        step: "S7ImageBuild".into(),
        run_id: "run-A".into(),
        params: Default::default(),
        input_identities: Default::default(),
        produced: Default::default(),
    })
    .expect("A step");
    a.record_s5_confirmation(S5Confirmation {
        tree_hash: "abc".into(),
        tenant_source_ref: "ref-1".into(),
    })
    .expect("A s5");

                                                                                                
                                                         
    let e = b
        .record_step(StepRecord {
            step: "S8BootGate".into(),
            run_id: "run-A".into(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: Default::default(),
        })
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("changed underneath this run-records handle"),
        "a second handle must fail closed on a concurrent write: {e}"
    );

    let reread = RunRecords::open_dir(&dir, "run-A").expect("reopen");
    assert!(
        reread.step_record("S7ImageBuild").is_some(),
        "A's step survived"
    );
    assert!(
        reread.s5_confirmation().is_some(),
        "A's S5 confirmation survived"
    );
}

/// The cure line of a composed refusal render, read the way an operator reads it: the single line
/// introduced by the `cure:` label, label stripped. `None` when no such line is present, so a
/// missing label and a wrong cure are different reds.
fn composed_cure_line(render: &str) -> Option<&str> {
    render
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("cure: "))
}

/// The refusal a process wrote to stderr, as the operator reads it: the `refusal (…)` line and
/// every continuation line indented under it. Advisory `note:` lines the harness's own env
/// overrides produce are not part of it.
fn composed_refusal_block(stderr: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for line in stderr.lines() {
        let continues = !out.is_empty() && line.starts_with("  ");
        if line.starts_with("refusal (") || continues {
            out.push(line);
        } else if !out.is_empty() {
            break;
        }
    }
    out.join("\n")
}

                                                                                                 
/// failures used to render `RecordsUnreadable`/`RecordsUnwritable` cures, which tell the operator
/// to move their records aside or check permissions and free space for a defect in orchard's own
/// bookkeeping. `a_finalize_token_from_another_record_set_refuses` asserts the token at the first
/// site and `a_second_live_handle_refuses_to_clobber_the_first` asserts only the detail at the
/// second, so neither holds what the operator is told to DO. This pin does, over the whole render.
///
/// A REGRESSION PIN, not the closure (D-W22-2): the closure is the id split, and this arm holds
/// two of its sites.
///
/// Residual, named: "no operator artifact is at fault" is true under the modeled cause of the
/// second-handle refusal — an in-process second handle, the host lock serializing cross-process
/// writers. An operator hand-editing a records file mid-run is outside that lock domain and would
/// read the clause wrongly.
#[test]
fn the_records_handle_identity_refusals_render_the_internal_invariant_cure() {
    use orchard::ceremony::records::StepRecord;
    const CURE: &str = "no operator artifact is at fault; re-run, and report the printed detail \
                        if it recurs";

    let tmp = tempfile::tempdir().expect("tempdir");
    let checkout = tmp.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("mk checkout");
    let declared = checkout.join("declared.txt");
    std::fs::write(&declared, "AAA").expect("seed");

                                                           
    let dir_a = tmp.path().join("a.d");
    let mut a = RunRecords::open_dir(&dir_a, "run-A").expect("open A");
    let tok = open_path_record(&mut a, &declared).expect("open entry");
    drop(a);
    let mut a2 = RunRecords::open_dir(&dir_a, "run-A").expect("reopen A");
    let mis_bound = finalize_path_record(&mut a2, tok).expect_err("a re-opened handle refuses");

                                                                                        
    let dir_b = tmp.path().join("b.d");
    let mut x = RunRecords::open_dir(&dir_b, "run-A").expect("open X");
    let mut y = RunRecords::open_dir(&dir_b, "run-A").expect("open Y");
    let step = |name: &str| StepRecord {
        step: name.to_string(),
        run_id: "run-A".into(),
        params: Default::default(),
        input_identities: Default::default(),
        produced: Default::default(),
    };
    x.record_step(step("S7ImageBuild")).expect("X persists");
    let second_handle = y
        .record_step(step("S8BootGate"))
        .expect_err("the second live handle refuses");

    for (site, refusal, detail_names) in [
        (
            "mis-bound finalize token",
            &mis_bound,
            "different run-records handle",
        ),
        (
            "second live handle",
            &second_handle,
            "changed underneath this run-records handle",
        ),
    ] {
                                                                                                 
                                                           
        assert!(
            refusal.detail.contains(detail_names),
            "{site}: the fixture reached a different refusal: {}",
            refusal.detail
        );
        let render = refusal.to_string();
        assert_eq!(
            refusal.id.token(),
            "internal-invariant-violated",
            "{site}: an internal bookkeeping failure is not an operator-artifact failure: {render}"
        );
                                                                                                  
                                                                                              
                                                    
        let cure = composed_cure_line(&render)
            .unwrap_or_else(|| panic!("{site}: the render carries no cure line: {render}"));
        assert_eq!(cure, CURE, "{site}: the composed cure moved: {render}");
        for harmful in [
            "check permissions and free space",
            "move them aside",
            "records dir",
        ] {
            assert!(
                !cure.contains(harmful),
                "{site}: the cure tells the operator to act on their records for an orchard \
                 invariant failure ({harmful:?}): {render}"
            );
        }
    }
}

#[test]
fn step_records_and_s5_confirmation_persist() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/alpha.d");
    let mut rec = RunRecords::open_dir(&dir, "run-1").expect("open");
    rec.record_step(orchard::ceremony::records::StepRecord {
        step: "S7ImageBuild".into(),
        run_id: rec.run_id().to_string(),
        params: [("domain".to_string(), "box.test".to_string())].into(),
        input_identities: [("ceremony-head".to_string(), "abc123".to_string())].into(),
        produced: [(
            "img".to_string(),
            orchard::ceremony::records::ProducedArtifact {
                path: "/tmp/box-images/recipes-image-abc123.img".into(),
                sha256: "d0d0".into(),
            },
        )]
        .into(),
    })
    .expect("record step");
    rec.record_s5_confirmation(S5Confirmation {
        tree_hash: "cafe".into(),
        tenant_source_ref: "f0ad0fc".into(),
    })
    .expect("record s5");
    let rec2 = RunRecords::open_dir(&dir, "run-2").expect("reload");
    assert_eq!(
        rec2.step_record("S7ImageBuild").expect("step").params["domain"],
        "box.test"
    );
    assert_eq!(rec2.s5_confirmation().expect("s5").tree_hash, "cafe");
                                                                                  
    for f in ["steps.toml", "paths.toml"] {
        let text = std::fs::read_to_string(dir.join(f)).unwrap_or_default();
        assert_eq!(scan_for_forbidden_content(&text), None, "{f}");
    }
}

                                                                                           

#[test]
fn sibling_recognition_consults_the_store_never_the_records() {
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = tmp.path().join("artifact-store");
    std::fs::create_dir_all(&store).expect("mk store");
    let bytes = b"published binary bytes";
    let sha = hex::encode(Sha256::digest(bytes));
    std::fs::write(store.join(format!("recipes-app@{sha}")), bytes).expect("store rev");

    let sibling = tmp.path().join("recipes/published-pins.toml");
    std::fs::create_dir_all(sibling.parent().expect("parent")).expect("mk sibling");

                                                                                        
                                                                                               
                                                             
    std::fs::write(
        &sibling,
        format!("schema-version = 1\n\n[artifacts]\nrecipes-app = \"{sha}\"\n"),
    )
    .expect("write pins");
    assert!(sibling_output_recognized(&store, &sibling));

                                                                                           
    let bogus = "ab".repeat(32);
    std::fs::write(
        &sibling,
        format!("schema-version = 1\n\n[artifacts]\nrecipes-app = \"{bogus}\"\n"),
    )
    .expect("write pins");
    assert!(!sibling_output_recognized(&store, &sibling));

                                                                                                
    std::fs::write(
        &sibling,
        format!("[artifacts.recipes-app]\nsha256 = \"{sha}\"\nkind = \"binary\"\n"),
    )
    .expect("write pins");
    assert!(!sibling_output_recognized(&store, &sibling));

                                                 
    std::fs::write(&sibling, "not a pin manifest").expect("write");
    assert!(!sibling_output_recognized(&store, &sibling));
}

                                                                                                   

#[test]
fn boxes_enumeration_pairs_profiles_with_their_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let boxes = tmp.path().join("boxes");
                                                                                             
    let records_root = tmp.path().join("state").join("orchard").join("records");
    std::fs::create_dir_all(&boxes).expect("mk boxes");
    std::fs::create_dir_all(records_root.join("alpha.d")).expect("mk records");
    std::fs::write(boxes.join("alpha.toml"), "ip = \"1.2.3.4\"\n").expect("write");
    std::fs::write(boxes.join("beta.toml"), "ip = \"5.6.7.8\"\n").expect("write");
    let entries = enumerate_boxes(&boxes, &records_root);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "alpha");
    assert!(
        entries[0].records_dir.is_some(),
        "alpha is paired with its operator-side records"
    );
    assert!(
        !entries[0].records_dir.as_ref().unwrap().starts_with(&boxes),
        "the records dir is operator-side, never inside the boxes/ checkout dir"
    );
    assert_eq!(entries[1].name, "beta");
    assert!(entries[1].records_dir.is_none(), "beta has no records yet");
    assert_eq!(
        records_dir_of(&records_root, &boxes.join("alpha.toml")),
        records_root.join("alpha.d")
    );
}

                                                                                  

/// Serializes the arms that hold a `flock` fd against the arms that `fork`+`exec` a child.
///
/// MEASURED, not assumed. `flock` belongs to the open file DESCRIPTION, and a `Command::spawn`
/// duplicates the whole fd table into the child at `fork`. Rust opens files `O_CLOEXEC`, so the
/// inherited fd is dropped at `exec` — but between `fork` and `exec` the child holds a reference to
/// every other test thread's lock fd, and for that window the lock outlives the holder's `drop`. A
/// concurrent acquirer in another arm then gets `LockHeld` and the arm reds for a reason that has
/// nothing to do with its subject. This test binary is the only place several independent "hosts"
/// live in one process, so this is a harness artefact, not a product defect (one orchard process
/// per host in production).
///
/// Rates on this tree, whole test binary, `TMPDIR` on a non-full filesystem:
                                                                                    
/// `--test-threads=1` 0/40. Taking this guard: 0/60. It is the same intermittent
                                                                                                 
/// which did not reproduce); the mechanism above does reproduce, on demand, by raising the fork
/// rate.
///
/// Poisoning is deliberately ignored (`into_inner`): one arm's panic must not turn every other arm
/// red for an unrelated reason.
static LOCK_ARMS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_arm_guard() -> std::sync::MutexGuard<'static, ()> {
    LOCK_ARMS.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn second_writing_acquisition_refuses_naming_the_holder() {
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let held = acquire_at(tmp.path(), "build", None).expect("first acquire");
    assert!(held.is_holder());
    let e = acquire_at(tmp.path(), "prod", None).unwrap_err();
    let rendered = e.to_string();
    assert!(rendered.contains("lock-held"), "{rendered}");
    assert!(
        rendered.contains(&std::process::id().to_string()) && rendered.contains("build"),
        "names the holder pid+verb: {rendered}"
    );
}

#[test]
fn a_child_with_the_live_token_joins_and_a_stale_token_never_does() {
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
                                                                                                 
    let held = acquire_at(tmp.path(), "run", None).expect("first acquire");
    let joined = acquire_at(tmp.path(), "build", Some(held.token())).expect("token join");
    assert!(!joined.is_holder(), "a joiner holds no fd of its own");
    assert_eq!(joined.token(), held.token());
                                                     
    assert!(acquire_at(tmp.path(), "build", Some("deadbeef")).is_err());
    drop(joined);
    drop(held);
                                                                                                
                                                                       
    let fresh = acquire_at(tmp.path(), "vendor", Some("stale-token-from-a-dead-run"))
        .expect("fresh acquire");
    assert!(fresh.is_holder());
    assert_ne!(fresh.token(), "stale-token-from-a-dead-run");
}

#[test]
fn acquire_for_is_total_writing_acquires_read_only_never_does() {
    let _serial = lock_arm_guard();
    use clap::Parser as _;
    let parse = |argv: &[&str]| {
        let mut full = vec!["orchard"];
        full.extend_from_slice(argv);
        orchard::cli::Cli::try_parse_from(full)
            .expect("parse")
            .command
    };
    let tmp = tempfile::tempdir().expect("tempdir");
                                                                                         
                                                                                                
                                                                 
    for argv in [
        vec!["vendor"],
        vec!["prime"],
        vec!["sync-pins"],
        vec!["generate-keys"],
        vec!["market", "upgrade", "--source", "x"],
        vec!["market", "store", "prune"],
        vec!["build", "--domain", "box.test"],
    ] {
        let lock = acquire_for_at(&parse(&argv), tmp.path(), None)
            .unwrap_or_else(|e| panic!("{argv:?}: {e}"))
            .unwrap_or_else(|| panic!("{argv:?} is WRITING and must acquire"));
        assert!(lock.is_holder());
        drop(lock);                                            
    }
    for argv in [
        vec!["doctor"],
        vec!["market", "verify"],
        vec!["market", "outdated"],
        vec!["market", "store", "status"],
        vec!["status", "h", "--ssh-identity", "/k"],
        vec!["derive-rescue-offline", "--image", "/x.img"],
    ] {
        let got = acquire_for_at(&parse(&argv), tmp.path(), None)
            .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        assert!(got.is_none(), "{argv:?} is READ-ONLY and never acquires");
    }
                                                                                               
    let held = acquire_at(tmp.path(), "build", None).expect("hold");
    let got = acquire_for_at(&parse(&["doctor"]), tmp.path(), None).expect("advisory only");
    assert!(got.is_none());
    drop(held);
}

                                                                                                   
  
                                                                                                  
                                                                                                   
                                                                                              
                                                                                                   
                   
  
                                                                                                
                                                                                                    
                                                                                                     
                                     
  
                                                                                        
                                                                                               
                                                                                  
                                                                                  
                                                                                             
                                                                                         
                                                                                                 
                                                                                           
                                                                                    
                                                                                                  
                                                                                                    
                                                                                                   
                                                                                              
                                                                 
fn holder_tmp_path(base: &Path) -> std::path::PathBuf {
    base.join(format!("host.lock.holder.{}.tmp", std::process::id()))
}

#[test]
fn a_failed_holder_diagnostic_write_refuses_the_acquisition()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = lock_arm_guard();
                                                                                                      
                                                                                                  
                                                                                                   
                                                                      
                                                                                                   
                                                                                                 
                                                     
    let tmp = tempfile::tempdir()?;
    let base = tmp.path();
    std::fs::create_dir_all(holder_tmp_path(base))?;
    let e = acquire_at(base, "build", None)
        .err()
        .ok_or("acquire_at must REFUSE when the holder diagnostic cannot be written")?;
    let rendered = e.to_string();
    assert!(
        rendered.contains("lock-unavailable"),
        "the refusal must carry the lock-unavailable id: {rendered}"
    );
    assert!(
        rendered.contains("holder diagnostic"),
        "the refusal must name the failing write: {rendered}"
    );
                                                                                                   
                                                                                                
                                                                                       
    std::fs::remove_dir(holder_tmp_path(base))?;
    let held = acquire_at(base, "build", None)?;
    let joined = acquire_at(base, "vendor", Some(held.token()))?;
    assert!(!joined.is_holder());
    Ok(())
}

                                                                                                   

/// Spawn the real binary on a WRITING verb against a fixture host-lock dir. The ambient ceremony
/// env is cleared first, so only `envs` reaches the child and no arm inherits another's. Returns
/// (exit code, stderr).
fn spawn_vendor(cwd: &Path, home: &Path, lock_dir: &Path, envs: &[(&str, &str)]) -> (i32, String) {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"));
    c.current_dir(cwd)
        .env_remove("FRUIT_ARTIFACT_STORE")
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env_remove("ORCHARD_CEREMONY_PPID")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("ORCHARD_LOCK_DIR", lock_dir)
        .args(["vendor"]);
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c.output().expect("spawn");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_binary_refuses_under_a_held_lock_and_joins_with_the_token() {
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
                                                                              
                                                
    let lock_dir = tmp.path().join("lockdir");
    let held = acquire_at(&lock_dir, "test-harness", None).expect("hold");

    let spawn = |envs: &[(&str, &str)]| spawn_vendor(tmp.path(), &home, &lock_dir, envs);

                                                                                
    let (code, stderr) = spawn(&[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("lock-held") && stderr.contains("test-harness"),
        "{stderr}"
    );

                                                                                            
                                                           
    let (code, stderr) = spawn(&[("ORCHARD_LOCK_TOKEN", held.token())]);
    assert_eq!(code, 2, "{stderr}");
    assert!(!stderr.contains("lock-held"), "{stderr}");
    assert!(stderr.contains("context-unresolvable"), "{stderr}");

                                                                                                     
                                                                                                     
                                                                                           
    let (code, stderr) = spawn(&[
        ("ORCHARD_LOCK_TOKEN", held.token()),
        ("ORCHARD_CEREMONY_PPID", "2147480000"),
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("runner-liveness-lost") && stderr.contains("runner exited before"),
        "a dead runner ppid must refuse the join: {stderr}"
    );

                                                                                                    
                                               
    let self_pid = std::process::id().to_string();
    let (code, stderr) = spawn(&[
        ("ORCHARD_LOCK_TOKEN", held.token()),
        ("ORCHARD_CEREMONY_PPID", self_pid.as_str()),
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(!stderr.contains("runner exited before"), "{stderr}");
    assert!(stderr.contains("context-unresolvable"), "{stderr}");

                                                                                      
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"));
    c.current_dir(tmp.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("ORCHARD_LOCK_DIR", &lock_dir)
        .args(["market", "store", "status"]);
    let out = c.output().expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("torn read"), "T7 advisory owed: {stderr}");
    assert!(!stderr.contains("lock-held"), "{stderr}");
    drop(held);
}

#[test]
fn a_malformed_runner_ppid_refuses_the_acquisition_instead_of_running_unarmed() {
                                                                                                  
                                                                                                
                                                                                                 
                                                                                                   
                                                                           
    use orchard::ceremony::lock::CEREMONY_PPID_ENV;
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let lock_dir = tmp.path().join("lockdir");
    let held = acquire_at(&lock_dir, "test-harness", None).expect("hold");
    let spawn = |ppid: &str| {
        spawn_vendor(
            tmp.path(),
            &home,
            &lock_dir,
            &[
                ("ORCHARD_LOCK_TOKEN", held.token()),
                (CEREMONY_PPID_ENV, ppid),
            ],
        )
    };
                                                                                                 
                                                                               
    let (code, stderr) = spawn(&std::process::id().to_string());
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("context-unresolvable"), "{stderr}");

                                                                         
    for malformed in ["0", "-5", "not-a-pid", " "] {
        let (code, stderr) = spawn(malformed);
        assert_eq!(code, 2, "{malformed:?}: {stderr}");
        assert!(
            stderr.contains("runner-liveness-lost") && stderr.contains(CEREMONY_PPID_ENV),
            "a malformed {CEREMONY_PPID_ENV}={malformed:?} must refuse the acquisition: {stderr}"
        );
        assert!(
            !stderr.contains("context-unresolvable"),
            "the refusal must precede the verb body — a fail-open branch runs the worker unarmed \
             ({malformed:?}): {stderr}"
        );
    }
    drop(held);
}

/// The `/proc/<pid>/stat` state letter. The comm field is parenthesized and may itself contain
/// spaces and parens, so the state is the first token after the LAST `)`.
#[cfg(target_os = "linux")]
fn proc_state(pid: i32) -> Option<char> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = s.rsplit_once(')')?;
    rest.split_whitespace().next()?.chars().next()
}

/// Measure the fixture's kernel-visible liveness the way any observer sees it: `Some(true)` = the
/// pidfd opened and `poll` reports it readable within `timeout_ms` (readable ⇒ terminated),
/// `Some(false)` = opened and not readable, `None` = `pidfd_open` failed (ESRCH for a pid with no
/// task). Fixture state, not the decision under test — that is the worker's refusal.
#[cfg(target_os = "linux")]
fn pidfd_readable_within(pid: i32, timeout_ms: i32) -> Option<bool> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if fd < 0 {
        return None;
    }
    let fd = fd as libc::c_int;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    unsafe { libc::close(fd) };
    Some(rc > 0 && pfd.revents != 0)
}

#[cfg(target_os = "linux")]
#[test]
fn a_zombie_runner_ppid_refuses_the_acquisition_through_the_poll_not_the_open() {
                                                                                                  
                                                                                                    
                                                                                              
                                       
    use orchard::ceremony::lock::CEREMONY_PPID_ENV;
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let lock_dir = tmp.path().join("lockdir");
    let held = acquire_at(&lock_dir, "test-harness", None).expect("hold");
    let spawn = |ppid: &str| {
        spawn_vendor(
            tmp.path(),
            &home,
            &lock_dir,
            &[
                ("ORCHARD_LOCK_TOKEN", held.token()),
                (CEREMONY_PPID_ENV, ppid),
            ],
        )
    };

                                                                                               
                                                                           
    let (code, stderr) = spawn(&std::process::id().to_string());
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("context-unresolvable"), "{stderr}");

                                                                                                    
                                                                                                 
                                                           
    let zombie = unsafe { libc::fork() };
    assert!(
        zombie >= 0,
        "fork the runner fixture: {}",
        std::io::Error::last_os_error()
    );
    if zombie == 0 {
                                                                                                  
                                                         
        #[allow(clippy::disallowed_methods)]
        unsafe {
            libc::_exit(0)
        };
    }

                                                                                                
                                                                                                    
                                                                                                   
                                                             
    assert_eq!(
        pidfd_readable_within(zombie, 5_000),
        Some(true),
        "the fixture pid {zombie} must open as a pidfd and poll readable"
    );
    assert_eq!(
        proc_state(zombie),
        Some('Z'),
        "the fixture pid {zombie} must be a zombie, not reaped and not running"
    );

    let (code, stderr) = spawn(&zombie.to_string());

                                                                                               
                                                                        
    assert_eq!(pidfd_readable_within(zombie, 0), Some(true), "{stderr}");
    assert_eq!(proc_state(zombie), Some('Z'), "{stderr}");
    assert_eq!(
        unsafe { libc::waitpid(zombie, std::ptr::null_mut(), 0) },
        zombie,
        "reap the fixture"
    );

    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("runner-liveness-lost")
            && stderr.contains("runner exited before this worker armed its death signal"),
        "a zombie runner ppid must refuse the join: {stderr}"
    );
    assert!(
        !stderr.contains("cannot open a liveness handle"),
        "the refusal must be the liveness verdict, not an open failure: {stderr}"
    );
    assert!(
        !stderr.contains("context-unresolvable"),
        "the refusal must precede the verb body — a poll that never reports gone runs the worker \
         joined to a dead runner: {stderr}"
    );
    drop(held);
}

                                                                                                
/// before they spawn, so their workers take the JOIN branch; this one drives the branch a worker
/// takes when its runner freed the flock by dying (the startup race). Driven over a lock base that
/// does not exist yet, so the worker's `flock_nb` succeeds and the branch under drive is the
/// acquire branch.
///
/// Claimed: over a free lock base, a worker naming an ESRCH-dead runner pid and a worker naming a
/// zombie (unreaped) runner pid each refuse with the liveness id, before the verb body and before
/// the acquisition's first filesystem write. Not claimed: the fate of a runner that dies AFTER the
/// arm — that is PDEATHSIG delivery, held by `a_joining_worker_dies_when_its_runner_is_killed`.
#[cfg(target_os = "linux")]
#[test]
fn a_free_lock_worker_refuses_a_dead_or_zombie_runner_before_it_acquires() {
    use orchard::ceremony::lock::CEREMONY_PPID_ENV;
    const DETAIL: &str = "refusal (runner-liveness-lost): the ceremony runner exited before this \
                          worker armed its death signal; aborting rather than running detached";
    const CURE: &str = "re-run the ceremony. ORCHARD_CEREMONY_PPID is exported by the runner, \
                        never set by hand";

    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
                                                                                                   
                                                                                                    
                       
    let composed = format!("{DETAIL}\n  cure: {CURE}");
    let base = tmp.path().join("free-lock-base");
                                                                                        
                                                                                                   
                                                                                 
    let spawn = |ppid: &str| spawn_vendor(tmp.path(), &home, &base, &[(CEREMONY_PPID_ENV, ppid)]);

                                                                                                   
                                                                                                  
                                                                                              
    let (code, stderr) = spawn(&std::process::id().to_string());
    assert_eq!(code, 2, "{stderr}");
    assert!(
        !stderr.contains("lock-held"),
        "the fixture base is held, so the worker joined rather than acquiring: {stderr}"
    );
    assert!(stderr.contains("context-unresolvable"), "{stderr}");
    assert!(
        base.join("host.lock").exists(),
        "an acquiring worker leaves its lock file behind: {}",
        base.display()
    );
                                                                                                    
    std::fs::remove_dir_all(&base).expect("clear the fixture base");
    assert!(!base.exists(), "{}", base.display());

    let assert_refused = |label: &str, code: i32, stderr: &str| {
        assert_eq!(code, 2, "{label}: {stderr}");
        assert_eq!(
            stderr.matches("refusal (").count(),
            1,
            "{label}: exactly one refusal composes this render: {stderr}"
        );
        assert!(
            !stderr.contains("context-unresolvable"),
            "{label}: the worker reached the verb body, so the acquire branch ran unarmed: {stderr}"
        );
        assert_eq!(
            composed_refusal_block(stderr),
            composed,
            "{label}: the composed refusal at the acquire branch moved: {stderr}"
        );
        assert!(
            !base.exists(),
            "{label}: the refusal created the lock base at {}, so the gate ran after the \
             acquisition had begun: {stderr}",
            base.display()
        );
    };

                                                                                               
                             
    let (code, stderr) = spawn("2147480000");
    assert_refused("dead runner pid", code, &stderr);

                                                                                            
                                                                                              
                                                                                           
    let zombie = unsafe { libc::fork() };
    assert!(
        zombie >= 0,
        "fork the runner fixture: {}",
        std::io::Error::last_os_error()
    );
    if zombie == 0 {
                                                                                                  
                                                         
        #[allow(clippy::disallowed_methods)]
        unsafe {
            libc::_exit(0)
        };
    }
    assert_eq!(
        pidfd_readable_within(zombie, 5_000),
        Some(true),
        "the fixture pid {zombie} must open as a pidfd and poll readable"
    );
    assert_eq!(
        proc_state(zombie),
        Some('Z'),
        "the fixture pid {zombie} must be a zombie, not reaped and not running"
    );
    let (code, stderr) = spawn(&zombie.to_string());
    let readable_after = pidfd_readable_within(zombie, 0);
    let state_after = proc_state(zombie);
    assert_eq!(
        unsafe { libc::waitpid(zombie, std::ptr::null_mut(), 0) },
        zombie,
        "reap the fixture"
    );
                                                                                                  
                                                               
    assert_eq!(readable_after, Some(true), "{stderr}");
    assert_eq!(state_after, Some('Z'), "{stderr}");
    assert_refused("zombie runner pid", code, &stderr);
}

                                                                                                 
/// that makes the old text harmful. The four parent-death sites used to render `LockUnavailable`,
/// whose cure ends "remove a stale lock dir" — and a worker refuses the join precisely when
/// ANOTHER invocation holds the host lock, so following that cure deletes a live holder's lock
                                                                                                   
/// asserts what the operator is told to do, with the live holder measured in the same run.
///
/// A REGRESSION PIN, not the closure (D-W22-2): the closure is `RunnerLivenessLost` not sharing
/// `LockUnavailable`'s key. This holds one of its four sites.
#[test]
fn the_parent_death_refusal_never_tells_a_joining_worker_to_remove_the_live_lock_dir() {
    use orchard::ceremony::lock::CEREMONY_PPID_ENV;
    const CURE: &str = "re-run the ceremony. ORCHARD_CEREMONY_PPID is exported by the runner, \
                        never set by hand";

    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let lock_dir = tmp.path().join("lockdir");
    let held = acquire_at(&lock_dir, "test-harness", None).expect("hold");

                                                                                              
                                                                                 
    let (code, stderr) = spawn_vendor(tmp.path(), &home, &lock_dir, &[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("lock-held") && stderr.contains("test-harness"),
        "the fixture holder is not live, so this arm proves nothing: {stderr}"
    );

                                                                                            
    let (code, stderr) = spawn_vendor(
        tmp.path(),
        &home,
        &lock_dir,
        &[
            ("ORCHARD_LOCK_TOKEN", held.token()),
            (CEREMONY_PPID_ENV, "2147480000"),
        ],
    );
    assert_eq!(code, 2, "{stderr}");
    assert_eq!(
        stderr.matches("refusal (").count(),
        1,
        "exactly one refusal composes this render: {stderr}"
    );
    let block = composed_refusal_block(&stderr);
    assert!(
        block.starts_with("refusal (runner-liveness-lost): the ceremony runner exited before "),
        "the composed render must open with the liveness id and this site's detail: {stderr}"
    );
    assert_eq!(
        composed_cure_line(&block),
        Some(CURE),
        "the composed cure moved: {stderr}"
    );
    for harmful in ["lock dir", "lock-unavailable", "ownership and permissions"] {
        assert!(
            !block.contains(harmful),
            "the refusal hands a lock-file remedy ({harmful:?}) to a worker refusing on runner \
             liveness, while a holder is live: {stderr}"
        );
    }
    drop(held);
}

#[test]
fn a_released_lock_leaves_no_sidecar_so_the_t7_advisory_stays_silent() {
    let _serial = lock_arm_guard();
                                                                                                   
                                                                                              
                                                                                                    
                                                                                                 
                                                                                                   
                                                                                       
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let lock_dir = tmp.path().join("lockdir");
    let advisory = || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"))
            .current_dir(tmp.path())
            .env_remove("FRUIT_ARTIFACT_STORE")
            .env_remove("ORCHARD_LOCK_TOKEN")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("ORCHARD_LOCK_DIR", &lock_dir)
            .args(["market", "store", "status"])
            .output()
            .expect("spawn");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
                                                                                              
                                    
    let held = acquire_at(&lock_dir, "test-harness", None).expect("hold");
    let while_held = advisory();
    assert!(
        while_held.contains("torn read") && while_held.contains("test-harness"),
        "the T7 advisory must fire while the lock is held: {while_held}"
    );
                                                                                                 
                                                                            
    drop(held);
    let after = advisory();
    assert!(
        !after.contains("torn read"),
        "the T7 advisory fired over a RELEASED lock — the holder sidecar outlived its lock: {after}"
    );
    assert!(
        !after.contains("test-harness"),
        "the released lock's holder is still named on stderr: {after}"
    );
}

                                                                                                    
/// a holder or a worker instead of running assertions, so the arming path runs in a real
/// runner→worker process pair, never in the test process.
#[cfg(target_os = "linux")]
const PDEATH_DRIVEN_TEST: &str = "a_joining_worker_dies_when_its_runner_is_killed";

                                                                                                  
#[allow(clippy::zombie_processes)]
#[cfg(target_os = "linux")]
fn run_pdeath_role(role: &str) -> ! {
    use orchard::ceremony::lock::{CEREMONY_PPID_ENV, LOCK_TOKEN_ENV};
    let lock_dir = std::path::PathBuf::from(std::env::var("ORCHARD_LOCK_DIR").expect("lock dir"));
    let ready =
        std::path::PathBuf::from(std::env::var("ORCHARD_PDEATH_READY").expect("ready path"));
    match role {
        "holder" => {
                                                                                                    
                                                                                                     
            let held = acquire_at(&lock_dir, "holder", None).expect("holder acquires the lock");
            let exe = std::env::var("ORCHARD_PDEATH_SELF").expect("self exe");
            std::process::Command::new(exe)
                .args([
                    PDEATH_DRIVEN_TEST,
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ORCHARD_PDEATH_ROLE", "worker")
                .env("ORCHARD_LOCK_DIR", &lock_dir)
                .env("ORCHARD_PDEATH_READY", &ready)
                .env(LOCK_TOKEN_ENV, held.token())
                .env(CEREMONY_PPID_ENV, std::process::id().to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("holder spawns the worker");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "worker" => {
            let token = std::env::var(LOCK_TOKEN_ENV).expect("token");
                                                                                                   
                                                                                          
            let _joined = acquire_at(&lock_dir, "worker", Some(&token)).expect("worker joins");
            std::fs::write(&ready, std::process::id().to_string()).expect("write ready");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        other => panic!("unknown pdeath role {other}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_joining_worker_dies_when_its_runner_is_killed() {
                                                                                                       
                                                                                                      
                                                                                                    
                                                                                                         
                                                                                                      
                                                                               
    if let Ok(role) = std::env::var("ORCHARD_PDEATH_ROLE") {
        run_pdeath_role(&role);
    }
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_dir = tmp.path().join("lockdir");
    let ready = tmp.path().join("worker-ready");
    let exe = std::env::current_exe().expect("current_exe");
    let mut holder = std::process::Command::new(&exe)
        .args([
            PDEATH_DRIVEN_TEST,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ORCHARD_PDEATH_ROLE", "holder")
        .env("ORCHARD_PDEATH_SELF", &exe)
        .env("ORCHARD_LOCK_DIR", &lock_dir)
        .env("ORCHARD_PDEATH_READY", &ready)
        .env_remove("ORCHARD_LOCK_TOKEN")
        .env_remove("ORCHARD_CEREMONY_PPID")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn holder");
                                                                                                  
    let mut worker_pid: Option<i32> = None;
    for _ in 0..400 {
        if let Ok(s) = std::fs::read_to_string(&ready)
            && let Ok(p) = s.trim().parse::<i32>()
        {
            worker_pid = Some(p);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let worker_pid = worker_pid.unwrap_or_else(|| {
        let _ = holder.kill();
        panic!("the worker did not arm within the timeout");
    });
                                                      
    assert_eq!(
        unsafe { libc::kill(holder.id() as i32, libc::SIGKILL) },
        0,
        "SIGKILL the holder"
    );
    let _ = holder.wait();
    let mut worker_dead = false;
    for _ in 0..400 {
        if unsafe { libc::kill(worker_pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            worker_dead = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if !worker_dead {
        unsafe { libc::kill(worker_pid, libc::SIGKILL) };
    }
    assert!(
        worker_dead,
        "the joining worker outlived its SIGKILLed runner — PDEATHSIG did not fire"
    );
}

                                                                   

use orchard::ceremony::admission::{
    self, Measured, RunInvocation, parse_porcelain_z, resolve_values, step_done,
};
use orchard::ceremony::probes::{DoneResult, ProbeCtx};
use orchard::ceremony::records::{ProducedArtifact, StepRecord};
use orchard::ceremony::spine::{SPINE, StepId};
use orchard::deploy::context::{ContextSources, ResolvedContext, ValueSource};
use orchard::deploy::profile::Profile;

/// A fixture tree: a repo root, a populated artifact store beside it, and a records dir.
struct Fixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    ctx: ResolvedContext,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("orchard");
    std::fs::create_dir_all(&root).expect("root");
    let store = tmp.path().join("artifact-store");
    std::fs::create_dir_all(&store).expect("store");
    let ctx = ResolvedContext {
        repo_root: orchard::ceremony::Utf8PathBuf::from(root.to_str().expect("utf8 test path")),
        artifact_store: orchard::ceremony::Utf8PathBuf::from(
            store.to_str().expect("utf8 test path"),
        ),
        repo_manifest: orchard::ceremony::Utf8PathBuf::from(
            root.join("repo-manifest.toml")
                .to_str()
                .expect("utf8 test path"),
        ),
        sources: ContextSources {
            repo_root: ValueSource::Flag,
            artifact_store: ValueSource::Flag,
            repo_manifest: ValueSource::Flag,
            context_file: None,
        },
    };
    Fixture {
        _tmp: tmp,
        root,
        ctx,
    }
}

/// Ratify the executing checkout's declared space from `fx.root`'s current state and point `i` at
/// it (§1.4). For a custom-fixture test that inits its own repo before `run_ceremony`.
fn ratify_at(fx: &Fixture, i: &mut RunInvocation) {
    let repo_form = fx.root.join(".repo-form");
    std::fs::create_dir_all(&repo_form).expect("mk repo-form");
    let body = orchard::ceremony::gate_commit::declared_space_body(&fx.root)
        .expect("measure the executing checkout's key set");
    std::fs::write(repo_form.join("executing.keys"), body).expect("write executing.keys");
    i.repo_form_dir = Some(orchard::ceremony::Utf8PathBuf::from(
        repo_form.to_str().expect("utf8 repo-form path"),
    ));
}

fn records_at(fx: &Fixture) -> RunRecords {
    RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records")
}

/// Initialise `root` as a git repo with an empty committed baseline. The bare `fixture`
/// root is a NON-repo, where `git_dirty_paths` returns the Unevaluable answer every call site
/// collapsed to clean — so a git-facing arm over it proved nothing about the dirty branch. Identity
/// is set locally so the commit does not depend on global git config; `--allow-empty` because the
/// root carries no tracked files, and any file a test then writes shows as untracked dirt.
fn git_init_baseline(root: &std::path::Path) {
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["commit", "-q", "--allow-empty", "-m", "baseline"],
    ] {
        let ok = std::process::Command::new("git")
            .current_dir(root)
            .args(&args)
            .output()
            .expect("git");
        assert!(
            ok.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }
}

/// A [`fixture`] whose root is a real git repo with a clean baseline. The non-repo
/// `fixture` stands in for the Unevaluable dirt answer; this one for the Scanned/dirty cases a
/// git-facing arm must drive.
fn repo_fixture() -> Fixture {
    let fx = fixture();
    git_init_baseline(&fx.root);
    fx
}

#[test]
fn repo_fixture_presents_real_dirt_that_the_bare_fixture_cannot() {
                                                                                                    
                                                                                                      
                                                                                          
    use admission::DirtScan;
    let fx = repo_fixture();
    assert_eq!(
        admission::git_dirty_paths(&fx.root),
        DirtScan::Scanned(vec![]),
        "repo_fixture root is a clean git repo"
    );
    std::fs::write(fx.root.join("pins.toml"), "x\n").expect("w");
    let DirtScan::Scanned(dirt) = admission::git_dirty_paths(&fx.root) else {
        panic!("repo_fixture is a real repo");
    };
    assert!(
        dirt.iter().any(|p| p.ends_with("pins.toml")),
        "a written file is real dirt: {dirt:?}"
    );
    assert!(
        matches!(
            admission::git_dirty_paths(&fixture().root),
            DirtScan::Unevaluable(_)
        ),
        "the bare fixture is a non-repo (Unevaluable) — the FAC-GC-7 gap"
    );
}

#[test]
fn s8_gate_child_gets_the_image_env_the_legs_demand() {
                                                                  
                                                                                                    
                                                                                          
                                  
    use orchard::ceremony::param::ParamValues;
    use orchard::ceremony::runner::s8_child_env;
    let fx = fixture();
    let mut records = records_at(&fx);
                                                                                     
    assert!(
        s8_child_env(&records, &ParamValues::default()).is_empty(),
        "no recorded image, no image env"
    );
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/box-images/recipes-image-abc.img".into(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record S7");
    let mut values = ParamValues::default();
    values.insert("box_login_identity", "/home/op/.ssh/box_ed25519");
    let env = s8_child_env(&records, &values);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(
        get("RECIPES_DRYRUN_IMG"),
        Some("/tmp/box-images/recipes-image-abc.img"),
        "the dryrun leg's image"
    );
    assert_eq!(
        get("RECIPES_PROD_IMG"),
        Some("/tmp/box-images/recipes-image-abc.img"),
        "the installed-disk leg's image"
    );
    assert_eq!(
        get("RECIPES_PROD_PRIVKEY"),
        Some("/home/op/.ssh/box_ed25519"),
        "the prod leg's ssh privkey (the resolved box_login_identity)"
    );
}

#[test]
fn only_s8_composes_child_env_through_the_step_field() {
                                                                                                     
                                                                                                
                                                                                                  
                                                                                          
    use orchard::ceremony::param::ParamValues;
    let fx = fixture();
    let mut records = records_at(&fx);
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/box-images/recipes-image-abc.img".into(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record S7");
    let mut values = ParamValues::default();
    values.insert("box_login_identity", "/home/op/.ssh/box_ed25519");
    for step in SPINE.iter() {
        let env = (step.compose_env)(&records, &values);
        if step.id == StepId::S8BootGate {
            assert!(
                env.iter().any(|(k, v)| k == "RECIPES_DRYRUN_IMG"
                    && v == "/tmp/box-images/recipes-image-abc.img"),
                "S8 composes the gate legs' image env: {env:?}"
            );
        } else {
            assert!(
                env.is_empty(),
                "{} composes no child env (only S8 does): {env:?}",
                step.id.token()
            );
        }
    }
}

#[test]
fn child_env_folds_the_step_composer_over_the_lock_token() {
                                                                                                  
                                                                                      
                                                                                                   
                                                                                                
                               
    use orchard::ceremony::param::ParamValues;
    use orchard::ceremony::runner::child_env;
    let fx = fixture();
    let mut records = records_at(&fx);
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/box-images/recipes-image-abc.img".into(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record S7");
    let values = ParamValues::default();
    let store = std::path::Path::new("/srv/ceremony-store");
    let s8 = child_env(
        step_of(StepId::S8BootGate),
        Some("token-abc"),
        store,
        &records,
        &values,
    );
    assert!(
        s8.iter()
            .any(|(k, v)| k == "ORCHARD_LOCK_TOKEN" && v == "token-abc"),
        "S8's child joins the host lock: {s8:?}"
    );
                                                                                                
                                                                                             
    assert!(
        s8.iter()
            .any(|(k, v)| k == "ORCHARD_CEREMONY_PPID" && v == &std::process::id().to_string()),
        "S8's child carries the runner ppid: {s8:?}"
    );
    assert!(
        s8.iter().any(|(k, v)| k == "RECIPES_DRYRUN_IMG"
            && v == "/tmp/box-images/recipes-image-abc.img"),
        "child_env folds S8's gate-image env over the token: {s8:?}"
    );
                                                                                
    assert!(
        s8.iter()
            .any(|(k, v)| k == "FRUIT_ARTIFACT_STORE" && v == "/srv/ceremony-store"),
        "child_env carries the resolved artifact store: {s8:?}"
    );
    let s1 = child_env(
        step_of(StepId::S1BuildContainer),
        Some("token-abc"),
        store,
        &records,
        &values,
    );
    assert_eq!(
        s1,
        vec![
            ("ORCHARD_LOCK_TOKEN".to_string(), "token-abc".to_string()),
            (
                "ORCHARD_CEREMONY_PPID".to_string(),
                std::process::id().to_string()
            ),
            (
                "FRUIT_ARTIFACT_STORE".to_string(),
                "/srv/ceremony-store".to_string()
            ),
            ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
            ("GIT_NO_LAZY_FETCH".to_string(), "1".to_string()),
        ],
        "a non-composing step's child env is the lock token, the runner ppid, the resolved \
         store, the §3.9 GIT_OPTIONAL_LOCKS pair and the §1.6 GIT_NO_LAZY_FETCH belt: {s1:?}"
    );
}

fn inv(target: Option<&str>) -> RunInvocation {
    RunInvocation {
        profile_path: "boxes/alpha.toml".into(),
        target: target.map(str::to_string),
        ..Default::default()
    }
}

fn profile_with_ip(ip: Option<&str>) -> Profile {
    Profile {
        ip: ip.map(str::to_string),
        ..Default::default()
    }
}

/// The parameter values a step declares, as a step record carries them.
fn params_of(
    id: StepId,
    values: &orchard::ceremony::param::ParamValues,
) -> std::collections::BTreeMap<String, String> {
    let step = SPINE.iter().find(|s| s.id == id).expect("step");
    let mut params = std::collections::BTreeMap::new();
    for p in step.params {
        if let Some(v) = values.get(p.name) {
            params.insert(p.name.to_string(), v.to_string());
        }
    }
    params
}

/// Record one step as completed with the values the current invocation resolves, so the plan
/// reports it done. Mirrors what the runner writes after a step (the loop unit builds the
/// production writer).
fn record_done(
    records: &mut RunRecords,
    step_id: StepId,
    ctx: &ProbeCtx,
    values: &orchard::ceremony::param::ParamValues,
    measured: &Measured,
) {
    let step = SPINE.iter().find(|s| s.id == step_id).expect("step");
    let mut params = std::collections::BTreeMap::new();
    for p in step.params {
        if let Some(v) = values.get(p.name) {
            params.insert(p.name.to_string(), v.to_string());
        }
    }
    let mut identities = std::collections::BTreeMap::new();
    for id in step.input_identities {
        if let Some(v) = admission::identity_value(id.id, ctx, values, measured) {
            identities.insert(id.id.to_string(), v);
        }
    }
    records
        .record_step(StepRecord {
            step: step_id.token().to_string(),
            run_id: records.run_id().to_string(),
            params,
            input_identities: identities,
            produced: Default::default(),
        })
        .expect("record");
}

#[test]
fn a_pending_destructive_step_refuses_without_a_typed_target() {
                                                                                           
    let fx = fixture();
    let records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let r = admission::admit_with(&inv(None), &fx.ctx, &profile, &records, Measured::default())
        .expect_err("must refuse");
    assert_eq!(r.id.token(), "target-not-typed");
    assert!(
        r.detail.contains("s10-prod-install"),
        "names the pending destructive step: {}",
        r.detail
    );
    assert!(
        r.cure().as_str().contains("--target"),
        "cure names the flag"
    );
}

#[test]
fn a_typed_target_disagreeing_with_the_profile_ip_refuses() {
    let fx = fixture();
    let records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let r = admission::admit_with(
        &inv(Some("198.51.100.9")),
        &fx.ctx,
        &profile,
        &records,
        Measured::default(),
    )
    .expect_err("must refuse");
    assert_eq!(r.id.token(), "target-mismatch");
    assert!(r.detail.contains("198.51.100.9") && r.detail.contains("203.0.113.5"));
}

#[test]
fn the_dirt_check_excludes_the_runs_own_profile() {
                                                                                                
                                                                                                  
    use admission::check_ceremony_tree_dirt;
    let own = Some("boxes/alpha.toml");
    let only_profile = Measured {
        dirty: vec!["boxes/alpha.toml".to_string()],
        ..Default::default()
    };
    assert!(
        check_ceremony_tree_dirt(&only_profile, own).is_ok(),
        "a dirty own-profile admits"
    );
    assert!(
        check_ceremony_tree_dirt(&only_profile, None).is_err(),
        "without the exclusion the own-profile refuses"
    );
    let profile_plus_foreign = Measured {
        dirty: vec!["boxes/alpha.toml".to_string(), "scratch.txt".to_string()],
        ..Default::default()
    };
    assert!(
        check_ceremony_tree_dirt(&profile_plus_foreign, own).is_err(),
        "an unrelated foreign path still refuses with the profile excluded"
    );
}

#[test]
fn a_pending_destructive_step_refuses_when_the_profile_carries_no_ip() {
                                                                                        
    let fx = fixture();
    let records = records_at(&fx);
    let r = admission::admit_with(
        &inv(Some("203.0.113.5")),
        &fx.ctx,
        &profile_with_ip(None),
        &records,
        Measured::default(),
    )
    .expect_err("must refuse");
    assert_eq!(r.id.token(), "profile-target-missing");
}

#[test]
fn a_plan_whose_destructive_step_is_done_needs_no_typed_target() {
                                                                               
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = complete_profile();
                                                                      
    let mut i = inv(None);
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("a done destructive step needs no typed target");
    assert!(
        admitted
            .plan
            .iter()
            .any(|p| p.id == StepId::S10ProdInstall && p.is_done()),
        "the recorded step reports done"
    );
}

#[test]
fn a_not_done_judgment_consumer_refuses_when_the_flag_is_absent() {
                                                                                     
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let values = resolve_values(&inv(Some("203.0.113.5")), &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
                                                                                      
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let r = admission::admit_with(&inv(None), &fx.ctx, &profile, &records, Measured::default())
        .expect_err("must refuse");
    assert_eq!(r.id.token(), "judgment-not-resupplied");
    assert!(r.detail.contains("image_version"), "{}", r.detail);
    assert!(
        r.cure().as_str().contains("--image-version"),
        "cure names the flag: {}",
        r.cure().as_str()
    );
}

#[test]
fn the_judgment_check_reads_the_typed_flag_not_the_merged_profile_value() {
                                                                                           
                                                                           
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = Profile {
        ip: Some("203.0.113.5".into()),
        image_version: Some(7),
        ..Default::default()
    };
    let values = resolve_values(&inv(None), &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    assert_eq!(
        values.get("image_version"),
        Some("7"),
        "the merge DOES see the profile value — which is exactly what the judgment class must not accept"
    );
    let r = admission::admit_with(&inv(None), &fx.ctx, &profile, &records, Measured::default())
        .expect_err("a profile-carried judgment value is not a re-supply");
    assert_eq!(r.id.token(), "judgment-not-resupplied");
}

#[test]
fn a_typed_judgment_flag_admits() {
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = complete_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".to_string());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    assert_eq!(admitted.values.get("image_version"), Some("3"));
}

#[test]
fn dirt_outside_the_declared_paths_refuses_naming_the_paths() {
                        
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let measured = Measured {
        dirty: vec![
            "src/main.rs".to_string(),
            "consume-pins.toml".to_string(),
            "vendor/x/y.tar.xz".to_string(),
        ],
        head: None,
    };
    let r = admission::admit_with(&i, &fx.ctx, &profile, &records, measured)
        .expect_err("foreign dirt refuses");
    assert_eq!(r.id.token(), "ceremony-tree-dirty");
    assert!(r.detail.contains("src/main.rs"), "names it: {}", r.detail);
    assert!(
        !r.detail.contains("consume-pins.toml") && !r.detail.contains("vendor/"),
        "declared paths route to the commit gate, never to this refusal: {}",
        r.detail
    );
}

#[test]
fn the_declared_write_set_covers_the_repo_tree_writes_and_nothing_else() {
                                                                                             
    let declared = admission::declared_repo_paths();
    assert_eq!(
        declared,
        vec![
            "consume-pins.toml",
            "crates/image-builder/pinned-cert-fingerprints.toml",
            "vendor/",
        ],
        "the declared set is exactly the spine's executing-checkout RepoTree writes"
    );
    assert!(admission::is_declared("vendor/deep/inner.tar.xz"));
    assert!(admission::is_declared("vendor"));
    assert!(admission::is_declared("consume-pins.toml"));
    assert!(!admission::is_declared("consume-pins.toml.bak"));
    assert!(!admission::is_declared("vendored/x"));
    assert!(!admission::is_declared("src/main.rs"));
}

#[test]
fn porcelain_z_parsing_matches_the_measured_git_shapes() {
                                                                                         
                                                                                               
                                                                                              
                                  
    let raw = " M tracked.txt\0R  vendor/renamed.txt\0vendor/v.txt\0A  weird\"name.txt\0?? \
               newdir/deep.txt\0?? untracked file.txt\0";
    assert_eq!(
        parse_porcelain_z(raw),
        vec![
            "newdir/deep.txt".to_string(),
            "tracked.txt".to_string(),
            "untracked file.txt".to_string(),
            "vendor/renamed.txt".to_string(),
            "vendor/v.txt".to_string(),
            "weird\"name.txt".to_string(),
        ],
        "a rename reports BOTH paths; spaces and quotes survive verbatim"
    );
}

#[test]
fn step_done_needs_a_record_and_is_parameter_bound() {
                                                                            
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = Profile {
        ip: Some("203.0.113.5".into()),
        domain: Some("box.test".into()),
        ..Default::default()
    };
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let step = SPINE
        .iter()
        .find(|s| s.id == StepId::S7ImageBuild)
        .expect("s7");
    assert!(
        matches!(
            step_done(step, &probe_ctx, &values, &records, &Measured::default()),
            DoneResult::NotDone(_)
        ),
        "no record ⇒ not done"
    );
    record_done(
        &mut records,
        StepId::S7ImageBuild,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    assert!(matches!(
        step_done(step, &probe_ctx, &values, &records, &Measured::default()),
        DoneResult::Done
    ));
                                                                                              
    let other = Profile {
        domain: Some("other.test".into()),
        ..profile.clone()
    };
    let other_values = resolve_values(&i, &other, &fx.ctx);
    match step_done(
        step,
        &probe_ctx,
        &other_values,
        &records,
        &Measured::default(),
    ) {
        DoneResult::NotDone(why) => assert!(why.contains("domain"), "{why}"),
        other => panic!("a changed parameter must be not-done, got {other:?}"),
    }
}

#[test]
fn step_done_is_identity_bound_and_re_executes_when_the_artifact_is_gone() {
                                                                                                 
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let step = SPINE
        .iter()
        .find(|s| s.id == StepId::S7ImageBuild)
        .expect("s7");
    let at_head = Measured {
        dirty: vec![],
        head: Some("aaaaaaaa".into()),
    };
    record_done(
        &mut records,
        StepId::S7ImageBuild,
        &probe_ctx,
        &values,
        &at_head,
    );
    assert!(matches!(
        step_done(step, &probe_ctx, &values, &records, &at_head),
        DoneResult::Done
    ));
    let moved_on = Measured {
        dirty: vec![],
        head: Some("bbbbbbbb".into()),
    };
    match step_done(step, &probe_ctx, &values, &records, &moved_on) {
        DoneResult::NotDone(why) => assert!(why.contains("ceremony-head"), "{why}"),
        other => panic!("a moved HEAD must be not-done, got {other:?}"),
    }
                                                                          
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: [("ceremony-head".to_string(), "aaaaaaaa".to_string())].into(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: fx
                        .root
                        .join("gone/recipes-image-aaaaaaaa.img")
                        .display()
                        .to_string(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record");
    match step_done(step, &probe_ctx, &values, &records, &at_head) {
        DoneResult::NotDone(why) => assert!(why.contains("gone"), "{why}"),
        other => panic!("an absent produced artifact must be not-done, got {other:?}"),
    }
}

#[test]
fn an_invalid_parameter_value_refuses_with_its_probe_cure() {
    let fx = fixture();
    let mut records = records_at(&fx);
                                                                                               
    let profile = Profile {
        ip: Some("203.0.113.5".into()),
        out_dir: Some(fx.root.join("inside")),
        ..Default::default()
    };
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let r = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect_err("an invalid parameter refuses");
    assert_eq!(r.id.token(), "parameter-invalid");
    assert!(r.detail.contains("out_dir"), "{}", r.detail);
}

#[test]
fn an_admission_precondition_refuses_before_any_step_runs() {
                                                                                               
                                  
    let fx = fixture();
    std::fs::remove_dir_all(&fx.ctx.artifact_store).expect("drop the store");
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let r = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect_err("an absent store refuses");
    assert_eq!(r.id.token(), "precondition-unmet");
    assert!(r.detail.contains("artifact-store-present"), "{}", r.detail);
    assert!(
        r.cure().as_str().contains("populate it"),
        "the probe's own cure rides the refusal: {}",
        r.cure().as_str()
    );
}

/// FAC-GC-16 shape 3's derived-render pin for `PreconditionUnmet`. The arm above asserts the
                                                                                             
/// fails this. `RequiredParamMissing`, the other derived-source id, is pinned the same way by
/// `the_s6_step_time_backstop_renders_the_admission_gates_derived_param_cure`.
#[test]
fn a_derived_source_precondition_cure_renders_the_probes_own_text_and_nothing_else() {
    let fx = fixture();
    std::fs::remove_dir_all(&fx.ctx.artifact_store).expect("drop the store");
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S10ProdInstall,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let r = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect_err("an absent store refuses");
                                                                                          
    assert_eq!(r.id.token(), "precondition-unmet");
    let expected = format!(
        "artifact store {} is not a directory — populate it (tenant publish / grocer) or point \
         the context at the real store",
        fx.ctx.artifact_store.display()
    );
    let render = r.to_string();
    assert_eq!(
        composed_cure_line(&render),
        Some(expected.as_str()),
        "the composed cure must be the probe's own text alone — a static head restating the \
         trigger is the defect: {render}"
    );
}

#[test]
fn an_unevaluable_artifact_probe_counts_not_done() {
                                                                                               
                                                                                            
                                                                        
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = profile_with_ip(Some("203.0.113.5"));
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S3Prime,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let step = SPINE.iter().find(|s| s.id == StepId::S3Prime).expect("s3");
    match step_done(step, &probe_ctx, &values, &records, &Measured::default()) {
        DoneResult::NotDone(why) => assert!(why.starts_with("unevaluable: "), "{why}"),
        other => panic!("an unevaluable artifact probe must be not-done, got {other:?}"),
    }
}

                                                                                                    

use orchard::ceremony::classify::{FlagClass, VerbId, class_of_token};
use orchard::ceremony::porcelain::{ExitClass, OwedKind, OwedStop, exit_code};
use orchard::ceremony::runner::{
    ChildCall, ChildOutcome, Executor, Reporter, RunnerDeps, StepDisposition, child_invocations,
    run_ceremony, sibling_gate, step_completion, step_disposition, tenant_repo_root,
    typed_destructive_gate,
};
use orchard::ceremony::spine::{Program, Step};

/// A container tag no host has: keeps S1's artifact probe deterministically NOT-done whether or
/// not this machine runs docker.
const ABSENT_TAG: &str = "orchard-ceremony-test-absent:tag";

fn ceremony_profile() -> Profile {
    Profile {
        ip: Some("203.0.113.5".into()),
        container_image: Some(ABSENT_TAG.into()),
        tenant_repo: Some("recipes".into()),
        tenant_artifacts: Some("binary:recipes-app".into()),
        tenant_source_ref: Some("f0ad0fc".into()),
        domain: Some("box.test".into()),
        net: Some("mode=dhcp".into()),
        ..Default::default()
    }
}

/// A real file under a shared test tempdir, for the key-path params `probe_key_file` validates
/// (it requires an existing file; the content is irrelevant). The path itself carries no
/// `-----BEGIN`/newline, so it is not read as raw key material.
fn test_key_file(name: &str) -> std::path::PathBuf {
                                                                                                    
                                                                                       
                                                                                                      
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ceremony-test-keys");
    std::fs::create_dir_all(&dir).expect("mk test key dir");
    let p = dir.join(name);
    if !p.exists() {
        std::fs::write(&p, "test-key-material\n").expect("write test key");
    }
                                                                                                   
                                                                                                        
    if let Some(private) = name.strip_suffix(".pub") {
        let pk = dir.join(private);
        if !pk.exists() {
            std::fs::write(&pk, "test-key-material\n").expect("write test private key");
        }
    }
    p
}

/// `ceremony_profile` plus every remaining `Required` param a fresh (nothing-done) run needs to
                                                   
/// host-key pin. Used by the run/success arms that admit a plan with not-done late steps.
fn complete_profile() -> Profile {
    Profile {
        operator_pubkey: Some(test_key_file("operator.pub")),
        recovery_pubkey: Some(test_key_file("recovery.pub")),
        ssh_identity: Some(test_key_file("id_ed25519")),
        host_fingerprint: Some("SHA256:testfingerprint".into()),
        ..ceremony_profile()
    }
}

fn step_of(id: StepId) -> &'static Step {
    SPINE.iter().find(|s| s.id == id).expect("step in spine")
}

/// Records every call and answers from a scripted list of outcomes.
struct FakeExec {
    calls: Vec<ChildCall>,
    outcomes: Vec<ChildOutcome>,
}

impl Executor for FakeExec {
    fn run(&mut self, call: &ChildCall, _sink: &mut dyn FnMut(&str)) -> ChildOutcome {
        self.calls.push(call.clone());
        if self.outcomes.is_empty() {
            return ChildOutcome::Ok;
        }
        self.outcomes.remove(0)
    }
}

#[test]
fn a_composed_child_carries_the_resolved_context_and_never_re_resolves_from_its_cwd() {
                                                                                           
                                                              
    let fx = fixture();
    let records = records_at(&fx);
    let profile = ceremony_profile();
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let calls = child_invocations(
        step_of(StepId::S7ImageBuild),
        &values,
        &i,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    let args = &calls[0].args;
    assert_eq!(calls[0].program, Program::SelfExe);
    for (flag, want) in [
        ("--repo-root", fx.ctx.repo_root.display().to_string()),
        (
            "--artifact-store",
            fx.ctx.artifact_store.display().to_string(),
        ),
        (
            "--repo-manifest",
            fx.ctx.repo_manifest.display().to_string(),
        ),
    ] {
        let at = args
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("{flag} is composed: {args:?}"));
        assert_eq!(args[at + 1], want, "{flag} carries the RESOLVED value");
    }
}

#[test]
fn forbidden_flag_classes_appear_only_because_the_operator_typed_them() {
                                                                                                 
                                                                                                 
                                                                      
    let fx = fixture();
    let records = records_at(&fx);
    let profile = ceremony_profile();
    let forbidden = |args: &[String], verb: VerbId| -> Vec<String> {
        args.iter()
            .filter(|a| a.starts_with("--"))
            .filter(|a| {
                matches!(
                    class_of_token(verb, a),
                    Some(FlagClass::ConsentBearing)
                        | Some(FlagClass::MandatoryDestructiveToken)
                        | Some(FlagClass::GuardDisabling)
                )
            })
            .cloned()
            .collect()
    };
                                                    
    let bare = inv(Some("203.0.113.5"));
    let values = resolve_values(&bare, &profile, &fx.ctx);
    for (id, verb) in [
        (StepId::S6TenantRepin, VerbId::MarketUpgrade),
        (StepId::S2OperatorKeys, VerbId::GenerateKeys),
        (StepId::S7ImageBuild, VerbId::Build),
    ] {
        for c in child_invocations(step_of(id), &values, &bare, &fx.ctx, &records).expect("compose")
        {
            assert!(
                forbidden(&c.args, verb).is_empty(),
                "{id:?} composed a forbidden-class token untyped: {:?}",
                c.args
            );
        }
    }
                                                                            
    let mut consenting = inv(Some("203.0.113.5"));
    consenting.commit = true;
    let s6 = child_invocations(
        step_of(StepId::S6TenantRepin),
        &values,
        &consenting,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    assert_eq!(
        forbidden(&s6[0].args, VerbId::MarketUpgrade),
        vec!["--commit".to_string()],
        "the typed consent token forwards verbatim, and nothing else does"
    );
                                                                                   
    let s7 = child_invocations(
        step_of(StepId::S7ImageBuild),
        &values,
        &consenting,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    assert!(forbidden(&s7[0].args, VerbId::Build).is_empty());
}

#[test]
fn the_destructive_token_forwards_only_when_typed_and_only_to_the_destructive_verb() {
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.wipe_confirmed = true;
    let values = resolve_values(&i, &profile, &fx.ctx);
                                                                                              
                                
    let bare = child_invocations(
        step_of(StepId::S10ProdInstall),
        &values,
        &i,
        &fx.ctx,
        &records,
    )
    .expect_err("no image record");
    assert_eq!(bare.id.token(), "step-input-missing");
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/box-images/recipes-image-abc.img".into(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record");
                                                                                             
    let untyped = inv(Some("203.0.113.5"));
    let untyped_values = resolve_values(&untyped, &profile, &fx.ctx);
    let bare_calls = child_invocations(
        step_of(StepId::S10ProdInstall),
        &untyped_values,
        &untyped,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    assert!(
        !bare_calls[0].args.iter().any(|a| a == "--wipe-confirmed"),
        "an untyped invocation composes no destructive token: {:?}",
        bare_calls[0].args
    );
    let calls = child_invocations(
        step_of(StepId::S10ProdInstall),
        &values,
        &i,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    let args = &calls[0].args;
    assert_eq!(
        args.iter().filter(|a| *a == "--wipe-confirmed").count(),
        1,
        "the typed token forwards exactly once: {args:?}"
    );
    let at = args.iter().position(|a| a == "--image").expect("--image");
    assert_eq!(
        args[at + 1],
        "/tmp/box-images/recipes-image-abc.img",
        "the image path comes from S7's record, never re-derived"
    );
}

#[test]
fn compose_s10_forwards_the_runtime_hostkey_fingerprint_only_when_present() {
                                                                                                    
                                                                                                   
                                                                                                    
                                                                                    
    let fx = fixture();
    let mut records = records_at(&fx);
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/box-images/recipes-image-abc.img".into(),
                    sha256: "d0d0".into(),
                },
            )]
            .into(),
        })
        .expect("record S7");
    let i = inv(Some("203.0.113.5"));
    let s10_args = |profile: &Profile| {
        let values = resolve_values(&i, profile, &fx.ctx);
        child_invocations(
            step_of(StepId::S10ProdInstall),
            &values,
            &i,
            &fx.ctx,
            &records,
        )
        .expect("compose")[0]
            .args
            .clone()
    };
    let with_fp = Profile {
        runtime_hostkey_fingerprint: Some("SHA256:runtimepin".into()),
        ..complete_profile()
    };
    let args = s10_args(&with_fp);
    let at = args
        .iter()
        .position(|a| a == "--runtime-hostkey-fingerprint")
        .expect("compose_s10 forwards --runtime-hostkey-fingerprint when the profile carries it");
    assert_eq!(args[at + 1], "SHA256:runtimepin");
    assert!(
        !s10_args(&complete_profile())
            .iter()
            .any(|a| a == "--runtime-hostkey-fingerprint"),
        "an absent runtime_hostkey_fingerprint composes no flag"
    );
}

#[test]
fn a_destructive_step_without_the_typed_flag_is_an_owed_typed_gate_stop() {
                                                                                
    let fx = fixture();
    let records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let s10 = step_of(StepId::S10ProdInstall);
    let owed =
        typed_destructive_gate(s10, &i, &fx.ctx).expect("the untyped destructive gate stops");
    assert_eq!(owed.kind, OwedKind::TypedGateStop);
    assert_eq!(owed.refusal.id.token(), "destructive-token-not-typed");
    let cure = owed.refusal.cure();
    assert!(
        cure.as_str().contains("--wipe-confirmed")
            && cure.as_str().contains("--target 203.0.113.5")
            && cure.as_str().contains("--image-version 3"),
        "the resume command re-types what THIS invocation carried: {}",
        cure.as_str()
    );
                                              
    i.wipe_confirmed = true;
    assert!(typed_destructive_gate(s10, &i, &fx.ctx).is_none());
                                                                                       
                                                                                                
                                                                                              
    i.wipe_confirmed = false;
    match step_disposition(
        s10,
        &probe_ctx,
        &values,
        &records,
        &Measured::default(),
        &i,
        &fx.ctx,
    ) {
        StepDisposition::Refuse(r) => {
            assert_eq!(r.id.token(), "precondition-unmet");
            assert!(r.detail.contains("gate-record-present"), "{}", r.detail);
        }
        other => panic!("expected the gate-record precondition to stop S10 today, got {other:?}"),
    }
                                                                       
    for id in [StepId::S1BuildContainer, StepId::S7ImageBuild] {
        assert!(typed_destructive_gate(step_of(id), &i, &fx.ctx).is_none());
    }
}

#[test]
fn an_external_checklist_step_with_an_unmet_probe_is_owed_not_failed() {
                                                                                                 
                                                                                        
                                                                 
    let fx = fixture();
    let records = records_at(&fx);
    let profile = ceremony_profile();
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    match step_disposition(
        step_of(StepId::S9BoxPreflight),
        &probe_ctx,
        &values,
        &records,
        &Measured::default(),
        &i,
        &fx.ctx,
    ) {
        StepDisposition::Owed(owed) => {
            assert_eq!(owed.kind, OwedKind::ExternalChecklistStop);
            assert!(
                owed.refusal.cure().as_str().contains("orchard run"),
                "the instruction block carries a resume command: {}",
                owed.refusal.cure().as_str()
            );
        }
        other => panic!("expected an owed external-checklist stop, got {other:?}"),
    }
                                                                                             
                                                               
    match step_disposition(
        step_of(StepId::S7ImageBuild),
        &probe_ctx,
        &values,
        &records,
        &Measured::default(),
        &i,
        &fx.ctx,
    ) {
        StepDisposition::Refuse(r) => assert_eq!(r.id.token(), "precondition-unmet"),
        other => panic!("expected a plain refusal on an internal step, got {other:?}"),
    }
}

#[test]
fn the_loop_skips_recorded_steps_and_stops_at_the_first_failure() {
                                                                                                 
                                                                                                
                                                                   
                                                                                                 
                                                                                         
                                                                                             
    let fx = repo_fixture();
    let mut records = records_at(&fx);
    let profile = complete_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    record_done(
        &mut records,
        StepId::S2OperatorKeys,
        &probe_ctx,
        &values,
        &Measured::default(),
    );
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![
            ChildOutcome::Ok,
            ChildOutcome::Ok,
            ChildOutcome::Failed("vendor: store miss".into()),
        ],
    };
    let reporter = Reporter { porcelain: true };
    let prompt = || 'n';
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: Some("token-abc"),
        is_tty: false,
        prompt: &prompt,
        editor: None,
    };
    let err = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
        .expect_err("the third step fails");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("a typed refusal");
    assert_eq!(refusal.id.token(), "step-failed");
    assert!(
        refusal.detail.contains("s4-store-vendor"),
        "{}",
        refusal.detail
    );
    assert_eq!(
        exec.calls.iter().map(|c| c.step).collect::<Vec<_>>(),
        vec![
            StepId::S1BuildContainer,
            StepId::S3Prime,
            StepId::S4StoreVendor
        ],
        "S2 was recorded, so it SKIPs; the loop stops at the first failure"
    );
    assert_eq!(
        exec.calls[0].env,
        vec![
            ("ORCHARD_LOCK_TOKEN".to_string(), "token-abc".to_string()),
            (
                "ORCHARD_CEREMONY_PPID".to_string(),
                std::process::id().to_string()
            ),
            (
                "FRUIT_ARTIFACT_STORE".to_string(),
                fx.ctx.artifact_store.display().to_string()
            ),
            ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
            ("GIT_NO_LAZY_FETCH".to_string(), "1".to_string()),
        ],
        "children inherit the host-lock token, the runner ppid, the resolved artifact \
         store, the §3.9 GIT_OPTIONAL_LOCKS pair and the §1.6 GIT_NO_LAZY_FETCH belt, so a \
         runner-driven verb JOINS instead of refusing and never re-resolves its store"
    );
    assert!(
        records.step_record(StepId::S4StoreVendor.token()).is_none(),
        "a failed step records nothing"
    );
    assert!(
        records.step_record(StepId::S3Prime.token()).is_some(),
        "a completed step records its provenance"
    );
}

#[test]
fn the_executing_gate_fails_closed_when_git_state_is_unreadable() {
                                                                                                  
                                                                                                    
                                                                                                      
                                                                
    let fx = fixture();                                               
    let mut records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
                                                                                     
                                                                                               
    for id in [
        StepId::S1BuildContainer,
        StepId::S2OperatorKeys,
        StepId::S3Prime,
        StepId::S4StoreVendor,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted (admission reads the supplied Measured, not live git)");
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let reporter = Reporter { porcelain: true };
    let prompt = || 'n';
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: Some("token-abc"),
        is_tty: false,
        prompt: &prompt,
        editor: None,
    };
    let err = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
        .expect_err("an unreadable checkout must refuse, not pass as clean");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("a typed refusal");
    assert_eq!(
        refusal.id.token(),
        "git-state-unreadable",
        "the commit gate fails CLOSED on an unevaluable checkout: {}",
        refusal.detail
    );
                                                                                                 
                                                                             
    assert_eq!(
        refusal.cure().as_str(),
        "git refused the read for the commit gate; the detail carries git's line; repair \
         what it names, then re-run"
    );
}

#[test]
fn an_owed_stop_concludes_as_operator_action_owed_not_as_a_bare_refusal() {
                                                                                               
                                             
    use orchard::ceremony::porcelain::class_of_outcome;
    for (kind, code) in [
        (OwedKind::TypedGateStop, 6),
        (OwedKind::ExternalChecklistStop, 5),
        (OwedKind::ConsentGateStop, 3),
        (OwedKind::SiblingRefuseBeforeOverwrite, 4),
    ] {
        let stop = OwedStop::new(
            kind,
            orchard::ceremony::refusal::Refusal::new(
                orchard::ceremony::refusal::RefusalId::DestructiveTokenNotTyped,
                "fixture",
            ),
        );
        let outcome: Result<(), Box<dyn std::error::Error>> = Err(Box::new(stop));
        let class = class_of_outcome(&outcome);
        assert_eq!(class, ExitClass::OperatorActionOwed(kind));
        assert_eq!(exit_code(&class), code);
    }
                                                                                                 
                                        
    let refused: Result<(), Box<dyn std::error::Error>> =
        Err(Box::new(orchard::ceremony::refusal::Refusal::new(
            orchard::ceremony::refusal::RefusalId::StepFailed,
            "fixture",
        )));
    assert_eq!(class_of_outcome(&refused), ExitClass::RefusalWithCure);
    let plain: Result<(), Box<dyn std::error::Error>> = Err("no such file".into());
    assert_eq!(class_of_outcome(&plain), ExitClass::Failure);
    let ok: Result<(), Box<dyn std::error::Error>> = Ok(());
    assert_eq!(class_of_outcome(&ok), ExitClass::Success);
}

#[test]
fn the_resume_command_names_only_what_the_invocation_carried() {
                                                                                                   
                           
    let fx = fixture();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "9".into());
    assert_eq!(
        i.with_wipe_confirmed().resume_command(&fx.ctx),
        format!(
            "orchard run boxes/alpha.toml --target 203.0.113.5 --image-version 9 --wipe-confirmed {}",
            fx.ctx.forward_flags().join(" ")
        )
    );
    let bare = inv(None);
    assert_eq!(
        bare.resume_command(&fx.ctx),
        format!(
            "orchard run boxes/alpha.toml {}",
            fx.ctx.forward_flags().join(" ")
        )
    );
}

                                                                              

use orchard::ceremony::handoff::{TENANT_HANDOFF_BINARIES, quiescent_with, shape};
use orchard::ceremony::preflight::{
    CLOUD_USER, ROOT_RESTRICTION_BANNER, ROOT_RESTRICTION_EXIT, SshAttempt, classify,
};
use orchard::ceremony::probes::ProbeResult;

fn attempt(code: Option<i32>, stdout: &str, stderr: &str) -> SshAttempt {
    SshAttempt {
        code,
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

#[test]
fn the_preflight_fixed_fixture_passes_and_the_142_fixture_stops_with_the_debian_cure() {
                                                                    
                                                                          
                                                                                                  
    let fixed = attempt(Some(0), "root\n", "");
    assert_eq!(
        classify(CLOUD_USER, "203.0.113.5", &fixed, None),
        ProbeResult::Met
    );

    let refused_cloud = attempt(Some(255), "", "Permission denied (publickey).");
    let restricted_root = attempt(
        Some(ROOT_RESTRICTION_EXIT),
        "Please login as the user \"debian\" rather than the user \"root\".\n",
        "",
    );
    match classify(
        CLOUD_USER,
        "203.0.113.5",
        &refused_cloud,
        Some(&restricted_root),
    ) {
        ProbeResult::Unmet(cure) => {
            assert!(
                cure.contains("login restriction"),
                "the 142 fixture reaches the restriction branch, not the generic one: {cure}"
            );
            assert!(
                cure.contains(CLOUD_USER) && cure.contains("sudo"),
                "the cure names the transport this ceremony uses: {cure}"
            );
            assert!(
                cure.contains("ssh_identity"),
                "the cure names what the operator supplies: {cure}"
            );
        }
        other => panic!("the 142 fixture must stop with a cure, got {other:?}"),
    }
                                                                                              
                                                                                              
                                                                                  
    let banner_only = attempt(Some(1), "", ROOT_RESTRICTION_BANNER);
    match classify(
        CLOUD_USER,
        "203.0.113.5",
        &refused_cloud,
        Some(&banner_only),
    ) {
        ProbeResult::Unmet(c) => assert!(
            c.contains("login restriction") && c.contains(&ROOT_RESTRICTION_EXIT.to_string()),
            "the banner alone must reach the restriction branch: {c}"
        ),
        other => panic!("expected an unmet preflight, got {other:?}"),
    }
                                                                                        
    let plain_root = attempt(
        Some(255),
        "",
        "ssh: connect to host 203.0.113.5 port 22: timeout",
    );
    match classify(CLOUD_USER, "203.0.113.5", &refused_cloud, Some(&plain_root)) {
        ProbeResult::Unmet(cure) => {
            assert!(cure.contains("Permission denied"), "{cure}");
            assert!(
                !cure.contains(ROOT_RESTRICTION_BANNER),
                "no root-restriction claim without the signature: {cure}"
            );
        }
        other => panic!("expected an unmet preflight, got {other:?}"),
    }
}

#[test]
fn a_cloud_leg_that_exits_zero_without_root_is_not_met() {
                                                                                         
                                                                                                  
    for out in ["", "debian\n", "root-ish\n"] {
        assert!(
            matches!(
                classify(CLOUD_USER, "203.0.113.5", &attempt(Some(0), out, ""), None),
                ProbeResult::Unmet(_)
            ),
            "stdout {out:?} must not count as escalated"
        );
    }
    assert_eq!(
        classify(
            CLOUD_USER,
            "203.0.113.5",
            &attempt(Some(0), " root \n", ""),
            None
        ),
        ProbeResult::Met,
        "surrounding whitespace is not a difference"
    );
}

#[test]
fn the_handoff_shape_refuses_every_mid_write_state() {
                                                                                          
                                                                                             
                                                           
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("handoff");
    assert!(matches!(shape(&root), ProbeResult::Unmet(w) if w.contains("does not exist")));
    std::fs::create_dir_all(root.join("release")).expect("mk");
    assert!(matches!(shape(&root), ProbeResult::Unmet(w) if w.contains("missing")));
                                                               
    std::fs::write(
        root.join("release").join(TENANT_HANDOFF_BINARIES[0]),
        b"elf",
    )
    .expect("w");
    assert!(
        matches!(shape(&root), ProbeResult::Unmet(w) if w.contains(TENANT_HANDOFF_BINARIES[1]))
    );
                                                                               
    std::fs::write(root.join("release").join(TENANT_HANDOFF_BINARIES[1]), b"").expect("w");
    assert!(matches!(shape(&root), ProbeResult::Unmet(w) if w.contains("empty")));
    std::fs::write(
        root.join("release").join(TENANT_HANDOFF_BINARIES[1]),
        b"elf2",
    )
    .expect("w");
    assert_eq!(shape(&root), ProbeResult::Met);
}

#[test]
fn a_mutating_handoff_tree_is_not_quiescent_and_a_stable_one_is() {
                                                                                            
                                                                                     
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("handoff");
    std::fs::create_dir_all(root.join("release")).expect("mk");
    for b in TENANT_HANDOFF_BINARIES {
        std::fs::write(root.join("release").join(b), b"elf").expect("w");
    }
    let stable = quiescent_with(&root, 3, std::time::Duration::ZERO).expect("stable");
    assert_eq!(
        stable,
        quiescent_with(&root, 2, std::time::Duration::ZERO).expect("same tree, same hash")
    );
                                                                                           
    let mutating = root.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            mutating.join("release").join(TENANT_HANDOFF_BINARIES[1]),
            b"elf-rewritten-mid-probe",
        )
        .expect("mid-probe write");
    });
    let verdict = quiescent_with(&root, 3, std::time::Duration::from_millis(60));
    handle.join().expect("writer");
    match verdict {
        Err(ProbeResult::Unmet(why)) => assert!(why.contains("changed between reads"), "{why}"),
        other => panic!("a tree written mid-probe is not quiescent, got {other:?}"),
    }
}

#[test]
fn the_handoff_probe_reads_the_shape_before_asking_about_stability() {
                                                                                               
                                                                        
    let tmp = tempfile::tempdir().expect("tempdir");
    let started = std::time::Instant::now();
    let verdict = quiescent_with(
        &tmp.path().join("nothing-here"),
        3,
        std::time::Duration::from_secs(30),
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the shape check returns before any re-read interval elapses"
    );
    assert!(matches!(verdict, Err(ProbeResult::Unmet(w)) if w.contains("does not exist")));
}

                                                                                                    

use orchard::ceremony::consent::{
    GateDecision, SiblingDecision, StopSlot, commit_message, decide_executing_gate, decide_sibling,
};

fn owed(
    pairs: &[(&str, DirtClass)],
) -> Vec<(orchard::ceremony::records::DeclaredPathName, DirtClass)> {
    pairs
        .iter()
        .map(|(p, c)| (orchard::ceremony::records::DeclaredPathName::new(*p), *c))
        .collect()
}

#[test]
fn headless_without_the_token_stops_at_the_gate_with_head_unchanged() {
                                                                                                 
                         
    let d = owed(&[("consume-pins.toml", DirtClass::CleanOrRecorded)]);
    match decide_executing_gate(
        &d,
        false,
        false,
        || panic!("no prompt headless"),
        "RESUME",
        "RESUME --commit",
    ) {
        GateDecision::Stop(stop) => {
            assert_eq!(stop.kind, OwedKind::ConsentGateStop);
            assert_eq!(stop.refusal.id.token(), "consent-gate-owed");
            assert!(
                stop.refusal.cure().as_str().contains("RESUME"),
                "the ready command rides the cure: {}",
                stop.refusal.cure().as_str()
            );
        }
        other => panic!("expected a consent-gate stop, got {other:?}"),
    }
}

/// The commit message's four class headings, frozen here as literals so a re-wording is a
/// conscious re-freeze on both sides (consent::class_heading owns the production copy).
const H_THIS_RUN: &str = "Declared paths written by this ceremony run:";
const H_PRIOR_RUN: &str = "Declared paths finalized by a prior ceremony run (recorded content):";
const H_INTERRUPTED: &str =
    "Declared paths whose latest path record is open without finalize (interrupted write):";
const H_AMBIGUOUS: &str = "Declared paths holding content no ceremony record speaks for:";

/// Split a commit message into its per-class sections: one of the four frozen headings opens a
/// section, the two-space-indented lines under it are its members, anything else closes it. A
/// heading present with no members reads as an empty section, so an emitted-but-empty heading is
/// distinguishable from an absent one.
fn message_sections(msg: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let headings: Vec<&'static str> = DirtClass::ALL
        .iter()
        .map(|c| orchard::ceremony::consent::class_heading(*c))
        .collect();
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut current: Option<String> = None;
    for line in msg.lines() {
        if let Some(h) = headings.iter().find(|h| **h == line) {
            current = Some((*h).to_string());
            out.entry((*h).to_string()).or_default();
            continue;
        }
        match (line.strip_prefix("  "), &current) {
            (Some(rest), Some(c)) => out
                .get_mut(c.as_str())
                .expect("the open section exists")
                .push(rest.trim_matches('"').to_string()),
            _ => current = None,
        }
    }
    out
}

#[test]
fn the_message_section_reader_finds_only_headed_indented_lines() {
                                                                                                 
    let read = message_sections(&format!(
        "subject\n\n{H_PRIOR_RUN}\n  a\n  b\nloose\n  not-a-member\n"
    ));
    assert_eq!(
        read.keys().cloned().collect::<Vec<_>>(),
        vec![H_PRIOR_RUN.to_string()],
        "only a frozen heading opens a section"
    );
    assert_eq!(read[H_PRIOR_RUN], vec!["a".to_string(), "b".to_string()]);
    assert!(
        message_sections("subject\n\n  a\n").is_empty(),
        "an indented line under no heading is attributed to nothing"
    );
}

#[test]
fn headless_with_the_token_commits_exactly_the_recorded_declared_paths() {
                                                                                               
             
    let d = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::CleanOrRecorded),
    ]);
    match decide_executing_gate(
        &d,
        false,
        true,
        || panic!("no prompt headless"),
        "RESUME",
        "RESUME --commit",
    ) {
        GateDecision::Commit { paths, .. } => {
            let just_paths: Vec<&str> = paths.iter().map(|(p, _)| p.as_str()).collect();
            assert_eq!(just_paths, vec!["consume-pins.toml", "vendor/x.tar.xz"]);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
                                                                                             
                                                                               
    let mixed = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::PriorRunRecorded),
    ]);
    match decide_executing_gate(
        &mixed,
        false,
        true,
        || panic!("no prompt headless"),
        "RESUME",
        "RESUME --commit",
    ) {
        GateDecision::Commit { paths, .. } => {
            let shown: Vec<(&str, DirtClass)> =
                paths.iter().map(|(p, c)| (p.as_str(), *c)).collect();
            assert_eq!(
                shown,
                vec![
                    ("consume-pins.toml", DirtClass::CleanOrRecorded),
                    ("vendor/x.tar.xz", DirtClass::PriorRunRecorded),
                ],
                "both paths commit, each carrying the classifier's verdict"
            );
        }
        other => panic!("a prior run's recorded content commits under the token, got {other:?}"),
    }
}

#[test]
fn a_headless_stop_names_only_the_paths_its_sentence_describes() {
                                                                                           
                                                                                                 
                                                             
    let mixed = owed(&[
        ("consume-pins.toml", DirtClass::PriorRunRecorded),
        ("vendor/x.tar.xz", DirtClass::Interrupted),
    ]);
                                                                                                 
                                                   
    assert!(
        matches!(
            decide_executing_gate(
                &owed(&[("consume-pins.toml", DirtClass::PriorRunRecorded)]),
                false,
                true,
                || panic!("no prompt headless"),
                "RESUME",
                "RESUME --commit"
            ),
            GateDecision::Commit { .. }
        ),
        "the prior-run path alone commits headlessly under the token"
    );
    match decide_executing_gate(
        &mixed,
        false,
        true,
        || panic!("no prompt headless"),
        "RESUME",
        "RESUME --commit",
    ) {
        GateDecision::Stop(stop) => {
            assert_eq!(stop.kind, OwedKind::ConsentGateStop);
            assert_eq!(stop.refusal.id.token(), "consent-gate-owed");
            assert!(
                stop.refusal.detail.contains("vendor/x.tar.xz"),
                "the interrupted path is what nothing can speak for: {}",
                stop.refusal.detail
            );
            assert!(
                !stop.refusal.detail.contains("consume-pins.toml"),
                "the prior-run path is recorded content and is not in the sentence's subject: {}",
                stop.refusal.detail
            );
        }
        other => panic!("an interrupted member stops the headless run, got {other:?}"),
    }
}

#[test]
fn a_prior_run_path_without_the_token_stops_on_the_no_authorization_branch() {
                                                                                             
                                                                                                   
                                                                                                 
                            
    let d = owed(&[("consume-pins.toml", DirtClass::PriorRunRecorded)]);
    match decide_executing_gate(
        &d,
        false,
        false,
        || panic!("no prompt headless"),
        "RESUME",
        "RESUME --commit",
    ) {
        GateDecision::Stop(stop) => {
            assert_eq!(stop.kind, OwedKind::ConsentGateStop);
            assert_eq!(stop.refusal.id.token(), "consent-gate-owed");
            assert!(
                stop.refusal.detail.contains("consume-pins.toml")
                    && stop.refusal.detail.contains("no commit authorization"),
                "the no-authorization branch names the path and the reason: {}",
                stop.refusal.detail
            );
            assert!(
                !stop.refusal.detail.contains("interrupted mid-write"),
                "a prior run's finalized write is not an interrupted one: {}",
                stop.refusal.detail
            );
            let cure = stop.refusal.cure();
            assert!(
                cure.as_str().contains("RESUME") && cure.as_str().contains("--commit"),
                "the cure carries the resume command and the token route: {}",
                cure.as_str()
            );
        }
        other => panic!("expected the no-authorization stop, got {other:?}"),
    }
}

#[test]
fn an_all_prior_run_set_is_prompted_once_and_the_answer_decides() {
                                                                                            
                                                                                              
                                                                                                  
                                           
    let d = owed(&[("consume-pins.toml", DirtClass::PriorRunRecorded)]);
    let asked = std::cell::Cell::new(0usize);
    let yes = decide_executing_gate(
        &d,
        true,
        false,
        || {
            asked.set(asked.get() + 1);
            Ok('y')
        },
        "R",
        "R --commit",
    );
    assert_eq!(
        asked.get(),
        1,
        "the operator is asked exactly once about the set the gate will commit"
    );
    match yes {
        GateDecision::Commit { paths, .. } => {
            let shown: Vec<(&str, DirtClass)> =
                paths.iter().map(|(p, c)| (p.as_str(), *c)).collect();
            assert_eq!(
                shown,
                vec![("consume-pins.toml", DirtClass::PriorRunRecorded)]
            );
        }
        other => panic!("`y` over an all-prior set commits it, got {other:?}"),
    }
    assert!(
        matches!(
            decide_executing_gate(&d, true, false, || Ok('n'), "R", "R --commit"),
            GateDecision::Stop(_)
        ),
        "`n` stops with HEAD unchanged"
    );
}

#[test]
fn ambiguity_beats_the_token_and_stops_every_regime() {
                                                                                                 
                                                                                                       
                                                                                      
                                                                                           
    for (class, route) in [
        (DirtClass::Ambiguous, AMBIGUOUS_ROUTE),
        (DirtClass::Interrupted, RESTORE_ROUTE),
    ] {
        let d = owed(&[
            ("consume-pins.toml", DirtClass::CleanOrRecorded),
            ("vendor/x.tar.xz", class),
        ]);
        for (is_tty, commit_token) in [(false, false), (false, true), (true, false), (true, true)] {
            match decide_executing_gate(
                &d,
                is_tty,
                commit_token,
                || panic!("no prompt over unspeakable content (is_tty={is_tty})"),
                "RESUME",
                "RESUME --commit",
            ) {
                GateDecision::Stop(stop) => {
                    assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                    assert!(
                        stop.refusal.detail.contains("vendor/x.tar.xz"),
                        "names the path nothing can speak for: {}",
                        stop.refusal.detail
                    );
                    assert!(
                        stop.refusal.cure().as_str().contains(route),
                        "the cure is the external per-class route ({route:?}): {}",
                        stop.refusal.cure().as_str()
                    );
                }
                other => panic!(
                    "{class:?} must stop (is_tty={is_tty}, token={commit_token}), got {other:?}"
                ),
            }
        }
    }
}

                                                                                                  
/// no longer opens a prompt. The forwarded token is effective only over an all-speakable set (which
/// commits with the prompt untouched); an unspeakable member stops the set pre-prompt with the
                                                                                                     
           
#[test]
fn the_token_at_a_terminal_does_not_take_unspeakable_content() {
                                                                                                  
                                                                                                 
                                      
    let speakable = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::PriorRunRecorded),
    ]);
    for is_tty in [true, false] {
        let asked = std::cell::Cell::new(0usize);
        match decide_executing_gate(
            &speakable,
            is_tty,
            true,
            || {
                asked.set(asked.get() + 1);
                Ok('n')
            },
            "RESUME",
            "RESUME --commit",
        ) {
            GateDecision::Commit { paths, .. } => {
                assert_eq!(paths.len(), 2, "the whole recorded set commits");
            }
            other => panic!("an all-speakable set commits under the token, got {other:?}"),
        }
        assert_eq!(
            asked.get(),
            0,
            "the token decides an all-speakable set without a prompt (is_tty={is_tty})"
        );
    }

    for (class, route) in [
        (DirtClass::Ambiguous, AMBIGUOUS_ROUTE),
        (DirtClass::Interrupted, RESTORE_ROUTE),
    ] {
        let d = owed(&[
            ("consume-pins.toml", DirtClass::CleanOrRecorded),
            ("vendor/x.tar.xz", class),
        ]);
        let asked = std::cell::Cell::new(0usize);
        let decision = decide_executing_gate(
            &d,
            true,
            true,
            || {
                asked.set(asked.get() + 1);
                Ok('y')
            },
            "RESUME",
            "RESUME --commit",
        );
        assert_eq!(
            asked.get(),
            0,
            "the token at a terminal over unspeakable content stops pre-prompt for {class:?}"
        );
        match decision {
            GateDecision::Stop(stop) => {
                assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                assert!(
                    stop.refusal.cure().as_str().contains(route),
                    "the token does not authorize unrecorded content; the cure is external \
                     ({route:?}): {}",
                    stop.refusal.cure().as_str()
                );
            }
            other => {
                panic!("the token cannot commit unspeakable content for {class:?}, got {other:?}")
            }
        }
    }
}

                                                                                                    
/// token, `n`) keeps the no-authorization detail and the `--commit` cure route; an unspeakable set at
/// a terminal now stops with the EXTERNAL cure (settle or commit it yourself) and never reaches a
/// prompt or a print-only slot. Behavior read from the rendered `Refusal`, not a frozen literal.
#[test]
fn the_printonly_stop_text_tracks_the_state_across_all_three_slots() {
    fn stop_text(
        d: &[(DeclaredPathName, DirtClass)],
        commit_token: bool,
        prompt: char,
    ) -> (String, String) {
        match decide_executing_gate(
            d,
            true,
            commit_token,
            || Ok(prompt),
            "RESUME",
            "RESUME --commit",
        ) {
            GateDecision::Stop(stop) => {
                assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                (
                    stop.refusal.detail.clone(),
                    stop.refusal.cure().as_str().to_string(),
                )
            }
            other => panic!("this state must stop, got {other:?}"),
        }
    }

    let unspeakable = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::Ambiguous),
    ]);
    let speakable = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::PriorRunRecorded),
    ]);

                                                                                                   
                                                                                                    
                           
    let (detail_u, cure_u) = stop_text(&unspeakable, false, 'n');
    assert!(
        detail_u.contains("cannot speak for"),
        "the unspeakable stop names the unrecorded content: {detail_u}"
    );
    assert!(
        cure_u.contains("settle or commit the named path(s) yourself"),
        "the unspeakable cure is the external route: {cure_u}"
    );
    assert!(
        !cure_u.contains("--commit"),
        "the unspeakable cure must not offer a --commit route: {cure_u}"
    );

                                                                                                 
    let (detail_a, cure_a) = stop_text(&speakable, false, 'n');
    assert!(
        detail_a.contains("carries no commit authorization"),
        "slot A keeps the no-authorization detail: {detail_a}"
    );
    assert!(
        cure_a.contains("re-run with --commit: RESUME --commit"),
        "slot A cure names the --commit route and prints the resume command carrying --commit: {cure_a}"
    );
}

/// The owed set as the gate's own pair type, for comparing against a decision's `paths`.
fn as_pairs(d: &[(DeclaredPathName, DirtClass)]) -> Vec<(DeclaredPathName, DirtClass)> {
    d.to_vec()
}

/// The regime `decide_executing_gate` reaches for one input tuple, as observables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Regime {
    /// No prompt; the whole owed set commits.
    TokenRecorded,
    /// No prompt; the "records cannot speak for" stop. Every `(false, *, *)` tuple reaches it — no
    /// token or terminal opens a prompt over unspeakable content (R14 regime collapse).
    UnspeakableStop,
    /// No prompt; the print-only stop.
    HeadlessUnauthorized,
    /// The prompt decides, and `e` carries this slot into the edit-abort branch.
    Interactive(StopSlot),
}

/// The regime derivation driven over ALL EIGHT `(unspeakable_empty, is_tty, commit_token)` tuples
/// through the real entry point. Per tuple: how many times the prompt closure runs, which decision
/// the gate reaches, and — on the three interactive tuples — which `StopSlot` the `e` answer
/// carries. The slot is read from the typed `declined` field, so its identity is checked without
/// reading any text.
///
/// What it claims: those observables per tuple. After the R14 regime collapse the four
/// `(false, *, *)` tuples all reach the unspeakable stop and only one tuple is interactive, so a
/// single non-commit slot (`NoTokenRecorded`) exists; the multi-slot distinctness claim is retired
/// with the two deleted slots.
#[test]
fn the_gate_regime_is_total_over_the_eight_input_tuples() {
    let speakable = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::PriorRunRecorded),
    ]);
    let unspeakable = owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::Ambiguous),
    ]);
                                                                                            
                                                                     
    assert!(
        speakable.iter().all(|(_, c)| c.speakable()),
        "the speakable fixture holds no unspeakable member"
    );
    assert!(
        unspeakable.iter().any(|(_, c)| !c.speakable()),
        "the unspeakable fixture holds an unspeakable member"
    );

    use StopSlot::NoTokenRecorded;
    const MATRIX: [(bool, bool, bool, Regime); 8] = [
        (false, false, false, Regime::UnspeakableStop),
        (false, false, true, Regime::UnspeakableStop),
        (false, true, false, Regime::UnspeakableStop),
        (false, true, true, Regime::UnspeakableStop),
        (true, false, false, Regime::HeadlessUnauthorized),
        (true, false, true, Regime::TokenRecorded),
        (true, true, false, Regime::Interactive(NoTokenRecorded)),
        (true, true, true, Regime::TokenRecorded),
    ];
    let mut slot_texts: std::collections::BTreeMap<String, (String, String)> = Default::default();

    for (unspeakable_empty, is_tty, commit_token, expect) in MATRIX {
        let d = if unspeakable_empty {
            &speakable
        } else {
            &unspeakable
        };
        let want = as_pairs(d);
        let tuple = format!(
            "(unspeakable_empty={unspeakable_empty}, is_tty={is_tty}, commit_token={commit_token})"
        );
        let asked = std::cell::Cell::new(0usize);
        let yes = decide_executing_gate(
            d,
            is_tty,
            commit_token,
            || {
                asked.set(asked.get() + 1);
                Ok('y')
            },
            "RESUME",
            "RESUME --commit",
        );
        match expect {
            Regime::TokenRecorded => {
                assert_eq!(asked.get(), 0, "{tuple} decides without a prompt");
                assert_eq!(
                    committed_pairs(&yes),
                    Some(&want[..]),
                    "{tuple} commits the whole owed set: {yes:?}"
                );
            }
            Regime::UnspeakableStop => {
                assert_eq!(asked.get(), 0, "{tuple} decides without a prompt");
                match &yes {
                    GateDecision::Stop(stop) => {
                        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                        assert!(
                            stop.refusal.detail.contains("cannot speak for"),
                            "{tuple} takes the unspeakable stop: {}",
                            stop.refusal.detail
                        );
                    }
                    other => panic!("{tuple} stops with the record view owed, got {other:?}"),
                }
            }
            Regime::HeadlessUnauthorized => {
                assert_eq!(asked.get(), 0, "{tuple} decides without a prompt");
                match &yes {
                    GateDecision::Stop(stop) => {
                        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                        assert!(
                            !stop.refusal.detail.contains("cannot speak for"),
                            "{tuple} is the print-only stop, not the unspeakable one: {}",
                            stop.refusal.detail
                        );
                    }
                    other => panic!("{tuple} stops print-only, got {other:?}"),
                }
            }
            Regime::Interactive(slot) => {
                assert_eq!(asked.get(), 1, "{tuple} asks exactly once");
                assert_eq!(
                    committed_pairs(&yes),
                    Some(&want[..]),
                    "{tuple}: `y` commits the whole set the prompt was opened over: {yes:?}"
                );
                let asked_e = std::cell::Cell::new(0usize);
                let edit = decide_executing_gate(
                    d,
                    is_tty,
                    commit_token,
                    || {
                        asked_e.set(asked_e.get() + 1);
                        Ok('e')
                    },
                    "RESUME",
                    "RESUME --commit",
                );
                assert_eq!(asked_e.get(), 1, "{tuple}: `e` asks exactly once");
                match edit {
                    GateDecision::EditThenCommit { paths, declined } => {
                        assert_eq!(paths, want, "{tuple}: `e` carries the whole owed set");
                        assert_eq!(
                            declined, slot,
                            "{tuple}: the edit-abort branch carries THIS tuple's slot"
                        );
                    }
                    other => panic!("{tuple}: `e` takes the edit branch, got {other:?}"),
                }
                let asked_q = std::cell::Cell::new(0usize);
                let stopped = decide_executing_gate(
                    d,
                    is_tty,
                    commit_token,
                    || {
                        asked_q.set(asked_q.get() + 1);
                        Ok('q')
                    },
                    "RESUME",
                    "RESUME --commit",
                );
                assert_eq!(
                    asked_q.get(),
                    1,
                    "{tuple}: any other char asks exactly once"
                );
                match stopped {
                    GateDecision::Stop(stop) => {
                        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                        slot_texts.insert(
                            format!("{slot:?}"),
                            (
                                stop.refusal.detail.clone(),
                                stop.refusal.cure().as_str().to_string(),
                            ),
                        );
                    }
                    other => panic!("{tuple}: a non-y/e char stops, got {other:?}"),
                }
            }
        }
    }

    assert_eq!(
        slot_texts.len(),
        1,
        "the one interactive tuple reaches the single slot: {:?}",
        slot_texts.keys().collect::<Vec<_>>()
    );
}

/// CT-1(d): a prompt closure that REFUSES — the disclosure could not be composed — yields
/// `GateDecision::Refuse` on every interactive tuple, and no commit branch is reachable through
/// it. A gate that cannot show the operator the record view commits nothing.
#[test]
fn a_prompt_refusal_refuses_the_gate_and_reaches_no_commit_branch() {
    let speakable = owed(&[("consume-pins.toml", DirtClass::CleanOrRecorded)]);
                                                                                                  
                                                                                          
    let (d, is_tty, commit_token) = (&speakable, true, false);
    {
                                                                                                 
                                                   
        let asked = std::cell::Cell::new(0usize);
        let _ = decide_executing_gate(
            d,
            is_tty,
            commit_token,
            || {
                asked.set(asked.get() + 1);
                Ok('y')
            },
            "RESUME",
            "RESUME --commit",
        );
        assert_eq!(asked.get(), 1, "the tuple under test is an interactive one");

        let refused = decide_executing_gate(
            d,
            is_tty,
            commit_token,
            || {
                Err(orchard::ceremony::refusal::Refusal::new(
                    orchard::ceremony::refusal::RefusalId::GitStateUnreadable,
                    "the disclosure could not be composed",
                ))
            },
            "RESUME",
            "RESUME --commit",
        );
        assert!(
            committed_pairs(&refused).is_none(),
            "a refused prompt commits nothing: {refused:?}"
        );
        match refused {
            GateDecision::Refuse(r) => assert_eq!(r.id.token(), "git-state-unreadable"),
            other => panic!("a prompt error surfaces as Refuse, got {other:?}"),
        }
    }
}

                                                                                        
/// subset, and carries each PRESENT unspeakable class's own cause phrase exactly once — deduped by
/// CLASS, so two paths of one class contribute one phrase. Driven at both token states, because the
/// token does not reach this regime. The phrases come from `DirtClass::cause_phrase`, not literals,
/// so this arm reads the production map rather than a copy of it.
#[test]
fn the_headless_unspeakable_stop_names_the_subset_and_each_present_cause_once() {
    fn stop_detail(d: &[(DeclaredPathName, DirtClass)], commit_token: bool) -> String {
        match decide_executing_gate(
            d,
            false,
            commit_token,
            || panic!("no prompt headless"),
            "RESUME",
            "RESUME --commit",
        ) {
            GateDecision::Stop(stop) => {
                assert_eq!(stop.kind, OwedKind::ConsentGateStop);
                stop.refusal.detail.clone()
            }
            other => panic!("an unspeakable member stops a headless run, got {other:?}"),
        }
    }
    let unspeakable_classes: Vec<DirtClass> = DirtClass::ALL
        .iter()
        .copied()
        .filter(|c| !c.speakable())
        .collect();
    assert_eq!(
        unspeakable_classes.len(),
        2,
        "this arm enumerates the unspeakable classes; the set moved: {unspeakable_classes:?}"
    );

    for class in &unspeakable_classes {
        let d = owed(&[
            ("consume-pins.toml", DirtClass::CleanOrRecorded),
            ("vendor/a.tar.xz", *class),
            ("vendor/b.tar.xz", *class),
        ]);
        for commit_token in [false, true] {
            let detail = stop_detail(&d, commit_token);
            assert!(
                detail.contains("vendor/a.tar.xz") && detail.contains("vendor/b.tar.xz"),
                "{class:?} (token={commit_token}): the detail names the unspeakable paths: {detail}"
            );
            assert!(
                !detail.contains("consume-pins.toml"),
                "{class:?} (token={commit_token}): the speakable path is not the sentence's \
                 subject: {detail}"
            );
            assert_eq!(
                detail.matches(class.cause_phrase()).count(),
                1,
                "{class:?} (token={commit_token}): its cause phrase appears once, deduped by \
                 class: {detail}"
            );
            for other in unspeakable_classes.iter().filter(|c| *c != class) {
                assert!(
                    !detail.contains(other.cause_phrase()),
                    "{class:?} (token={commit_token}): an absent class's phrase is rendered: \
                     {detail}"
                );
            }
        }
    }

                                                                 
    let mixed = owed(&[
        ("vendor/a.tar.xz", unspeakable_classes[0]),
        ("vendor/b.tar.xz", unspeakable_classes[1]),
    ]);
    let detail = stop_detail(&mixed, true);
    for class in &unspeakable_classes {
        assert_eq!(
            detail.matches(class.cause_phrase()).count(),
            1,
            "each present class contributes its phrase once: {detail}"
        );
    }
}

                                                                                      
const CONSENT_GATE_TEMPLATE: &str = "the ceremony commits nothing the operator has not reviewed or \
                                     recorded — review the paths and re-run the resume \
                                     command";
                                                                                 
const AMBIGUOUS_ROUTE: &str = "settle or commit the named path(s) yourself, then re-run";
                                                                      
const RESTORE_ROUTE: &str = "restore or settle the interrupted write at the named path(s) (the \
                             re-executed step re-writes and finalizes), then re-run";

                                                                                                    
/// class, each route bound to its own class's path subset, joined with "; ", then the resume
/// command. `Interrupted` gets the restore-or-settle route the clause names over the interrupted
/// path(s) only, never the commit-it-yourself route the two-phase record exists to keep from
/// happening unnoticed. Each case asserts the WHOLE composed cure against hand literals, including
/// the join and its order (first appearance in the owed set), so a re-word anywhere in the
/// composition reds this arm.
#[test]
fn the_unspeakable_stops_cure_is_one_route_per_present_class_joined() {
    fn cure_of(d: &[(DeclaredPathName, DirtClass)]) -> String {
        match decide_executing_gate(
            d,
            false,
            true,
            || panic!("no prompt over unspeakable content"),
            "RESUME",
            "RESUME --commit",
        ) {
            GateDecision::Stop(stop) => stop.refusal.cure().as_str().to_string(),
            other => panic!("an unspeakable member stops every regime, got {other:?}"),
        }
    }

    let interrupted = cure_of(&owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::Interrupted),
    ]));
    assert_eq!(
        interrupted,
        format!("{CONSENT_GATE_TEMPLATE} ([\"vendor/x.tar.xz\"]: {RESTORE_ROUTE}: RESUME)"),
        "the interrupted write is restored over its own path, and the resume follows"
    );
    assert!(
        !interrupted.contains(AMBIGUOUS_ROUTE),
        "the restore must not offer committing a torn write: {interrupted}"
    );

    let ambiguous = cure_of(&owed(&[
        ("consume-pins.toml", DirtClass::CleanOrRecorded),
        ("vendor/x.tar.xz", DirtClass::Ambiguous),
    ]));
    assert_eq!(
        ambiguous,
        format!("{CONSENT_GATE_TEMPLATE} ([\"vendor/x.tar.xz\"]: {AMBIGUOUS_ROUTE}: RESUME)"),
        "unrecorded content is the operator's to settle"
    );
    assert!(
        !ambiguous.contains("restore or settle"),
        "the ambiguous route does not name a write to restore: {ambiguous}"
    );

                                                                                                 
              
    assert_eq!(
        cure_of(&owed(&[
            ("vendor/a.tar.xz", DirtClass::Ambiguous),
            ("vendor/b.tar.xz", DirtClass::Interrupted),
        ])),
        format!(
            "{CONSENT_GATE_TEMPLATE} ([\"vendor/a.tar.xz\"]: {AMBIGUOUS_ROUTE}; \
             [\"vendor/b.tar.xz\"]: {RESTORE_ROUTE}: RESUME)"
        )
    );
    assert_eq!(
        cure_of(&owed(&[
            ("vendor/b.tar.xz", DirtClass::Interrupted),
            ("vendor/a.tar.xz", DirtClass::Ambiguous),
        ])),
        format!(
            "{CONSENT_GATE_TEMPLATE} ([\"vendor/b.tar.xz\"]: {RESTORE_ROUTE}; \
             [\"vendor/a.tar.xz\"]: {AMBIGUOUS_ROUTE}: RESUME)"
        )
    );
}

/// The decision's committed pairs, or None when it committed nothing.
fn committed_pairs(d: &GateDecision) -> Option<&[(DeclaredPathName, DirtClass)]> {
    match d {
        GateDecision::Commit { paths, .. } | GateDecision::EditThenCommit { paths, .. } => {
            Some(paths)
        }
        GateDecision::Proceed | GateDecision::Stop(_) | GateDecision::Refuse(_) => None,
    }
}

                                                                                               
/// `decide_executing_gate` -> the committed pairs -> `commit_message`, driven over a prior run's
/// finalized-uncommitted write beside this run's own. The classes come from the classifier, so the
/// fixture cannot hand-pick a class the records would not produce.
#[test]
fn a_prior_runs_finalized_write_commits_under_its_own_attribution() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("boxes/gamma.d");
    let checkout = tmp.path().join("checkout");
    let prior = checkout.join("consume-pins.toml");
    let mine = checkout.join("vendor/x.tar.xz");
    std::fs::create_dir_all(mine.parent().expect("parent")).expect("mk checkout");

                                                                                              
    let mut r2 = RunRecords::open_dir(&dir, "run-2").expect("open records");
    let tok = open_path_record(&mut r2, &prior).expect("open entry");
    std::fs::write(&prior, "prior run bytes").expect("prior write");
    finalize_path_record(&mut r2, tok).expect("finalize");
    drop(r2);

                                                                            
    let mut r3 = RunRecords::open_dir(&dir, "run-3").expect("reload");
    let tok = open_path_record(&mut r3, &mine).expect("open entry");
    std::fs::write(&mine, "this run's bytes").expect("this run's write");
    finalize_path_record(&mut r3, tok).expect("finalize");

                                                                                                 
                                                                                      
    let prior_class = classify_executing_dirt(&r3, &prior);
    let mine_class = classify_executing_dirt(&r3, &mine);
    assert_eq!(
        prior_class,
        DirtClass::PriorRunRecorded,
        "run-2's finalized write observed by run-3 is another run's content"
    );
    assert_eq!(
        mine_class,
        DirtClass::CleanOrRecorded,
        "run-3's own finalized write is this run's content"
    );

    let mine_n = DeclaredPathName::new(mine.display().to_string());
    let prior_n = DeclaredPathName::new(prior.display().to_string());
    let both = vec![(mine_n.clone(), mine_class), (prior_n.clone(), prior_class)];
                                                                                                   
                                                                             
    let headless = decide_executing_gate(
        &both,
        false,
        true,
        || panic!("no prompt headless"),
        "R",
        "R --commit",
    );
    let pairs = committed_pairs(&headless)
        .unwrap_or_else(|| panic!("recorded content commits under the token, got {headless:?}"))
        .to_vec();
    assert_eq!(
        pairs,
        vec![
            (mine_n.clone(), DirtClass::CleanOrRecorded),
            (prior_n.clone(), DirtClass::PriorRunRecorded),
        ]
    );

                                                                                  
    let msg = commit_message("gamma", &["s4-store-vendor"], &pairs);
    let sections = message_sections(&msg);
    assert_eq!(
        sections
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [H_THIS_RUN.to_string(), H_PRIOR_RUN.to_string()].into(),
        "exactly the two classes present get a heading: {msg}"
    );
    assert_eq!(sections[H_THIS_RUN], vec![mine.display().to_string()]);
    assert_eq!(sections[H_PRIOR_RUN], vec![prior.display().to_string()]);
                                                                                            
    let nothing_executed = commit_message("gamma", &[], &pairs);
    assert_eq!(
        nothing_executed.lines().next(),
        Some("ceremony(gamma)"),
        "an empty step list renders no `: ` with nothing after it: {nothing_executed}"
    );

                                                                                                
                                     
    assert!(matches!(
        decide_executing_gate(&both, true, false, || Ok('n'), "R", "R --commit"),
        GateDecision::Stop(_)
    ));
    let interactive = decide_executing_gate(&both, true, false, || Ok('y'), "R", "R --commit");
    assert_eq!(
        committed_pairs(&interactive)
            .unwrap_or_else(|| panic!("interactive y commits, got {interactive:?}"))
            .to_vec(),
        pairs
    );
}

#[test]
fn the_commit_message_partitions_the_declared_paths_by_class() {
                                                                                                   
                                                                                
    let mine = DeclaredPathName::new("consume-pins.toml");
    let prior = DeclaredPathName::new("vendor/x.tar.xz");
    let torn = DeclaredPathName::new("crates/image-builder/pinned-cert-fingerprints.toml");
    let m = commit_message(
        "alpha",
        &["s4-store-vendor", "s6-tenant-repin"],
        &[
            (mine.clone(), DirtClass::CleanOrRecorded),
            (prior.clone(), DirtClass::PriorRunRecorded),
            (torn.clone(), DirtClass::Interrupted),
        ],
    );
    assert!(m.starts_with("ceremony(alpha): s4-store-vendor + s6-tenant-repin"));
    let sections = message_sections(&m);
    assert_eq!(
        sections
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            H_THIS_RUN.to_string(),
            H_PRIOR_RUN.to_string(),
            H_INTERRUPTED.to_string(),
        ]
        .into(),
        "one heading per class PRESENT, and none for the absent Ambiguous class: {m}"
    );
    assert_eq!(sections[H_THIS_RUN], vec![mine.as_str().to_string()]);
    assert_eq!(sections[H_PRIOR_RUN], vec![prior.as_str().to_string()]);
    assert_eq!(sections[H_INTERRUPTED], vec![torn.as_str().to_string()]);
                                                                                                 
                                                                    
    let amb = commit_message("alpha", &[], &[(mine.clone(), DirtClass::Ambiguous)]);
    assert_eq!(
        message_sections(&amb)[H_AMBIGUOUS],
        vec![mine.as_str().to_string()]
    );
}

/// The commit message's sections IN ORDER: each frozen heading in the sequence it appears, with its
/// two-space-indented members in the sequence they appear. `message_sections` is a BTreeMap and can
/// see neither order; a repeated heading pushes a SECOND entry here, so a class split across two
/// headings is visible rather than merged.
fn message_section_sequence(msg: &str) -> Vec<(String, Vec<String>)> {
    let headings: Vec<&'static str> = DirtClass::ALL
        .iter()
        .map(|c| orchard::ceremony::consent::class_heading(*c))
        .collect();
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut open = false;
    for line in msg.lines() {
        if let Some(h) = headings.iter().find(|h| **h == line) {
            out.push(((*h).to_string(), Vec::new()));
            open = true;
            continue;
        }
        match (line.strip_prefix("  "), open) {
            (Some(rest), true) => out
                .last_mut()
                .expect("a section is open")
                .1
                .push(rest.trim_matches('"').to_string()),
            _ => open = false,
        }
    }
    out
}

#[test]
fn the_message_section_sequence_reader_keeps_order_and_splits_a_repeated_heading() {
                                                                                       
    let read = message_section_sequence(&format!(
        "subject\n\n{H_AMBIGUOUS}\n  z\n  m\nloose\n  not-a-member\n{H_THIS_RUN}\n  a\n{H_AMBIGUOUS}\n  q\n"
    ));
    assert_eq!(
        read,
        vec![
            (
                H_AMBIGUOUS.to_string(),
                vec!["z".to_string(), "m".to_string()]
            ),
            (H_THIS_RUN.to_string(), vec!["a".to_string()]),
            (H_AMBIGUOUS.to_string(), vec!["q".to_string()]),
        ],
        "heading order, member order, and a repeated heading as two entries"
    );
    assert!(
        message_section_sequence("subject\n\n  a\n").is_empty(),
        "an indented line under no heading is attributed to nothing"
    );
}

                                                                                     
/// within a section the paths keep INPUT order. The input below is in neither order, so both
/// properties are read off one render. `message_sections` is order-blind and cannot hold either.
///
/// The expected sequence is a HAND LITERAL (the intended section order: this run, prior run,
/// interrupted, ambiguous), not a re-derivation through `section_order` — an expectation computed
/// with the map under test would follow a reordering of it and assert nothing.
#[test]
fn the_commit_message_sections_follow_section_order_and_keep_input_order_within_a_section() {
    let fixture: [(&str, DirtClass); 6] = [
        ("z.txt", DirtClass::Ambiguous),
        ("a.txt", DirtClass::CleanOrRecorded),
        ("m.txt", DirtClass::Ambiguous),
        ("p.txt", DirtClass::PriorRunRecorded),
        ("b.txt", DirtClass::CleanOrRecorded),
        ("c.txt", DirtClass::Interrupted),
    ];
                                                                                                  
                      
    assert_eq!(
        fixture.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        vec![
            DirtClass::Ambiguous,
            DirtClass::CleanOrRecorded,
            DirtClass::Ambiguous,
            DirtClass::PriorRunRecorded,
            DirtClass::CleanOrRecorded,
            DirtClass::Interrupted,
        ],
        "the fixture must arrive interleaved and out of section order, with all four classes \
         present so a swap of ANY two section ranks moves the rendered sequence"
    );
    let rows: Vec<(DeclaredPathName, DirtClass)> = fixture
        .iter()
        .map(|(p, c)| (DeclaredPathName::new(*p), *c))
        .collect();

    let msg = commit_message("alpha", &["s4-store-vendor"], &rows);
    let read = message_section_sequence(&msg);

    assert_eq!(
        read.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(),
        vec![H_THIS_RUN, H_PRIOR_RUN, H_INTERRUPTED, H_AMBIGUOUS],
        "the section sequence follows section_order: {msg}"
    );
    let members: Vec<Vec<String>> = read.into_iter().map(|(_, m)| m).collect();
    assert_eq!(
        members,
        vec![
            vec!["a.txt".to_string(), "b.txt".to_string()],
            vec!["p.txt".to_string()],
            vec!["c.txt".to_string()],
            vec!["z.txt".to_string(), "m.txt".to_string()],
        ],
        "within a section the paths keep the order they arrived in: {msg}"
    );
}

#[test]
fn a_clean_declared_set_never_prompts_and_never_commits() {
    match decide_executing_gate(
        &[],
        true,
        true,
        || panic!("no prompt when nothing is owed"),
        "R",
        "R --commit",
    ) {
        GateDecision::Proceed => {}
        other => panic!("expected Proceed, got {other:?}"),
    }
}

#[test]
fn a_recognized_sibling_path_proceeds_with_its_owed_command_and_an_unrecognized_one_refuses() {
                                                                                            
                                                                                 
    let root = std::path::Path::new("/x/recipes");
    match decide_sibling("tenant", &[("published-pins.toml".into(), true)], root, "") {
        SiblingDecision::Proceed { owed } => {
            assert_eq!(
                owed,
                vec!["git -C /x/recipes commit -- published-pins.toml".to_string()]
            );
        }
        other => panic!("recognized ceremony output proceeds, got {other:?}"),
    }
    match decide_sibling("tenant", &[("published-pins.toml".into(), false)], root, "") {
        SiblingDecision::Stop(stop) => {
            assert_eq!(stop.kind, OwedKind::SiblingRefuseBeforeOverwrite);
            assert_eq!(stop.refusal.id.token(), "sibling-content-unrecognized");
            let cure = stop.refusal.cure();
            assert!(
                cure.as_str().contains("commit or stash") && cure.as_str().contains("/x/recipes"),
                "the external cure names the sibling and the action: {}",
                cure.as_str()
            );
            assert!(
                !cure.as_str().contains("y/e/N") && !cure.as_str().contains("--commit"),
                "never a prompt implying the runner will act: {}",
                cure.as_str()
            );
        }
        other => panic!("unrecognized content refuses, got {other:?}"),
    }
                                                    
    assert!(matches!(
        decide_sibling("tenant", &[], root, ""),
        SiblingDecision::Proceed { owed } if owed.is_empty()
    ));
}

#[test]
fn the_commit_message_names_the_run_and_only_the_declared_paths() {
    let m = commit_message(
        "alpha",
        &["s4-store-vendor", "s6-tenant-repin"],
        &[
            (
                DeclaredPathName::new("consume-pins.toml"),
                DirtClass::CleanOrRecorded,
            ),
            (
                DeclaredPathName::new("vendor/x.tar.xz"),
                DirtClass::CleanOrRecorded,
            ),
        ],
    );
    assert!(m.starts_with("ceremony(alpha): s4-store-vendor + s6-tenant-repin"));
    assert!(m.contains("consume-pins.toml") && m.contains("vendor/x.tar.xz"));
}

#[test]
fn s7_records_its_image_triple_by_path_and_producer_declared_hash() {
                                                                                             
                                                                                      
                                                                                                
                                                           
    use orchard::ceremony::runner::produced_artifacts;
    let fx = fixture();
    let records = records_at(&fx);
    let out_dir = fx._tmp.path().join("images");
    std::fs::create_dir_all(&out_dir).expect("mk");
    let head = "abc1234";
    let base = recipes_image_builder::image::image_output_base(head);
    for (ext, body) in [
        ("img", "IMAGE"),
        ("layout.toml", "layout = 1"),
        ("vmlinuz", "KERNEL"),
        ("initramfs", "INITRD"),
    ] {
        std::fs::write(out_dir.join(format!("{base}.{ext}")), body).expect("w");
    }
    let img_hex = "1".repeat(64);
    let vml_hex = "2".repeat(64);
    let ini_hex = "3".repeat(64);
    std::fs::write(
        out_dir.join(format!("{base}.sha256")),
        format!("{img_hex}  {base}.img\n"),
    )
    .expect("w");
    std::fs::write(
        out_dir.join(format!("{base}.vmlinuz.sha256")),
        format!("{vml_hex}  {base}.vmlinuz\n"),
    )
    .expect("w");
    std::fs::write(
        out_dir.join(format!("{base}.initramfs.sha256")),
        format!("{ini_hex}  {base}.initramfs\n"),
    )
    .expect("w");
    let profile = Profile {
        out_dir: Some(out_dir.clone()),
        ..ceremony_profile()
    };
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let measured = Measured {
        dirty: vec![],
        head: Some(head.to_string()),
    };
    let produced = produced_artifacts(
        step_of(StepId::S7ImageBuild),
        &values,
        &fx.ctx,
        &measured,
        records.dir(),
    )
    .expect("ok");
    assert_eq!(
        produced.keys().collect::<Vec<_>>(),
        vec!["img", "initramfs", "layout", "vmlinuz"]
    );
    assert_eq!(
        produced["img"].path,
        out_dir.join(format!("{base}.img")).display().to_string()
    );
    assert_eq!(
        produced["img"].sha256, img_hex,
        "read from the build's sidecar"
    );
    assert_eq!(produced["vmlinuz"].sha256, vml_hex);
    assert_eq!(produced["initramfs"].sha256, ini_hex);
    assert_eq!(
        produced["layout"].sha256.len(),
        64,
        "the small sidecar has no sha file of its own, so it is hashed directly"
    );
                                                                                          
                                                           
    std::fs::remove_file(out_dir.join(format!("{base}.img"))).expect("rm");
    let err = produced_artifacts(
        step_of(StepId::S7ImageBuild),
        &values,
        &fx.ctx,
        &measured,
        records.dir(),
    )
    .expect_err("a missing artifact fails closed");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("typed");
    assert_eq!(refusal.id.token(), "step-failed");
                                                                     
    assert!(
        produced_artifacts(
            step_of(StepId::S3Prime),
            &values,
            &fx.ctx,
            &measured,
            records.dir()
        )
        .expect("ok")
        .is_empty()
    );
}

                                                                                                    
/// for the artifact name renders its own remedy and never the commit gate's. Driven through
/// `produced_artifacts` with no measured HEAD; the cure is a hand literal, and the commit-gate text
/// is asserted absent, so a collapse of the two purposes onto one text reds this arm. The
/// commit-gate purpose is asserted at its own driven site
/// (`the_executing_gate_fails_closed_when_git_state_is_unreadable`).
#[test]
fn the_s7_artifact_naming_read_renders_its_own_cure_not_the_commit_gates() {
    use orchard::ceremony::runner::produced_artifacts;
    const ARTIFACT_NAMING_CURE: &str = "the ceremony reads HEAD to name the S7 artifact; run \
         against the git checkout the ceremony was invoked on, with git on PATH";
    let fx = fixture();
    let records = records_at(&fx);
    let out_dir = fx._tmp.path().join("images");
    std::fs::create_dir_all(&out_dir).expect("mk");
    let profile = Profile {
        out_dir: Some(out_dir),
        ..ceremony_profile()
    };
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);

                                                                                            
                                                                                           
    let with_head = Measured {
        dirty: vec![],
        head: Some("abc1234".to_string()),
    };
    let other = produced_artifacts(
        step_of(StepId::S7ImageBuild),
        &values,
        &fx.ctx,
        &with_head,
        records.dir(),
    )
    .expect_err("an absent triple fails closed");
    assert_eq!(
        other
            .downcast_ref::<orchard::ceremony::refusal::Refusal>()
            .expect("typed")
            .id
            .token(),
        "step-failed"
    );

    let err = produced_artifacts(
        step_of(StepId::S7ImageBuild),
        &values,
        &fx.ctx,
        &Measured {
            dirty: vec![],
            head: None,
        },
        records.dir(),
    )
    .expect_err("S7 cannot name its artifact without a HEAD");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .unwrap_or_else(|| panic!("expected the typed refusal, got: {err}"));
    assert_eq!(refusal.id.token(), "git-state-unreadable");
    assert_eq!(
        refusal.cure().as_str(),
        ARTIFACT_NAMING_CURE,
        "the S7 read's own remedy, not the commit gate's"
    );
    assert!(
        !refusal.cure().as_str().contains("commit gate"),
        "the commit-gate remedy is false at this site: {}",
        refusal.cure().as_str()
    );
}

                                                                                                     

use orchard::deploy::prod_orchestrate::{
    DEFAULT_PROVISIONING_USER, DEFAULT_RECONNECT_USER, privileged_remote, prod_ssh_args,
    prod_ssh_args_as,
};

#[test]
fn the_pre_kexec_leg_connects_as_the_cloud_user_and_never_as_root() {
                                                                                                  
                                                                                         
                               
    let args = prod_ssh_args_as(
        DEFAULT_PROVISIONING_USER,
        "203.0.113.5",
        Path::new("/k"),
        Path::new("/kh"),
        22,
    );
    assert!(
        args.iter().any(|a| a == "debian@203.0.113.5"),
        "the pre-kexec destination is the cloud user: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a.starts_with("root@")),
        "no root@ destination on the pre-kexec leg: {args:?}"
    );
                                                                                              
    let reconnect = prod_ssh_args("203.0.113.5", Path::new("/k"), Path::new("/kh"), 22);
    assert!(reconnect.iter().any(|a| a == "root@203.0.113.5"));
                                                                                   
    assert_eq!(args.len(), reconnect.len());
    assert_eq!(&args[..args.len() - 1], &reconnect[..reconnect.len() - 1]);
}

#[test]
fn a_privileged_remote_command_keeps_its_root_shell_semantics() {
                                                                                         
                                                                                         
                                                                                                  
                          
    let composed = privileged_remote(DEFAULT_PROVISIONING_USER, "findmnt -n -o SOURCE / || true");
    assert_eq!(composed, "sudo -n sh -c 'findmnt -n -o SOURCE / || true'");
    assert!(
        composed.contains("-n"),
        "sudo fails instead of prompting, so a target without passwordless sudo refuses loudly \
         rather than hanging: {composed}"
    );
                                                                                 
    assert_eq!(
        privileged_remote(DEFAULT_RECONNECT_USER, "kexec -e"),
        "kexec -e"
    );
}

#[test]
fn the_sudo_wrapper_preserves_a_command_that_already_carries_single_quotes() {
                                                                                               
                                                                                            
                                                                                                
                    
    let inner = "kexec -l /var/tmp/x/vmlinuz --initrd=/var/tmp/x/initramfs --append 'root=/dev/vda2 fb.net=mode=dhcp'";
    let composed = privileged_remote(DEFAULT_PROVISIONING_USER, inner);
                                                                                           
                                                                                              
                                                                                                 
                                                                                   
    assert_eq!(
        shell_words(&composed),
        vec![
            "sudo".to_string(),
            "-n".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            inner.to_string()
        ],
        "composed: {composed}"
    );
}

/// POSIX word splitting with single-quote and backslash handling — enough to tokenize what
/// `privileged_remote` composes. An oracle for the arms; it shares no code with the escaper.
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut in_quote = false;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            cur.push(c);
            escape = false;
            started = true;
            continue;
        }
        if in_quote {
            if c == '\'' {
                in_quote = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\\' => {
                escape = true;
            }
            '\'' => {
                in_quote = true;
                started = true;
            }
            ' ' => {
                if started {
                    words.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            _ => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(cur);
    }
    words
}

#[test]
fn the_composed_prod_child_carries_the_declared_provisioning_user() {
                                                                                                  
                                                                   
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = Profile {
        provisioning_user: Some("ubuntu".into()),
        ..ceremony_profile()
    };
    let mut i = inv(Some("203.0.113.5"));
    i.wipe_confirmed = true;
    let values = resolve_values(&i, &profile, &fx.ctx);
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: Default::default(),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: "/tmp/x.img".into(),
                    sha256: "d0".into(),
                },
            )]
            .into(),
        })
        .expect("record");
    let calls = child_invocations(
        step_of(StepId::S10ProdInstall),
        &values,
        &i,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    let args = &calls[0].args;
    let at = args
        .iter()
        .position(|a| a == "--provisioning-user")
        .unwrap_or_else(|| panic!("composed: {args:?}"));
    assert_eq!(args[at + 1], "ubuntu");
}

                                                                                                    

#[test]
fn a_held_ceremony_lock_refuses_a_second_run_and_a_direct_writing_verb() {
                                                                                                  
                                                                                                
    let _serial = lock_arm_guard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("mk home");
    let lock_dir = tmp.path().join("lockdir");
    let held = acquire_at(&lock_dir, "run", None).expect("hold");
    let spawn = |args: &[&str]| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"));
        c.current_dir(tmp.path())
            .env_remove("FRUIT_ARTIFACT_STORE")
            .env_remove("ORCHARD_LOCK_TOKEN")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("ORCHARD_LOCK_DIR", &lock_dir)
            .args(args);
        let out = c.output().expect("spawn");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for args in [
        vec!["run", "boxes/alpha.toml"],
        vec!["build", "--domain", "box.test"],
    ] {
        let (code, stderr) = spawn(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert!(
            stderr.contains("lock-held") && stderr.contains("run"),
            "{args:?} must refuse naming the holder: {stderr}"
        );
    }
                                                             
    let (code, stderr) = spawn(&["doctor"]);
    assert!(
        !stderr.contains("lock-held"),
        "doctor is not blocked: {stderr}"
    );
    assert_ne!(code, 2, "doctor is not refused by the lock: {stderr}");
    drop(held);
}

#[test]
fn a_second_profile_never_inherits_the_first_profiles_image() {
                                                                                             
                                                                                                
                                                                               
    let fx = fixture();
    let out_dir = fx._tmp.path().join("shared-images");
    std::fs::create_dir_all(&out_dir).expect("mk");
    let head = "same0000";
    let base = recipes_image_builder::image::image_output_base(head);
    let img = out_dir.join(format!("{base}.img"));
    std::fs::write(&img, b"A's image").expect("w");
    let profile = Profile {
        out_dir: Some(out_dir.clone()),
        ..ceremony_profile()
    };
    let i = inv(Some("203.0.113.5"));
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let measured = Measured {
        dirty: vec![],
        head: Some(head.to_string()),
    };
                                                                               
    let mut a = RunRecords::open_dir(&fx.root.join("boxes/a.d"), "run-a").expect("a");
    a.record_step(StepRecord {
        step: StepId::S7ImageBuild.token().to_string(),
        run_id: a.run_id().to_string(),
        params: params_of(StepId::S7ImageBuild, &values),
        input_identities: [("ceremony-head".to_string(), head.to_string())].into(),
        produced: [(
            "img".to_string(),
            ProducedArtifact {
                path: img.display().to_string(),
                sha256: recipes_image_builder::image::sha256_hex(b"A's image"),
            },
        )]
        .into(),
    })
    .expect("record");
    let s7 = step_of(StepId::S7ImageBuild);
    assert!(matches!(
        step_done(s7, &probe_ctx, &values, &a, &measured),
        DoneResult::Done
    ));
                                                                                       
    let b = RunRecords::open_dir(&fx.root.join("boxes/b.d"), "run-b").expect("b");
    match step_done(s7, &probe_ctx, &values, &b, &measured) {
        DoneResult::NotDone(why) => assert!(why.contains("no record"), "{why}"),
        other => panic!("B must rebuild, got {other:?}"),
    }
                                                                                              
                                                                                              
                                                                                            
    let mut b2 = RunRecords::open_dir(&fx.root.join("boxes/b2.d"), "run-b2").expect("b2");
    b2.record_step(StepRecord {
        step: StepId::S7ImageBuild.token().to_string(),
        run_id: b2.run_id().to_string(),
        params: params_of(StepId::S7ImageBuild, &values),
        input_identities: [("ceremony-head".to_string(), head.to_string())].into(),
        produced: [(
            "img".to_string(),
            ProducedArtifact {
                path: img.display().to_string(),
                sha256: recipes_image_builder::image::sha256_hex(b"B's image"),
            },
        )]
        .into(),
    })
    .expect("record");
    match step_done(s7, &probe_ctx, &values, &b2, &measured) {
        DoneResult::NotDone(why) => assert!(why.contains("changed since the record"), "{why}"),
        other => panic!("B must rebuild when A's bytes sit at B's recorded path, got {other:?}"),
    }
    let mut wipe = inv(Some("203.0.113.5"));
    wipe.wipe_confirmed = true;
    let err = child_invocations(step_of(StepId::S10ProdInstall), &values, &wipe, &fx.ctx, &b)
        .expect_err("B cannot name an image");
    assert_eq!(err.id.token(), "step-input-missing");
}

#[test]
fn a_resumed_run_skips_what_the_records_bind_and_retries_the_failed_step() {
                                                                                               
                                                                                               
                                                                                               
                                                                                               
                                                                                           
                     
                                                                                             
                                                                                         
                                                                 
    let fx = repo_fixture();
    let mut records = records_at(&fx);
    let profile = complete_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let reporter = Reporter { porcelain: true };
    let prompt = || 'n';
    let run_once = |records: &mut RunRecords, outcomes: Vec<ChildOutcome>| -> Vec<StepId> {
        let admitted = admission::admit_with(&i, &fx.ctx, &profile, records, Measured::default())
            .expect("admitted");
        let mut exec = FakeExec {
            calls: vec![],
            outcomes,
        };
        let mut deps = RunnerDeps {
            exec: &mut exec,
            reporter: &reporter,
            lock_token: None,
            is_tty: false,
            prompt: &prompt,
            editor: None,
        };
        let _ = run_ceremony(&admitted, &i, &fx.ctx, &profile, records, &mut deps);
        exec.calls.iter().map(|c| c.step).collect()
    };
                        
    let first = run_once(
        &mut records,
        vec![
            ChildOutcome::Ok,
            ChildOutcome::Ok,
            ChildOutcome::Ok,
            ChildOutcome::Failed("vendor: store miss".into()),
        ],
    );
    assert_eq!(
        first,
        vec![
            StepId::S1BuildContainer,
            StepId::S2OperatorKeys,
            StepId::S3Prime,
            StepId::S4StoreVendor
        ]
    );
    assert!(
        records
            .step_record(StepId::S2OperatorKeys.token())
            .is_some()
    );
    assert!(records.step_record(StepId::S4StoreVendor.token()).is_none());
                                                                                       
    let second = run_once(&mut records, vec![]);
    assert!(
        !second.contains(&StepId::S2OperatorKeys),
        "a recorded step with no artifact probe SKIPs on resume: {second:?}"
    );
    assert!(
        second.contains(&StepId::S4StoreVendor),
        "the step that failed is retried: {second:?}"
    );
}

#[test]
fn a_run_whose_clean_tree_steps_all_skip_still_reaches_the_commit_gate() {
                                                                                                   
                                                                                                 
                                                                                                    
                                                                      
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
                                                                                                   
                                                                                               
                                                                                                   
                                                                                                 
                                        
    for id in [
        StepId::S2OperatorKeys,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    assert!(
        SPINE
            .iter()
            .filter(|s| s.requires_clean_tree)
            .all(|s| admitted.plan.iter().any(|p| p.id == s.id && p.is_done())),
        "the fixture must have every clean-tree step done, or this arm proves nothing"
    );
                                                                                                   
                                                                                                
                                                                                           
                                                                            
    let dirty = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    std::fs::create_dir_all(dirty.parent().expect("parent")).expect("mk");
    std::fs::write(&dirty, "committed baseline\n").expect("w");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["add", "-A"],
        vec!["commit", "-qm", "baseline"],
    ] {
        let ok = std::process::Command::new("git")
            .current_dir(&fx.root)
            .args(&args)
            .output()
            .expect("git");
        assert!(
            ok.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }
    std::fs::write(&dirty, "dirtied by an earlier step\n").expect("w");
    let admission::DirtScan::Scanned(scanned) = admission::git_dirty_paths(&fx.root) else {
        panic!("the inline-init fixture is a real repo");
    };
    assert!(
        scanned
            .iter()
            .any(|p| p.ends_with("pinned-cert-fingerprints.toml")),
        "the fixture must present real dirt, or the gate has nothing to find"
    );
    let mut rec2 = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let tok = orchard::ceremony::records::open_path_record(&mut rec2, &dirty).expect("open");
    orchard::ceremony::records::finalize_path_record(&mut rec2, tok).expect("finalize");
    drop(rec2);
    let mut records =
        RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-2").expect("re-open");
    let reporter = Reporter { porcelain: true };
    let head_before = git_head(&fx.root);
    let prompt = || 'n';
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: false,
        prompt: &prompt,
        editor: None,
    };
    ratify_at(&fx, &mut i);
    match run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps) {
        Err(e) => {
            let stop = e
                .downcast_ref::<OwedStop>()
                .unwrap_or_else(|| panic!("expected an owed consent-gate stop, got: {e}"));
            assert_eq!(stop.kind, OwedKind::ConsentGateStop);
        }
        Ok(()) => panic!(
            "the run reported success with a dirty declared path the operator was never shown"
        ),
    }
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "and it committed nothing without authorization"
    );
}

                                                                                             
/// themselves; this one drives `run_ceremony` over a real checkout with a prior-run and a this-run
/// dirty declared path and reads what the runner hands the git seam. `executing_gate` derives BOTH
/// the pathspec and the message from the decision's own pairs, so a second derivation (composing
/// either from the pre-gate `owed` scan, or filtering one of them) is what this arm holds.
#[test]
fn the_runners_commit_carries_the_gates_pairs_and_equals_the_dirt_it_scanned() {
    let _fd1 = fd1_arm_guard();
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
                                                                                                   
                                                                                              
                                                                                                  
                                                                                       
    for id in [
        StepId::S2OperatorKeys,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");

    git_init_baseline(&fx.root);
    let prior = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    let mine = fx.root.join("vendor/x.tar.xz");
    std::fs::create_dir_all(prior.parent().expect("parent")).expect("mk crates");
    std::fs::create_dir_all(mine.parent().expect("parent")).expect("mk vendor");

    let mut r1 = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-1").expect("records");
    let tok = open_path_record(&mut r1, &prior).expect("open entry");
    std::fs::write(&prior, "prior run bytes\n").expect("prior write");
    finalize_path_record(&mut r1, tok).expect("finalize");
    drop(r1);
    let mut run2 = RunRecords::open_dir(&fx.root.join("boxes/alpha.d"), "run-2").expect("re-open");
    let tok = open_path_record(&mut run2, &mine).expect("open entry");
    std::fs::write(&mine, "this run's bytes\n").expect("this run's write");
    finalize_path_record(&mut run2, tok).expect("finalize");

                                                                                                 
                                                                                               
    let admission::DirtScan::Scanned(scanned) = admission::git_dirty_paths(&fx.root) else {
        panic!("the fixture root is a real repo");
    };
    let scanned_declared: Vec<String> = scanned
        .iter()
        .filter(|p| admission::is_declared(p))
        .cloned()
        .collect();
    assert_eq!(
        scanned_declared,
        vec![
            "crates/image-builder/pinned-cert-fingerprints.toml".to_string(),
            "vendor/x.tar.xz".to_string(),
        ],
        "the scanned dirty DECLARED set is what the gate must commit: {scanned:?}"
    );
    assert_eq!(
        classify_executing_dirt(&run2, &prior),
        DirtClass::PriorRunRecorded
    );
    assert_eq!(
        classify_executing_dirt(&run2, &mine),
        DirtClass::CleanOrRecorded
    );

    let reporter = Reporter { porcelain: true };
    let head_before = git_head(&fx.root);
    let prompt = || 'y';
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    ratify_at(&fx, &mut i);
    run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut run2, &mut deps)
        .unwrap_or_else(|e| panic!("the interactive run commits and reports success: {e}"));

                                                                                                 
                                                                                    
                                   
    assert_ne!(git_head(&fx.root), head_before, "one gate, one commit");
    assert_eq!(
        git_show_names(&fx.root, "HEAD"),
        scanned_declared,
        "the landed commit changes the gate's pathspec and it equals what the gate scanned"
    );
    let message = git_log_message(&fx.root, "HEAD");
    let sections = message_sections(&message);
    assert_eq!(
        sections
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [H_THIS_RUN.to_string(), H_PRIOR_RUN.to_string()].into(),
        "the composed message carries one heading per class present: {message}"
    );
    assert_eq!(
        sections[H_PRIOR_RUN],
        vec!["crates/image-builder/pinned-cert-fingerprints.toml".to_string()],
        "the prior run's path is attributed to a prior run: {message}"
    );
    assert_eq!(
        sections[H_THIS_RUN],
        vec!["vendor/x.tar.xz".to_string()],
        "this run's path is attributed to this run: {message}"
    );
}

/// An executor that records the checkout's dirty state AT the moment each child would run, so an
/// arm can assert what the tree looked like at a step's own boundary rather than after the run.
struct DirtAtExec {
    root: std::path::PathBuf,
    seen: Vec<(StepId, admission::DirtScan)>,
}

impl Executor for DirtAtExec {
    fn run(&mut self, call: &ChildCall, _sink: &mut dyn FnMut(&str)) -> ChildOutcome {
        let scan = admission::git_dirty_paths(&self.root);
        self.seen.push((call.step, scan));
        ChildOutcome::Ok
    }
}

                                                                                                
/// every `requires_clean_tree` step done, which selects the post-loop call by construction, so the
/// in-loop site — the one that must clear the tree BEFORE the step that refuses dirt — had no arm.
/// Here S10 is the first not-done clean-tree step and it executes, and the capture at its child's
/// boundary is what the gate left behind.
#[test]
fn the_in_loop_gate_clears_the_tree_before_the_clean_tree_step_runs() {
    let _fd1 = fd1_arm_guard();
    use orchard::ceremony::gate_record::{
        BuildParams, GATE_RECORD_SCHEMA_VERSION, GateRecord, LegRun, adopt_gate_record,
        gate_record_path, s10_precondition,
    };
    use orchard::ceremony::leg_registry::composition_of;

    let fx = fixture();
                                                                                               
                                                           
    let makefile_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Makefile");
    std::fs::copy(&makefile_src, fx.root.join("Makefile")).expect("copy the real Makefile");
    let dirty = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    std::fs::create_dir_all(dirty.parent().expect("parent")).expect("mk crates");
    std::fs::write(&dirty, "committed baseline\n").expect("w");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["add", "-A"],
        vec!["commit", "-qm", "baseline"],
    ] {
        let ok = std::process::Command::new("git")
            .current_dir(&fx.root)
            .args(&args)
            .output()
            .expect("git");
        assert!(
            ok.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }

                                                                                              
                                                    
    let out = fx._tmp.path().join("images");
    std::fs::create_dir_all(&out).expect("mk out");
    let label = "abc1234";
    let base = recipes_image_builder::image::image_output_base(label);
    let img = out.join(format!("{base}.img"));
    let layout = out.join(format!("{base}.layout.toml"));
    let vmlinuz = out.join(format!("{base}.vmlinuz"));
    let initramfs = out.join(format!("{base}.initramfs"));
    for (p, body) in [
        (&img, "IMG"),
        (&layout, "layout = 1"),
        (&vmlinuz, "KERNEL"),
        (&initramfs, "INITRD"),
    ] {
        std::fs::write(p, body).expect("write artifact");
    }
    for (name, byte) in [
        ("sha256", 0x11u8),
        ("vmlinuz.sha256", 0x22),
        ("initramfs.sha256", 0x33),
    ] {
        let stem = match name {
            "sha256" => format!("{base}.img"),
            "vmlinuz.sha256" => format!("{base}.vmlinuz"),
            _ => format!("{base}.initramfs"),
        };
        std::fs::write(
            out.join(format!("{base}.{name}")),
            format!("{}  {stem}\n", format!("{byte:02x}").repeat(32)),
        )
        .expect("w sidecar");
    }
    let provenance = orchard::ceremony::gate_record::compose(
        label,
        BuildParams {
            domain: "box.test".into(),
            net: "mode=dhcp".into(),
            firmware: "seabios".into(),
            image_version: 3,
            git_sha: "a".repeat(40),
        },
        &img,
        &layout,
        &vmlinuz,
        &initramfs,
    )
    .expect("compose provenance");
    orchard::ceremony::gate_record::write(&img, &provenance).expect("write provenance");

    let gate_target = "boot-gate-ceremony";
    let makefile = std::fs::read_to_string(fx.root.join("Makefile")).expect("read Makefile");
    let declared = composition_of(&makefile, gate_target).expect("the target has a composition");
    let record = GateRecord {
        schema_version: GATE_RECORD_SCHEMA_VERSION,
        gate_target: gate_target.to_string(),
        image_label: provenance.image_label.clone(),
        staged: provenance.produced.clone(),
        params: provenance.params.clone(),
        leg: declared
            .legs
            .iter()
            .map(|l| LegRun { id: l.id.clone() })
            .collect(),
    };
    std::fs::write(
        gate_record_path(&img),
        toml::to_string(&record).expect("encode the gate record"),
    )
    .expect("write the gate record");
    let records_dir = fx.root.join("boxes/alpha.d");
    adopt_gate_record(&img, &records_dir).expect("adopt");
    assert_eq!(
        s10_precondition(Some(&img), Some(&records_dir), &fx.root, gate_target),
        ProbeResult::Met,
        "arm sanity: S10's precondition holds, or the step never executes and the gate never fires \
         in-loop"
    );

    let profile = Profile {
        gate_target: Some(gate_target.to_string()),
        out_dir: Some(out.clone()),
        ..complete_profile()
    };
    let mut i = inv(Some("203.0.113.5"));
    i.wipe_confirmed = true;
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    let mut records = RunRecords::open_dir(&records_dir, "run-1").expect("records");
    for id in [
        StepId::S1BuildContainer,
        StepId::S2OperatorKeys,
        StepId::S3Prime,
        StepId::S4StoreVendor,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    records
        .record_step(StepRecord {
            step: StepId::S7ImageBuild.token().to_string(),
            run_id: records.run_id().to_string(),
            params: params_of(StepId::S7ImageBuild, &values),
            input_identities: Default::default(),
            produced: [(
                "img".to_string(),
                ProducedArtifact {
                    path: img.display().to_string(),
                    sha256: recipes_image_builder::image::sha256_hex(b"IMG"),
                },
            )]
            .into(),
        })
        .expect("record s7");

    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
                                                                                                  
                                              
    let first_clean_tree = SPINE
        .iter()
        .filter(|s| s.requires_clean_tree)
        .find(|s| admitted.plan.iter().any(|p| p.id == s.id && !p.is_done()))
        .map(|s| s.id);
    assert_eq!(
        first_clean_tree,
        Some(StepId::S10ProdInstall),
        "the fixture must leave S10 as the first not-done clean-tree step"
    );

                                                                                                  
    let mut r0 = RunRecords::open_dir(&records_dir, "run-0").expect("prior records");
    let tok = open_path_record(&mut r0, &dirty).expect("open entry");
    std::fs::write(&dirty, "prior run bytes\n").expect("prior write");
    finalize_path_record(&mut r0, tok).expect("finalize");
    drop(r0);
    let mut run1 = RunRecords::open_dir(&records_dir, "run-1").expect("re-open");
    assert_eq!(
        classify_executing_dirt(&run1, &dirty),
        DirtClass::PriorRunRecorded,
        "arm sanity: the dirt is a prior run's recorded content"
    );
    let admission::DirtScan::Scanned(before) = admission::git_dirty_paths(&fx.root) else {
        panic!("the fixture root is a real repo");
    };
    assert!(
        before
            .iter()
            .any(|p| p == "crates/image-builder/pinned-cert-fingerprints.toml"),
        "the declared path is dirty BEFORE the run: {before:?}"
    );

    let reporter = Reporter { porcelain: true };
                                                                                             
                   
    let prompt = || 'y';
    let mut exec = DirtAtExec {
        root: fx.root.clone(),
        seen: Vec::new(),
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    let head_before = git_head(&fx.root);
    ratify_at(&fx, &mut i);
    run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut run1, &mut deps)
        .unwrap_or_else(|e| panic!("the run reaches S10 and reports success: {e}"));

                                                                                                   
                                                             
    let s10_calls: Vec<&(StepId, admission::DirtScan)> = exec
        .seen
        .iter()
        .filter(|(s, _)| *s == StepId::S10ProdInstall)
        .collect();
    assert_eq!(
        s10_calls.len(),
        1,
        "S10 executed exactly one child: {:?}",
        exec.seen.iter().map(|(s, _)| *s).collect::<Vec<_>>()
    );
    let admission::DirtScan::Scanned(at_s10) = &s10_calls[0].1 else {
        panic!("the checkout stayed readable through the run");
    };
    let declared_at_s10: Vec<&String> = at_s10
        .iter()
        .filter(|p| admission::is_declared(p))
        .collect();
    assert!(
        declared_at_s10.is_empty(),
        "S10's child ran with a dirty declared path the gate should have settled first: \
         {declared_at_s10:?} (before the run: {before:?})"
    );
                                                                                                 
                                                                                                  
    let pre_gate: Vec<StepId> = exec
        .seen
        .iter()
        .take_while(|(s, _)| *s != StepId::S10ProdInstall)
        .map(|(s, _)| *s)
        .collect();
    assert!(
        !pre_gate.is_empty(),
        "at least one step must run before S10, or the capture has nothing to contrast with"
    );
    for (step, scan) in exec
        .seen
        .iter()
        .take_while(|(s, _)| *s != StepId::S10ProdInstall)
    {
        let admission::DirtScan::Scanned(v) = scan else {
            panic!("{step:?}: the checkout stayed readable");
        };
        assert!(
            v.iter()
                .any(|p| p == "crates/image-builder/pinned-cert-fingerprints.toml"),
            "{step:?} ran before the gate, so the declared path is still dirty at its boundary: \
             {v:?}"
        );
    }

                                                                                             
                                                        
    let head_after = git_head(&fx.root);
    assert_ne!(head_before, head_after, "the gate moved HEAD");
    let touched = git_show_names(&fx.root, &head_after);
    assert_eq!(
        touched,
        vec!["crates/image-builder/pinned-cert-fingerprints.toml".to_string()],
        "the commit is pathspec-scoped to the gate's own paths"
    );
    let message = git_log_message(&fx.root, &head_after);
    let sections = message_sections(&message);
    assert_eq!(
        sections
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [H_PRIOR_RUN.to_string()].into(),
        "the message attributes it to a prior run, and to nothing else: {message}"
    );
    assert_eq!(
        sections[H_PRIOR_RUN],
        vec!["crates/image-builder/pinned-cert-fingerprints.toml".to_string()]
    );
}

fn git_out(root: &std::path::Path, args: &[&str]) -> String {
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

fn git_head(root: &std::path::Path) -> String {
    git_out(root, &["rev-parse", "HEAD"])
}

fn git_log_message(root: &std::path::Path, rev: &str) -> String {
    git_out(root, &["log", "-1", "--format=%B", rev])
}

fn git_show_names(root: &std::path::Path, rev: &str) -> Vec<String> {
    git_out(root, &["show", "--name-only", "--format=", rev])
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// A [`repo_fixture`] plus a repo-manifest naming `recipes` at `../recipes` and a clean sibling git
                                                                                              
fn sibling_fixture() -> (Fixture, std::path::PathBuf) {
    let fx = repo_fixture();
    std::fs::write(
        fx.root.join("repo-manifest.toml"),
        "schema-version = 1\n[repos.recipes]\npath = \"../recipes\"\nartifacts = [\"recipes-app\"]\n",
    )
    .expect("manifest");
    let sibling = fx.ctx.repo_root.to_path_buf().join("../recipes");
    std::fs::create_dir_all(&sibling).expect("sibling dir");
    git_init_baseline(&sibling);
    (fx, sibling)
}

/// A `RunInvocation` whose `--repo-form-dir` holds a ratified `tenant-repo.keys` measured from the
/// sibling checkout, so §1.4's sibling declared-space check passes and a later refusal is the dirt
/// gate's.
fn ratified_inv(fx: &Fixture, sibling: &std::path::Path) -> RunInvocation {
    let repo_form = fx.root.join(".repo-form");
    std::fs::create_dir_all(&repo_form).expect("mk repo-form");
    let body = orchard::ceremony::gate_commit::declared_space_body(sibling)
        .expect("measure the sibling checkout's key set");
    std::fs::write(repo_form.join("tenant-repo.keys"), body).expect("write tenant-repo.keys");
    let mut i = inv(Some("203.0.113.5"));
    i.repo_form_dir = Some(orchard::ceremony::Utf8PathBuf::from(
        repo_form.to_str().expect("utf8 repo-form path"),
    ));
    i
}

                                                                                                   
/// run naming that checkout, BEFORE the sibling overwrite check. The fixture drifts the sibling's
/// configuration AND leaves unrecognized dirt at its declared path, so the two candidate refusals
/// are both live and the returned id names which check ran first: a contract check moved after the
/// dirt scan returns `sibling-content-unrecognized` instead.
#[test]
fn the_sibling_checkouts_declared_space_delta_refuses_before_the_overwrite_check() {
    let (fx, sibling) = sibling_fixture();
    std::fs::write(
        sibling.join("published-pins.toml"),
        format!(
            "schema-version = 1\n\n[artifacts]\nrecipes-app = \"{}\"\n",
            "ab".repeat(32)
        ),
    )
    .expect("dirty sibling");
    let ratified = ratified_inv(&fx, &sibling);
                                                                                     
    git_out(&sibling, &["config", "floor.sib", "1"]);
    let profile = ceremony_profile();
    let reporter = Reporter { porcelain: true };
    let err = sibling_gate(
        step_of(StepId::S6TenantRepin),
        &ratified,
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect_err("a sibling declared-space delta refuses");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .unwrap_or_else(|| panic!("expected a typed Refusal, got: {err}"));
    assert_eq!(
        refusal.to_string(),
        format!(
            "refusal (repository-form-unmodelled): the tenant-repo checkout's declared space differs \
             from the ratified file: added [\"local\\tfloor.sib\"], removed []\n  \
             cure: the tenant-repo checkout's effective git configuration differs from its ratified \
             declared space (the delta is in the detail: keys at every scope, and values at the \
             program-valued keys); revert the configuration, or run `{}` to ratify the \
             shown delta, then re-run",
            ratified.admit_command(&fx.ctx)
        )
    );
}

#[test]
fn the_sibling_gate_proceeds_over_a_clean_tenant_checkout() {
    let (fx, sibling) = sibling_fixture();
    let profile = ceremony_profile();
    let reporter = Reporter { porcelain: true };
    sibling_gate(
        step_of(StepId::S6TenantRepin),
        &ratified_inv(&fx, &sibling),
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect("a clean sibling checkout proceeds");
}

#[test]
fn the_sibling_gate_refuses_an_unrecognized_dirty_tenant_checkout() {
    let (fx, sibling) = sibling_fixture();
    std::fs::write(
        sibling.join("published-pins.toml"),
        "[artifacts]\nrecipes-app = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .expect("dirty sibling");
    let profile = ceremony_profile();
    let reporter = Reporter { porcelain: true };
    let err = sibling_gate(
        step_of(StepId::S6TenantRepin),
        &ratified_inv(&fx, &sibling),
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect_err("unrecognized dirty sibling content refuses");
    let stop = err.downcast_ref::<OwedStop>().expect("an owed stop");
    assert_eq!(stop.refusal.id.token(), "sibling-content-unrecognized");
}

#[test]
fn the_sibling_gate_fails_closed_when_the_tenant_checkout_cannot_be_located() {
                                                                                                  
                                                                                                
                                                                                              
                                                                                                    
                                                                                                 
    let fx = fixture();
    let profile = ceremony_profile();
    let reporter = Reporter { porcelain: true };
    let err = sibling_gate(
        step_of(StepId::S6TenantRepin),
        &inv(Some("203.0.113.5")),
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect_err("an unlocatable tenant checkout fails closed at the sibling gate");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("tenant_repo_root's typed refusal, propagated through the `?`");
    assert_eq!(refusal.id.token(), "repo-manifest-unusable");
}

#[test]
fn tenant_repo_root_refuses_a_manifest_less_or_unnamed_tenant() {
                                                                      
    let fx = fixture();
    let profile = ceremony_profile();
    let err = tenant_repo_root(&fx.ctx, &profile).expect_err("an absent manifest refuses");
    assert_eq!(err.id.token(), "repo-manifest-unusable");
                                                           
    let (fx3, _sibling) = sibling_fixture();
    let mut profile3 = ceremony_profile();
    profile3.tenant_repo = Some("nonesuch".into());
    let err3 = tenant_repo_root(&fx3.ctx, &profile3).expect_err("an unnamed tenant refuses");
    assert_eq!(err3.id.token(), "repo-manifest-unusable");
}

#[test]
fn tenant_repo_root_materializes_the_builtin_when_the_profile_omits_tenant_repo() {
    let (fx, _sibling) = sibling_fixture();
    let mut profile = ceremony_profile();
    profile.tenant_repo = None;
    let root = tenant_repo_root(&fx.ctx, &profile).expect("the builtin resolves via the manifest");
    assert!(
        root.ends_with("recipes"),
        "resolved to the manifest's recipes entry: {}",
        root.display()
    );
}

#[test]
fn admission_refuses_an_absent_tenant_artifacts_and_s6_composes_when_present() {
                                                                                             
                                                                                                    
                                                                                                
                                                                                                    
          
    let fx = fixture();
    let mut records = records_at(&fx);
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());

    let mut absent = complete_profile();
    absent.tenant_artifacts = None;
    let err = admission::admit_with(&i, &fx.ctx, &absent, &records, Measured::default())
        .expect_err("an absent Required param refuses at admission");
    assert_eq!(err.id.token(), "required-param-missing");
    assert!(
        err.detail.contains("tenant_artifacts"),
        "the refusal names the missing param: {}",
        err.detail
    );
    assert!(
        err.cure().as_str().contains("tenant_artifacts") && err.cure().as_str().contains("profile"),
        "the cure names the profile key, not a nonexistent run flag: {}",
        err.cure().as_str()
    );

    let present = complete_profile();
    let values = resolve_values(&i, &present, &fx.ctx);
    let admitted_present =
        admission::admit_with(&i, &fx.ctx, &present, &records, Measured::default())
            .expect("admitted");
    step_completion(
        step_of(StepId::S6TenantRepin),
        &admitted_present,
        &fx.ctx,
        &mut records,
        &i,
    )
    .expect("a present tenant_artifacts completes");
    let composed = child_invocations(
        step_of(StepId::S6TenantRepin),
        &values,
        &i,
        &fx.ctx,
        &records,
    )
    .expect("compose");
    assert!(
        !composed.is_empty(),
        "a present tenant_artifacts composes at least one market upgrade"
    );
}

#[test]
fn admission_enforces_a_late_step_required_param_not_only_s6() {
                                                                                                  
                                                                                                  
                                                                                              
                                                      
    let fx = fixture();
    let records = records_at(&fx);
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let mut no_fp = complete_profile();
    no_fp.host_fingerprint = None;
    let err = admission::admit_with(&i, &fx.ctx, &no_fp, &records, Measured::default())
        .expect_err("an absent late-step Required param refuses at admission");
    assert_eq!(err.id.token(), "required-param-missing");
    assert!(
        err.detail.contains("host_fingerprint"),
        "the refusal names the missing late-step param: {}",
        err.detail
    );
}

                                                                                                   
/// own id and cure (`missing_param_refusal`, resolving the spine's `ParamRecord` by name through
/// `admission::spine_param`), not `StepInputMissing` (whose cure names an artifact an earlier step
/// produces and the records dir), so the two enforcement points hand the operator one instruction.
///
/// Admission-enforce (2026-08-25) catches the absent param first on a normal run, so the backstop
/// is unreachable there and the two admission arms above cannot see it. This arm reaches it by
/// recording S6 DONE — `required_present_params` skips a done step's params, so admission admits
/// the run with the value absent — and then calls the step's own completion directly.
///
/// A REGRESSION PIN, not the closure (D-W22-2). Its unique margin over the census is the cure:
/// dropping the `MissingParam` cure construction leaves the id, and the count, unchanged.
///
/// The S5 backstop (`tenant_source_ref`) is NOT driven here: reaching it requires
/// `handoff::quiescent` over the host-global `HANDOFF_ROOT`, which no fixture can redirect.
#[test]
fn the_s6_step_time_backstop_renders_the_admission_gates_derived_param_cure() {
    use orchard::ceremony::spine::StepId;
                                                                                       
                                                                     
    const CURE: &str = "add `tenant_artifacts` to the profile (the guided interview collects it)";

    let fx = fixture();
    let mut records = records_at(&fx);
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let mut absent = complete_profile();
    absent.tenant_artifacts = None;

                                                                                               
                                                                             
    records
        .record_step(StepRecord {
            step: StepId::S6TenantRepin.token().to_string(),
            run_id: records.run_id().to_string(),
            params: [("tenant_repo".to_string(), "recipes".to_string())].into(),
            input_identities: Default::default(),
            produced: Default::default(),
        })
        .expect("record S6 done");
    let admitted = admission::admit_with(&i, &fx.ctx, &absent, &records, Measured::default())
        .expect("a done S6 does not demand its Required param at admission");

                                                                                         
    assert!(
        admitted.values.get("tenant_artifacts").is_none(),
        "the fixture supplied the param, so the backstop is not what this arm reaches"
    );

    let err = step_completion(
        step_of(StepId::S6TenantRepin),
        &admitted,
        &fx.ctx,
        &mut records,
        &i,
    )
    .expect_err("the step-time backstop refuses an absent tenant_artifacts");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("a typed refusal");
    assert_eq!(refusal.id.token(), "required-param-missing");
    assert!(
        refusal.detail.contains("tenant_artifacts"),
        "the refusal names the missing param: {}",
        refusal.detail
    );
    let render = refusal.to_string();
    let cure = composed_cure_line(&render).expect("a cure line");
    assert_eq!(
        cure, CURE,
        "the composed cure moved: the backstop must render the admission gate's derived cure, \
         which names the PROFILE key and no run flag: {render}"
    );
    for wrong_class in [
        "an artifact an earlier step produces",
        "restore the records dir",
    ] {
        assert!(
            !cure.contains(wrong_class),
            "the cure hands a step-input remedy ({wrong_class:?}) for a missing operator \
             parameter: {render}"
        );
    }
}

/// The resume command a cure carries: from the `orchard run` it names to the cure's end, less the
/// one closing parenthesis a `CureSource::Static` id's render wraps its extra in. The five sites
/// append the command last. A token holding `)` falls outside §2.3's bare set and is therefore
/// single-quoted, so a trailing `)` is the template's and not a value's.
fn resume_in(cure: &str) -> &str {
    let at = cure
        .find("orchard run ")
        .unwrap_or_else(|| panic!("the cure carries no resume command: {cure:?}"));
    let tail = &cure[at..];
    tail.strip_suffix(')').unwrap_or(tail)
}

/// Delta v3.6 §5 row G2's oracle, second half: the tokens the shell handed back, read by the
/// parser that will receive them.
fn parse_printed(tokens: &[String]) -> orchard::cli::Cli {
    use clap::Parser as _;
    let argv: Vec<&str> = std::iter::once("orchard")
        .chain(tokens.iter().map(String::as_str))
        .collect();
    orchard::cli::Cli::try_parse_from(&argv)
        .unwrap_or_else(|e| panic!("the printed resume command does not parse: {e}\n{tokens:?}"))
}

/// Assert `printed` re-types `want` over `ctx`: the shell's own word splitting of the line equals
/// the composed argv, then every `Run` field and every global compared to the value it was
/// composed from, then the two literals an operator reads off the line.
fn assert_resume_re_types(printed: &str, want: &RunInvocation, ctx: &ResolvedContext, label: &str) {
    let dir = want
        .repo_form_dir
        .as_ref()
        .expect("this row's invocations carry a declared-space directory");
    let tokens = shell_split::shell_split(printed);
    assert_eq!(
        tokens,
        want.argv(ctx),
        "{label}: the shell's split of the printed resume command is not argv(ctx): {printed:?}"
    );
    let cli = parse_printed(&tokens);
    assert_eq!(cli.repo_root.as_ref(), Some(&ctx.repo_root), "{label}");
    assert_eq!(
        cli.artifact_store.as_ref(),
        Some(&ctx.artifact_store),
        "{label}"
    );
    assert_eq!(
        cli.repo_manifest.as_ref(),
        Some(&ctx.repo_manifest),
        "{label}"
    );
    assert_eq!(cli.context, None, "{label}: no --context is composed");
    assert!(
        !cli.print_context,
        "{label}: no --print-context is composed"
    );
                                                                                             
                                             
    let orchard::cli::OrchardCmd::Run {
        profile,
        target,
        image_version,
        commit,
        wipe_confirmed,
        porcelain,
        repo_form_dir,
    } = cli.command
    else {
        panic!("{label}: the printed command is not a `run`: {printed:?}");
    };
    assert_eq!(profile, want.profile_path, "{label}");
    assert_eq!(target, want.target, "{label}");
    assert_eq!(
        image_version.map(|v| v.to_string()),
        want.judgment.get("image_version").cloned(),
        "{label}"
    );
    assert_eq!(commit, want.commit, "{label}");
    assert_eq!(wipe_confirmed, want.wipe_confirmed, "{label}");
    assert_eq!(
        porcelain, want.porcelain,
        "{label}: --porcelain is composed iff the field is set"
    );
    assert_eq!(repo_form_dir.as_ref(), Some(dir), "{label}");
    assert!(
        printed.contains(&format!("--repo-form-dir {}", dir.as_str())),
        "{label}: the operator does not read the directory off the line: {printed:?}"
    );
    assert!(
        printed.contains(&format!("--repo-root {}", ctx.repo_root.as_str())),
        "{label}: the operator does not read the repo root off the line: {printed:?}"
    );
}

                                                                                                   
/// `--commit` line is a resume command that re-types the stopped invocation with `--commit` set,
/// over a real untokened headless stop, at both settings of the regime flag.
///
/// What it claims: at `porcelain: false` and at `porcelain: true`, the cure of the owed stop this
/// run produces carries a command whose `/bin/sh` word splitting equals `want.argv(&ctx)` and
/// which clap parses to a `Run` whose every field equals the stopped invocation's with `commit`
/// set, whose globals equal the resolved context, and whose line carries `--repo-form-dir <dir>`
/// and `--repo-root <root>` literally; HEAD is unmoved. The oracles are `/bin/sh` and clap over
/// the printed line, so a change in the composer moves the printed line and this arm alone; the
/// pre-floor form computed the expectation with `inv.with_commit().resume_command(ctx)`, which
                                                                                            
/// claim: the cure's surrounding sentence (`the_gate_cures_are_the_frozen_operator_text`'s), and
/// nothing about the four other emitting sites
/// (`every_printed_resume_command_re_types_the_stopped_invocation`'s). Blind spots, named: a
/// `judgment` key other than `image_version` has no `Run` field; the fixture's paths carry no
/// character outside §2.3's bare set, so the quoting rule is read here only where the composer
/// prints bare (`ceremony_interview.rs`'s row G2 arm drives the quoted classes).
#[test]
fn the_slot_a_cure_carries_the_resume_command_the_runner_composes() {
    let _fd1 = fd1_arm_guard();
    for porcelain in [false, true] {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        i.porcelain = porcelain;
        let label = format!("slot A, porcelain: {porcelain}");
        let _ = dirty_the_declared_pair(&fx, &mut records);
        let reporter = Reporter { porcelain: true };
        let head_before = git_head(&fx.root);
        let prompt = || panic!("no prompt headless");
        let mut exec = FakeExec {
            calls: vec![],
            outcomes: vec![],
        };
        let mut deps = RunnerDeps {
            exec: &mut exec,
            reporter: &reporter,
            lock_token: None,
            is_tty: false,
            prompt: &prompt,
            editor: None,
        };
        let outcome = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps);
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "arm sanity: the untokened headless stop commits nothing"
        );
        let err = outcome.expect_err("headless without the token stops on slot A");
        let stop = err.downcast_ref::<OwedStop>().expect("an owed stop");
        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
        let cure = stop.refusal.cure().as_str().to_string();
        assert!(
            cure.contains("re-run with --commit: orchard run "),
            "the slot-A cure names the --commit route: {cure:?}"
        );
                                                                                                   
                                           
        assert!(!i.commit, "the stopped invocation carries no commit token");
        let mut want = i.clone();
        want.commit = true;
        assert_resume_re_types(resume_in(&cure), &want, &fx.ctx, &label);
    }
}

/// Delta v3.5 §6 row E2 + v3.6 §5 rows G1/G2/G4, the four sites beside the consent gate: the
/// unmet-precondition cure, the typed-gate stop, the step-failed cure and the S5 handoff-quiescence
/// stop each print a resume command that re-types the stopped invocation and the resolved context.
///
/// What it claims: at each of the four sites and at both settings of the regime flag, the command
/// the cure carries word-splits through `/bin/sh` into exactly the composed argv and parses
/// through clap to the stopped invocation's field values (with `wipe_confirmed` set at the typed
/// gate, which amends) and to the context's three paths, and the line carries `--repo-form-dir
/// <dir>` and `--repo-root <root>` literally. Every leg's invocation carries a non-default
/// declared-space directory, so a composer that dropped the flag would send the operator to a
                                                                                  
/// command (the typed-cure suite's), the exit classes (`ceremony_selftests`'), or that these are
/// the only emitting sites; the site set is the delta §0.5 read, frozen by
/// `the_resume_command_call_sites_in_the_crate_are_the_frozen_five`. Blind spots, named:
/// the step-failed leg drives S4's child through the scripted executor, not a real child process;
/// leg (d) reaches its stop through the handoff probe's SHAPE half over the host-global
/// `HANDOFF_ROOT`, so it reads the host filesystem and reds (loudly, naming the cause) on a host
/// carrying a tenant publish tree; the fixtures' paths carry no character outside §2.3's bare set,
/// so the quoting rule is read here only where the composer prints bare.
#[test]
fn every_printed_resume_command_re_types_the_stopped_invocation() {
    for porcelain in [false, true] {
                                                                                                  
                                                                                   
        {
            const UNSAFE_TAG: &str = "-flagshaped:tag";
            let (fx, _records, _admitted, mut i, profile) = gate_fixture();
            i.porcelain = porcelain;
            let records = RunRecords::open_dir(&fx.root.join("boxes/fresh.d"), "run-2")
                .expect("a records set no step is recorded in");
            let values = resolve_values(&i, &profile, &fx.ctx);
            let probe_ctx = ProbeCtx::new(
                &fx.ctx,
                Some(Profile {
                    container_image: Some(UNSAFE_TAG.to_string()),
                    ..profile.clone()
                }),
            );
            let refusal = match step_disposition(
                step_of(StepId::S7ImageBuild),
                &probe_ctx,
                &values,
                &records,
                &Measured::default(),
                &i,
                &fx.ctx,
            ) {
                StepDisposition::Refuse(r) => r,
                other => panic!("expected a plain refusal on an internal step, got {other:?}"),
            };
                                                                                                  
                                          
            assert_eq!(refusal.id.token(), "precondition-unmet");
            assert!(
                refusal.detail.contains("build-container-present"),
                "{}",
                refusal.detail
            );
            let cure = refusal.cure().as_str().to_string();
            let label = format!("unmet precondition, porcelain: {porcelain}");
            assert_resume_re_types(resume_in(&cure), &i, &fx.ctx, &label);
        }

                                                                                   
        {
            let (fx, _records, _admitted, mut i, _profile) = gate_fixture();
            i.porcelain = porcelain;
                                                                                               
            assert!(
                !i.wipe_confirmed,
                "the stopped invocation carries no destructive token"
            );
            let owed = typed_destructive_gate(step_of(StepId::S10ProdInstall), &i, &fx.ctx)
                .expect("the untyped destructive gate stops");
            assert_eq!(owed.kind, OwedKind::TypedGateStop);
            let cure = owed.refusal.cure().as_str().to_string();
            let mut want = i.clone();
            want.wipe_confirmed = true;
            let label = format!("typed gate, porcelain: {porcelain}");
            assert_resume_re_types(resume_in(&cure), &want, &fx.ctx, &label);
        }

                                                                                    
        {
            let fx = repo_fixture();
            let mut records = records_at(&fx);
            let profile = complete_profile();
            let mut i = inv(Some("203.0.113.5"));
            i.judgment.insert("image_version".into(), "3".into());
            i.porcelain = porcelain;
            ratify_at(&fx, &mut i);
            let values = resolve_values(&i, &profile, &fx.ctx);
            let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
            record_done(
                &mut records,
                StepId::S2OperatorKeys,
                &probe_ctx,
                &values,
                &Measured::default(),
            );
            let admitted =
                admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
                    .expect("admitted");
            let mut exec = FakeExec {
                calls: vec![],
                outcomes: vec![
                    ChildOutcome::Ok,
                    ChildOutcome::Ok,
                    ChildOutcome::Failed("vendor: store miss".into()),
                ],
            };
            let reporter = Reporter { porcelain: true };
            let prompt = || panic!("the step fails before any prompt");
            let mut deps = RunnerDeps {
                exec: &mut exec,
                reporter: &reporter,
                lock_token: None,
                is_tty: false,
                prompt: &prompt,
                editor: None,
            };
            let err = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
                .expect_err("the third step fails");
            let refusal = err
                .downcast_ref::<orchard::ceremony::refusal::Refusal>()
                .expect("a typed refusal");
                                                                                               
            assert_eq!(refusal.id.token(), "step-failed");
            assert!(
                refusal.detail.contains("s4-store-vendor"),
                "{}",
                refusal.detail
            );
            let cure = refusal.cure().as_str().to_string();
            let label = format!("step failed, porcelain: {porcelain}");
            assert_resume_re_types(resume_in(&cure), &i, &fx.ctx, &label);
        }

                                                                                            
                                                                                  
                                                                                    
        {
            let (fx, mut records, admitted, mut i, _profile) = gate_fixture();
            i.porcelain = porcelain;
            let root = std::path::Path::new(orchard::ceremony::spine::HANDOFF_ROOT);
            assert!(
                matches!(
                    shape(root),
                    ProbeResult::Unmet(_) | ProbeResult::Unevaluable(_)
                ),
                "the host carries a tenant publish tree at {}, where S5's completion does not \
                 stop; the site reads that path as a constant, so no fixture can redirect it and \
                 this leg asserts nothing until the tree is gone",
                orchard::ceremony::spine::HANDOFF_ROOT
            );
            let err = step_completion(
                step_of(StepId::S5TenantPublish),
                &admitted,
                &fx.ctx,
                &mut records,
                &i,
            )
            .expect_err("the handoff-quiescence probe stops S5's completion");
            let stop = err.downcast_ref::<OwedStop>().expect("an owed stop");
            assert_eq!(stop.kind, OwedKind::ExternalChecklistStop);
                                                                                                  
            assert_eq!(stop.refusal.id.token(), "precondition-unmet");
            assert!(
                stop.refusal.detail.contains("tenant-handoff-quiescent"),
                "{}",
                stop.refusal.detail
            );
            let cure = stop.refusal.cure().as_str().to_string();
            let label = format!("S5 handoff quiescence, porcelain: {porcelain}");
            assert_resume_re_types(resume_in(&cure), &i, &fx.ctx, &label);
        }
    }
}

                                                                                                   
  
                                                                                                  
                                                                                                   
                                                                                                
                                                                                                   
                                                                                                 
                                                                                                   
                                                                                                

/// Every `resume_command(` call expression under `crates/orchard/src/`, as (file relative to that
/// directory, enclosing function, count). Frozen: a sixth site, a lost site, or a site moved to
/// another function reddens the arm and forces a conscious re-freeze with a leg.
const FROZEN_RESUME_SITES: &[(&str, &str, usize)] = &[
    ("ceremony/runner.rs", "executing_gate", 2),
    ("ceremony/runner.rs", "run_ceremony", 1),
    ("ceremony/runner.rs", "step_completion", 1),
    ("ceremony/runner.rs", "step_disposition", 1),
    ("ceremony/runner.rs", "typed_destructive_gate", 1),
];

/// The name a function-declaration line opens, or `None` for any other line. Everything before
/// `fn` must be a visibility or an `async`/`const`/`unsafe`/`extern` qualifier, so a call
/// expression is never read as a declaration.
fn declared_fn(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let at = t.find("fn ")?;
    let head = t[..at].trim_end();
    if !(head.is_empty()
        || head.starts_with("pub")
        || head == "async"
        || head == "const"
        || head == "unsafe"
        || head.starts_with("extern"))
    {
        return None;
    }
    let rest = &t[at + 3..];
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    (end > 0).then(|| &rest[..end])
}

/// The call sites in `files` as (file, enclosing fn, count), sorted, and the number of
/// `fn resume_command(` declarations seen. A comment-only line is dropped; a call outside any
/// function is attributed to `(top level)`, which no frozen entry names.
fn resume_sites(files: &[(String, String)]) -> (Vec<(String, String, usize)>, usize) {
    const NEEDLE: &str = "resume_command(";
    let mut counts: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    let mut definitions = 0usize;
    for (name, text) in files {
        let mut current = "(top level)".to_string();
        for line in text.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if let Some(f) = declared_fn(line) {
                current = f.to_string();
            }
            for (at, _) in line.match_indices(NEEDLE) {
                if line[..at].trim_end().ends_with("fn") {
                    definitions += 1;
                } else {
                    *counts.entry((name.clone(), current.clone())).or_default() += 1;
                }
            }
        }
    }
    let sites = counts
        .into_iter()
        .map(|((f, g), n)| (f, g, n))
        .collect::<Vec<_>>();
    (sites, definitions)
}

/// Every `.rs` file under `crates/orchard/src/`, as (path relative to it, text). Fails closed: a
/// read failure or an implausibly small file set panics rather than scanning nothing and passing.
fn crate_src_files() -> Vec<(String, String)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("read {}: {e}", d.display()))
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p
                    .strip_prefix(&root)
                    .expect("under the scan root")
                    .to_string_lossy()
                    .into_owned();
                let text =
                    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
                out.push((rel, text));
            }
        }
    }
    assert!(
        out.len() >= 15,
        "the scan found {} source files under src/, so it is scanning nothing",
        out.len()
    );
    out.sort();
    out
}

                                                                                      
/// the frozen five, so a sixth cannot appear without a conscious re-freeze.
///
/// What it claims, as the exact model checked: over the non-comment lines of every `.rs` file
/// under `crates/orchard/src/`, the occurrences of the literal `resume_command(` are exactly
/// [`FROZEN_RESUME_SITES`] by (file, enclosing function, count), plus one `fn resume_command(`
/// declaration. What it does NOT claim: anything about what a site composes — a site handing the
/// composer a different invocation keeps this arm green (leg (d)'s M-S5-AMEND is that measure) —
/// nor that the five sites are the only stops that print a command, which is the delta §0.5 read.
/// The model is a literal count: a call reached through an alias, a function pointer, a macro
/// expansion or a re-export is outside it, as writing-floors Principle 2 requires such a claim to
/// be. Blind spots, named: the enclosing function is the last declaration line above the call, so
/// a call inside a nested function is attributed to that nested one; a needle inside a string
/// literal counts as code; the crate's other source trees are outside the scan root.
#[test]
fn the_resume_command_call_sites_in_the_crate_are_the_frozen_five() {
    let (sites, definitions) = resume_sites(&crate_src_files());
    let want: Vec<(String, String, usize)> = FROZEN_RESUME_SITES
        .iter()
        .map(|(f, g, n)| ((*f).to_string(), (*g).to_string(), *n))
        .collect();
    assert_eq!(
        sites, want,
        "the resume-command emitting sites moved; re-freeze consciously, with a driven leg per \
         new site (delta v3.6 §5 row G4)"
    );
    assert_eq!(
        definitions, 1,
        "the crate declares {definitions} `resume_command` functions, so the frozen set above \
         does not name one composer's callers"
    );
}

/// A sample the scanner is measured against: two emitting functions, a declaration, a comment and
/// a doc line naming the needle, and a call attributed to the function above it.
const RESUME_SCANNER_SAMPLE: &str = r#"
/// A doc line naming resume_command( in prose.
pub fn resume_command(&self, ctx: &ResolvedContext) -> String {
    format!("orchard {}", self.argv(ctx).join(" "))
}

pub fn step_disposition(inv: &RunInvocation, ctx: &ResolvedContext) -> Refusal {
    // never spell resume_command( in a comment and expect it counted
    UnmetPrecondition::from_probe(probe, result, Some(inv.resume_command(ctx)))
}

fn executing_gate(inv: &RunInvocation, ctx: &ResolvedContext) -> Gate {
    let resume = inv.resume_command(ctx);
    let resume_with_commit = inv.with_commit().resume_command(ctx);
    Gate { resume, resume_with_commit }
}
"#;

/// Principle 6 self-test: a freeze asserted only against the tree it was written for can be
/// vacuous or unspecific without either showing up.
///
/// What it claims: over one clean sample, the scanner returns exactly the two emitting functions
/// and one declaration, reading neither the declaration line, the comment nor the doc line as a
/// call site; over four planted changes (a sixth site in a new function, a site removed, a second
/// site in an existing function, the call replaced by `None`) the site set moves; and a second
/// declaration is counted. What it does NOT claim: the scanner's attribution over source shapes
/// outside these five samples; the crate scan's own assertion is what reads the tree. Blind spots,
/// named: the samples carry no nested function, no macro-emitted call and no
/// needle inside a string literal, which are the model's stated edges.
#[test]
fn the_resume_site_scanner_is_non_vacuous_and_specific() {
    let clean = vec![("m.rs".to_string(), RESUME_SCANNER_SAMPLE.to_string())];
    let (sites, definitions) = resume_sites(&clean);
    assert_eq!(
        sites,
        vec![
            ("m.rs".to_string(), "executing_gate".to_string(), 2),
            ("m.rs".to_string(), "step_disposition".to_string(), 1),
        ],
        "the scanner is UNSPECIFIC: it reads the declaration, the comment or the doc line as a \
         call site"
    );
    assert_eq!(definitions, 1, "the scanner does not see the declaration");

    for (label, planted) in [
        (
            "a sixth site in a new function",
            format!(
                "{RESUME_SCANNER_SAMPLE}\nfn another_stop(inv: &RunInvocation, ctx: &ResolvedContext) -> String {{\n    inv.resume_command(ctx)\n}}\n"
            ),
        ),
        (
            "one of a function's two sites removed",
            RESUME_SCANNER_SAMPLE.replace("    let resume = inv.resume_command(ctx);\n", ""),
        ),
        (
            "a second site in an existing function",
            RESUME_SCANNER_SAMPLE.replace(
                "    UnmetPrecondition::from_probe(probe, result, Some(inv.resume_command(ctx)))\n",
                "    let _ = inv.resume_command(ctx);\n    UnmetPrecondition::from_probe(probe, result, Some(inv.resume_command(ctx)))\n",
            ),
        ),
        (
            "the site dropped",
            RESUME_SCANNER_SAMPLE.replace(
                "Some(inv.resume_command(ctx))",
                "None",
            ),
        ),
    ] {
        let (planted_sites, _) = resume_sites(&[("m.rs".to_string(), planted)]);
        assert_ne!(
            planted_sites, sites,
            "the scanner is VACUOUS for {label}: the site set did not move"
        );
    }

                                                                                            
    let (_, two) = resume_sites(&[(
        "m.rs".to_string(),
        format!("{RESUME_SCANNER_SAMPLE}\nfn resume_command(x: u8) -> u8 {{ x }}\n"),
    )]);
    assert_eq!(two, 2, "the scanner does not count a second declaration");
}

                                                                                     
/// drives a gate at a terminal — the one regime that emits the disclosure — takes this lock, and
/// the arms that CAPTURE fd 1 take it too. Measured without it: 2 of 3 default (parallel)
/// `cargo test` runs put one arm's disclosure rows into another arm's capture.
static FD1_ARMS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fd1_arm_guard() -> std::sync::MutexGuard<'static, ()> {
    FD1_ARMS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Capture what the process writes to FD 1 while `f` runs. `emit_stdout` writes to the descriptor
                                                                                          
/// arm reading operator-visible text redirects the descriptor.
fn capture_fd1<T>(f: impl FnOnce() -> T) -> (T, String) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let _fd1 = fd1_arm_guard();
    let sink = tempfile::NamedTempFile::new().expect("capture sink");
    let _ = std::io::stdout().flush();
    let saved = unsafe { libc::dup(1) };
    assert!(saved >= 0, "dup(1) failed");
    assert!(
        unsafe { libc::dup2(sink.as_file().as_raw_fd(), 1) } >= 0,
        "dup2 onto fd 1 failed"
    );
    let out = f();
    let _ = std::io::stdout().flush();
    assert!(
        unsafe { libc::dup2(saved, 1) } >= 0,
        "restoring fd 1 failed"
    );
    unsafe { libc::close(saved) };
    let text = std::fs::read_to_string(sink.path()).expect("read the capture");
    (out, text)
}

/// The declared paths a rendered gate record view names, read out of everything the run wrote to
/// fd 1. Reading rule: a row is a line opening with one space that carries the ` [` class column;
/// the path is the text before it, rendered through Debug, so the surrounding quotes are stripped.
/// The footer carries no class column and porcelain records open with no space, so neither reads
/// as a row.
fn disclosure_paths(captured: &str) -> Vec<String> {
    captured
        .lines()
        .filter_map(|l| l.strip_prefix(' '))
        .filter_map(|l| l.split_once(" ["))
        .map(|(p, _)| p.trim_matches('"').to_string())
        .collect()
}

#[test]
fn the_fd1_capture_and_the_disclosure_reader_read_what_the_run_emits() {
                                                                                                     
    let (n, text) = capture_fd1(|| {
        orchard::ceremony::emit::emit_stdout(
            " a/one.toml [recorded by this run] this run 0123456789ab 5 bytes\n\
             step\tstep=s4-store-vendor\taction=run\n\
             \x20two.bin [recorded by a prior run] prior run 1600-9pr 9 bytes\n\
             \x20 2 declared path(s)\n",
        );
        7usize
    });
    assert_eq!(n, 7, "the capture returns the closure's own value");
    assert!(
        text.contains("a/one.toml"),
        "the capture read nothing off fd 1: {text:?}"
    );
    assert_eq!(
        disclosure_paths(&text),
        vec!["a/one.toml".to_string(), "two.bin".to_string()],
        "only the row lines read as rows, and the path stops at the class column"
    );
    assert!(
        disclosure_paths("step\tstep=x\taction=run\n").is_empty(),
        "a porcelain record is not a disclosure row"
    );
}

/// A [`fixture`] whose root is a real repo carrying `crates/image-builder/pinned-cert-fingerprints.toml`
/// as a TRACKED committed baseline, plus an admitted plan whose every step but the gate is done.
                                                                                                    
/// run reaches. Neither declared path is a step's input identity, so dirtying them un-does no
/// recorded step.
fn gate_fixture() -> (
    Fixture,
    RunRecords,
    admission::Admitted,
    RunInvocation,
    Profile,
) {
    let fx = fixture();
    let mut records = records_at(&fx);
    let profile = ceremony_profile();
    let mut i = inv(Some("203.0.113.5"));
    i.judgment.insert("image_version".into(), "3".into());
    let values = resolve_values(&i, &profile, &fx.ctx);
    let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
    for id in [
        StepId::S2OperatorKeys,
        StepId::S5TenantPublish,
        StepId::S6TenantRepin,
        StepId::S7ImageBuild,
        StepId::S8BootGate,
        StepId::S9BoxPreflight,
        StepId::S10ProdInstall,
    ] {
        record_done(&mut records, id, &probe_ctx, &values, &Measured::default());
    }
    let admitted = admission::admit_with(&i, &fx.ctx, &profile, &records, Measured::default())
        .expect("admitted");
    let tracked = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    std::fs::create_dir_all(tracked.parent().expect("parent")).expect("mk crates");
    std::fs::write(&tracked, "a\nb\nc\n").expect("baseline write");
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
        vec!["add", "-A"],
        vec!["commit", "-qm", "baseline"],
    ] {
        git_out(&fx.root, &args);
    }
    let repo_form = fx.root.join(".repo-form");
    std::fs::create_dir_all(&repo_form).expect("mk repo-form");
    let body = orchard::ceremony::gate_commit::declared_space_body(&fx.root)
        .expect("measure the executing checkout's key set");
    std::fs::write(repo_form.join("executing.keys"), body).expect("write executing.keys");
    i.repo_form_dir = Some(orchard::ceremony::Utf8PathBuf::from(
        repo_form.to_str().expect("utf8 repo-form path"),
    ));
    (fx, records, admitted, i, profile)
}

/// Dirty both declared paths of a [`gate_fixture`] and record them as this run's writes: the
/// tracked one as a STAGED modify, the vendor one as an UNTRACKED new file. Returns the relative
/// paths in scan order.
fn dirty_the_declared_pair(fx: &Fixture, records: &mut RunRecords) -> Vec<String> {
    let tracked = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    let untracked = fx.root.join("vendor/x.tar.xz");
    std::fs::create_dir_all(untracked.parent().expect("parent")).expect("mk vendor");
    for path in [&tracked, &untracked] {
        let tok = open_path_record(records, path).expect("open entry");
        std::fs::write(path, "a\nb\nc\nd\n").expect("this run's write");
        finalize_path_record(records, tok).expect("finalize");
    }
    git_out(
        &fx.root,
        &["add", "crates/image-builder/pinned-cert-fingerprints.toml"],
    );
    vec![
        "crates/image-builder/pinned-cert-fingerprints.toml".to_string(),
        "vendor/x.tar.xz".to_string(),
    ]
}

                                                                                                
/// seam RECEIVES. Driven end to end over a real checkout carrying one staged declared path and one
/// untracked declared path — the two shapes the deleted `diff_stat` borrow rendered as nothing —
/// with the disclosure read off fd 1 as the operator sees it.
#[test]
fn the_runners_disclosure_names_exactly_the_paths_its_commit_receives() {
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let expected = dirty_the_declared_pair(&fx, &mut records);
                                                                                                 
                                           
    let admission::DirtScan::Scanned(scanned) = admission::git_dirty_paths(&fx.root) else {
        panic!("the fixture root is a real repo");
    };
    let mut scanned_declared: Vec<String> = scanned
        .into_iter()
        .filter(|p| admission::is_declared(p))
        .collect();
    scanned_declared.sort();
    assert_eq!(
        scanned_declared, expected,
        "the scanned dirty DECLARED set is what the gate must disclose and commit"
    );

    let reporter = Reporter { porcelain: true };
    let head_before = git_head(&fx.root);
    let prompt = || 'y';
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    let (outcome, captured) = capture_fd1(|| {
        run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
            .map_err(|e| e.to_string())
    });
    outcome.unwrap_or_else(|e| panic!("the interactive run commits and reports success: {e}"));

                                                                                                    
                                                    
    assert_ne!(git_head(&fx.root), head_before, "one gate, one commit");
    let committed = git_show_names(&fx.root, "HEAD");
    let disclosed = disclosure_paths(&captured);
    assert_eq!(
        disclosed, expected,
        "the emitted disclosure names one row per owed path: {captured}"
    );
    assert_eq!(
        committed, disclosed,
        "the commit's pathspec is the set the operator was shown, with nothing withheld from \
         either: {captured}"
    );
}

/// CT-2(c), the runner half: a gate whose disclosure refuses reaches no prompt and no commit call.
/// The refusal comes from the production read, not an injected error: `git update-ref -d HEAD`
/// leaves both declared paths dirty for the porcelain scan and makes the render's `git diff HEAD`
/// exit non-zero (measured against real git: `git status --porcelain` still reports `A ` and `??`
/// while `git diff HEAD` answers `fatal: bad revision 'HEAD'`).
#[test]
fn a_gate_whose_disclosure_cannot_be_composed_commits_nothing() {
    let _fd1 = fd1_arm_guard();
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let expected = dirty_the_declared_pair(&fx, &mut records);
    git_out(&fx.root, &["update-ref", "-d", "HEAD"]);
                                                                                                 
                                                                   
    let admission::DirtScan::Scanned(scanned) = admission::git_dirty_paths(&fx.root) else {
        panic!("the fixture root is a real repo");
    };
    let mut scanned_declared: Vec<String> = scanned
        .into_iter()
        .filter(|p| admission::is_declared(p))
        .collect();
    scanned_declared.sort();
    assert_eq!(
        scanned_declared, expected,
        "both declared paths are still dirt"
    );
    let reporter = Reporter { porcelain: true };
    let prompt = || panic!("the prompt is never reached once the gate's git read refuses");
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    let err = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
        .expect_err("a gate whose git read cannot complete refuses");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .expect("the gate's typed git-read refusal");
    assert_eq!(refusal.id.token(), "git-state-unreadable");
                                                                                               
    assert!(
        !std::process::Command::new("git")
            .current_dir(&fx.root)
            .args(["rev-parse", "--verify", "--quiet", "HEAD"])
            .status()
            .expect("git")
            .success(),
        "a gate that could not read git state committed anyway"
    );
}

                                                                                                  
/// no class column (the sibling gate holds no classifier verdict), and a recognized sibling emits
/// its owed command and no disclosure at all.
#[test]
fn the_sibling_refusal_discloses_the_row_for_the_path_it_names() {
    use sha2::{Digest, Sha256};
    let (fx, sibling) = sibling_fixture();
    let profile = ceremony_profile();
    let reporter = Reporter { porcelain: true };

    let bogus = "ab".repeat(32);
    let unrecognized = format!("schema-version = 1\n\n[artifacts]\nrecipes-app = \"{bogus}\"\n");
    std::fs::write(sibling.join("published-pins.toml"), &unrecognized).expect("dirty sibling");
    let ratified = ratified_inv(&fx, &sibling);
    let err = sibling_gate(
        step_of(StepId::S6TenantRepin),
        &ratified,
        &fx.ctx,
        &profile,
        &reporter,
    )
    .expect_err("unrecognized dirty sibling content refuses");
    let stop = err.downcast_ref::<OwedStop>().expect("an owed stop");
    assert_eq!(stop.refusal.id.token(), "sibling-content-unrecognized");
                                                                                        
                                                                                           
    let want_len = unrecognized.len();
    let row = format!(
        " {:?} {want_len} bytes not recognized as ceremony output",
        "published-pins.toml"
    );
    assert!(
        stop.refusal.detail.lines().any(|l| l == row),
        "the refusal discloses the row for the path it names, class column absent: want {row:?} \
         in\n{}",
        stop.refusal.detail
    );
    assert!(
        stop.refusal
            .detail
            .lines()
            .any(|l| l == " 1 declared path(s)"),
        "the record view's path-count footer rides with it: {}",
        stop.refusal.detail
    );

                                                                                                 
                                                   
    let bytes = b"published binary bytes";
    let sha = hex::encode(Sha256::digest(bytes));
    std::fs::write(
        fx.ctx
            .artifact_store
            .to_path_buf()
            .join(format!("recipes-app@{sha}")),
        bytes,
    )
    .expect("store rev");
    std::fs::write(
        sibling.join("published-pins.toml"),
        format!("schema-version = 1\n\n[artifacts]\nrecipes-app = \"{sha}\"\n"),
    )
    .expect("recognized sibling");
    let (outcome, captured) = capture_fd1(|| {
        sibling_gate(
            step_of(StepId::S6TenantRepin),
            &ratified,
            &fx.ctx,
            &profile,
            &reporter,
        )
        .map_err(|e| e.to_string())
    });
    outcome.expect("recognized ceremony output proceeds");
    assert!(
        captured.contains("git -C") && captured.contains("published-pins.toml"),
        "the owed sibling commit command is printed: {captured}"
    );
    assert!(
        disclosure_paths(&captured).is_empty() && !captured.contains("declared path(s)"),
        "a recognized sibling is not disclosed: {captured}"
    );
}

/// A throwaway executable "editor": a shell script receiving the message file as `$1`.
fn editor_script(body: &str) -> tempfile::TempPath {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let mut f = tempfile::NamedTempFile::new().expect("script file");
    f.write_all(format!("#!/bin/sh\n{body}").as_bytes())
        .expect("write script");
    f.flush().expect("flush");
    let path = f.into_temp_path();
    let mut perm = std::fs::metadata(&path).expect("stat").permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm).expect("chmod");
    path
}

/// What `run_ceremony` answered.
type RunOutcome = Result<(), Box<dyn std::error::Error>>;

/// Run one gate to completion with the given prompt keystroke and editor seam, returning what the
/// run answered, the landed commit's message when HEAD advanced (`None` when nothing committed),
/// and the fixture's tempdir root (the resume command in a cure now embeds it, so a cure compared
/// across two fixtures is normalized against this).
/// Re-targeted off the recording seam onto the real checkout (the fixture is read before it drops).
fn run_gate_with(
    keystroke: char,
    editor: Option<&std::ffi::OsStr>,
) -> (RunOutcome, Option<String>, String) {
    let _fd1 = fd1_arm_guard();
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let _ = dirty_the_declared_pair(&fx, &mut records);
    let reporter = Reporter { porcelain: true };
    let head_before = git_head(&fx.root);
    let prompt = move || keystroke;
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor,
    };
    let outcome = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps);
    let landed = (git_head(&fx.root) != head_before).then(|| git_log_message(&fx.root, "HEAD"));
    let tmp_root = fx
        .root
        .parent()
        .expect("the fixture root has a tempdir parent")
        .display()
        .to_string();
    (outcome, landed, tmp_root)
}

                                                                                                
/// gestures the runner can drive through its seam are no `$EDITOR` and an editor that empties the
/// message; an editor that rewrites it commits the rewritten message. The abort's cure is the same
/// text the declined slot composes, read from a `n` run over the same fixture rather than a literal.
#[test]
fn an_aborted_message_edit_commits_nothing_and_owes_the_declined_slots_cure() {
                                                                                                    
                                                                                                  
                                                           
    let normalize = |cure: &str, root: &str| cure.replace(root, "<ROOT>");
    let (declined, no_commit, declined_root) = run_gate_with('n', None);
    assert!(
        no_commit.is_none(),
        "arm sanity: `n` commits nothing: {no_commit:?}"
    );
    let declined_cure = {
        let err = declined.expect_err("`n` stops the run");
        let stop = err.downcast_ref::<OwedStop>().expect("an owed stop");
        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
        normalize(stop.refusal.cure().as_str(), &declined_root)
    };

    for (label, editor) in [
        ("no $EDITOR", None),
        (
            "an editor that empties the message",
            Some(editor_script("printf '' > \"$1\"\n")),
        ),
    ] {
        let (outcome, landed, abort_root) =
            run_gate_with('e', editor.as_ref().map(|p| p.as_os_str()));
        assert!(
            landed.is_none(),
            "{label}: the abort committed anyway: {landed:?}"
        );
        let err = outcome.expect_err("{label}: an aborted edit stops the run");
        let stop = err
            .downcast_ref::<OwedStop>()
            .unwrap_or_else(|| panic!("{label}: expected an owed stop, got: {err}"));
        assert_eq!(stop.kind, OwedKind::ConsentGateStop);
        assert!(
            stop.refusal.detail.contains("the message edit aborted"),
            "{label}: the stop names the abort: {}",
            stop.refusal.detail
        );
        assert_eq!(
            normalize(stop.refusal.cure().as_str(), &abort_root),
            declined_cure,
            "{label}: the abort owes the cure its declined slot composes"
        );
    }
}

/// CT-3(b): `e` with an editor that rewrites the message commits the EDITED text, so the abort arm
/// above is the abort's doing and not a gate that never commits after `e`.
#[test]
fn an_edited_message_commits_the_text_the_editor_wrote() {
    let rewriter = editor_script("printf 'operator wrote this' > \"$1\"\n");
    let (outcome, landed, _root) = run_gate_with('e', Some(rewriter.as_os_str()));
    outcome
        .unwrap_or_else(|e| panic!("an edited message commits and the run reports success: {e}"));
    assert_eq!(
        landed.as_deref(),
        Some("operator wrote this"),
        "the landed commit carries the editor's text (trimmed), not the composed base"
    );
}

/// [`dirty_the_declared_pair`] with the vendor member made EXECUTABLE before its finalize, so its
/// witness carries an exec bit the landed tree has to carry too. `core.fileMode=true` is pinned on
/// the fixture, so git's exec domain here is the worktree bit and does not depend on the host's
/// default (the index-mode branch is the records arm's).
fn dirty_the_declared_pair_with_an_executable(
    fx: &Fixture,
    records: &mut RunRecords,
) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt as _;
    git_out(&fx.root, &["config", "core.fileMode", "true"]);
    let tracked = fx
        .root
        .join("crates/image-builder/pinned-cert-fingerprints.toml");
    let untracked = fx.root.join("vendor/x.tar.xz");
    std::fs::create_dir_all(untracked.parent().expect("parent")).expect("mk vendor");
    for (path, exec) in [(&tracked, false), (&untracked, true)] {
        let tok = open_path_record(records, path).expect("open entry");
        std::fs::write(path, "a\nb\nc\nd\n").expect("this run's write");
        if exec {
            let mut perm = std::fs::metadata(path).expect("stat").permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(path, perm).expect("chmod +x");
        }
        finalize_path_record(records, tok).expect("finalize");
    }
    git_out(
        &fx.root,
        &["add", "crates/image-builder/pinned-cert-fingerprints.toml"],
    );
    vec![
        "crates/image-builder/pinned-cert-fingerprints.toml".to_string(),
        "vendor/x.tar.xz".to_string(),
    ]
}

/// The mode and object type `git ls-tree` reports at HEAD for one path; `None` when HEAD carries no
/// entry. The test-side oracle for what landed, read from git rather than from the code under
/// test.
fn landed_entry(root: &Path, rel: &str) -> Option<(String, String)> {
    let raw = git_out(root, &["ls-tree", "HEAD", "--", rel]);
    let line = raw.lines().next()?;
    let (meta, _) = line.split_once('\t')?;
    let mut f = meta.split_whitespace();
    Some((f.next()?.to_string(), f.next()?.to_string()))
}

fn landed_bytes(root: &Path, rel: &str) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["cat-file", "blob", &format!("HEAD:{rel}")])
        .output()
        .expect("git cat-file");
    assert!(
        out.status.success(),
        "cat-file HEAD:{rel}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// The run's own deps, headless with the forwarded `--commit` token and a prompt that panics.
fn headless_token_deps<'a>(
    reporter: &'a Reporter,
    exec: &'a mut FakeExec,
    prompt: &'a dyn Fn() -> char,
) -> RunnerDeps<'a> {
    RunnerDeps {
        exec,
        reporter,
        lock_token: None,
        is_tty: false,
        prompt,
        editor: None,
    }
}

                                                                                             
/// content commits EXACTLY the recorded bytes and exec bit, and the chokepoint's landed re-verify
/// passes over the real commit. The oracle is git's own tree (`ls-tree` mode + type, `cat-file`
/// bytes) against the literal bytes the fixture wrote — never a value the ceremony computed.
#[test]
fn a_headless_commit_run_lands_exactly_the_recorded_bytes_and_exec() {
    const BYTES: &[u8] = b"a\nb\nc\nd\n";
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair_with_an_executable(&fx, &mut records);
    i.commit = true;
    let before_head = git_head(&fx.root);
    let reporter = Reporter { porcelain: true };
    let prompt = || panic!("the forwarded token commits an all-recorded set with no prompt");
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = headless_token_deps(&reporter, &mut exec, &prompt);
    run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps).unwrap_or_else(|e| {
        panic!("the token commits the recorded set and the verify passes: {e}")
    });

    assert_ne!(
        before_head,
        git_head(&fx.root),
        "one gate, one commit really landed"
    );
    for (rel, want_mode) in [(&owed[0], "100644"), (&owed[1], "100755")] {
        let (mode, otype) = landed_entry(&fx.root, rel).unwrap_or_else(|| {
            panic!("HEAD carries no entry for {rel}");
        });
        assert_eq!(otype, "blob", "{rel} landed as {otype}");
        assert_eq!(
            mode, want_mode,
            "{rel} landed with git's mode for the recorded exec bit"
        );
        assert_eq!(
            landed_bytes(&fx.root, rel),
            BYTES,
            "{rel} landed exactly the bytes the ceremony recorded writing"
        );
    }
}

/// `--no-commit --no-ff` writes MERGE_HEAD and stages nothing (measured, git 2.55.0), so the
/// declared paths stay the only dirt the gate sees.
fn start_a_merge(root: &Path) {
    git_out(root, &["checkout", "-q", "-b", "r15-merge-side"]);
    git_out(
        root,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "an unrelated side commit",
        ],
    );
    git_out(root, &["checkout", "-q", "-"]);
    git_out(root, &["merge", "--no-commit", "--no-ff", "r15-merge-side"]);
}

/// Leave the fixture repo mid-cherry-pick. `cherry-pick -n` writes no CHERRY_PICK_HEAD (measured,
/// git 2.55.0), so the state needs a pick that conflicts; the conflict is at an UNDECLARED path, so
/// the gate's owed set is still exactly the declared pair.
fn start_a_cherry_pick(root: &Path) {
    std::fs::write(root.join("unrelated.txt"), "base\n").expect("write");
    git_out(root, &["add", "--", "unrelated.txt"]);
    git_out(root, &["commit", "-qm", "an unrelated baseline"]);
    git_out(root, &["checkout", "-q", "-b", "r15-pick-side"]);
    std::fs::write(root.join("unrelated.txt"), "side\n").expect("write");
    git_out(root, &["commit", "-qam", "a side edit"]);
    git_out(root, &["checkout", "-q", "-"]);
    std::fs::write(root.join("unrelated.txt"), "mainline\n").expect("write");
    git_out(root, &["commit", "-qam", "a mainline edit"]);
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["cherry-pick", "r15-pick-side"])
        .output()
        .expect("git cherry-pick");
    assert!(
        !out.status.success(),
        "the pick has to conflict to leave CHERRY_PICK_HEAD: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

                                                                                                  
/// prompt, because git refuses a partial (pathspec) commit in either state and the ceremony's
/// commit would die post-consent. Driven end to end over real git states, at a terminal with no
/// token, so the prompt is what the guard runs ahead of.
#[test]
fn a_merge_or_a_cherry_pick_in_progress_refuses_the_partial_commit_before_the_prompt() {
    type Start = fn(&Path);
    for (label, marker, start) in [
        ("merge", "MERGE_HEAD", start_a_merge as Start),
        (
            "cherry-pick",
            "CHERRY_PICK_HEAD",
            start_a_cherry_pick as Start,
        ),
    ] {
        let _fd1 = fd1_arm_guard();
        let (fx, mut records, admitted, i, profile) = gate_fixture();
        start(&fx.root);
        let owed = dirty_the_declared_pair(&fx, &mut records);
                                                                                               
                                                                                             
        let marker_path = fx
            .root
            .join(git_out(&fx.root, &["rev-parse", "--git-path", marker]));
        assert!(
            marker_path.exists(),
            "{label}: git left no {marker} at {}",
            marker_path.display()
        );
        for rel in &owed {
            assert_eq!(
                classify_executing_dirt(&records, &fx.root.join(rel)),
                DirtClass::CleanOrRecorded,
                "{label}: {rel} is this run's recorded content"
            );
        }
        let head_before = git_head(&fx.root);
        let reporter = Reporter { porcelain: true };
        let prompt = || panic!("{label}: the marker refusal is pre-prompt");
        let mut exec = FakeExec {
            calls: vec![],
            outcomes: vec![],
        };
        let mut deps = RunnerDeps {
            exec: &mut exec,
            reporter: &reporter,
            lock_token: None,
            is_tty: true,
            prompt: &prompt,
            editor: None,
        };
        let err =
            run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps).unwrap_err();
        let refusal = err
            .downcast_ref::<orchard::ceremony::refusal::Refusal>()
            .unwrap_or_else(|| panic!("{label}: expected the typed refusal, got: {err}"));
        assert_eq!(refusal.id.token(), "partial-commit-blocked");
        assert!(
            refusal.detail.contains(&format!("{label} is in progress")),
            "{label}: the refusal names the state it read: {}",
            refusal.detail
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "{label}: HEAD moved under a refusal"
        );
    }
}

                                                                                                
/// lands nothing refuses pre-prompt; one untracked new member is enough to make the set land
/// something; and a sibling checkout whose declared path lands nothing still refuses with the
/// SIBLING id, never with the executing gate's.
#[test]
fn the_emptiness_refusal_is_the_executing_gates_and_the_sibling_gate_keeps_its_own_id() {
    /// A tracked declared path that is dirty and lands nothing: the index holds an edit, the
    /// worktree holds HEAD's bytes, and the ceremony recorded writing exactly those bytes.
    fn stage_then_revert(root: &Path, rel: &str, head_bytes: &str) {
        let p = root.join(rel);
        std::fs::write(&p, "a staged edit\n").expect("staged edit");
        git_out(root, &["add", "--", rel]);
        std::fs::write(&p, head_bytes).expect("worktree back to HEAD");
    }

                                         
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let rel = "crates/image-builder/pinned-cert-fingerprints.toml";
    let path = fx.root.join(rel);
    let tok = open_path_record(&mut records, &path).expect("open entry");
    stage_then_revert(&fx.root, rel, "a\nb\nc\n");
    finalize_path_record(&mut records, tok).expect("finalize");
                                                                                          
    assert!(
        git_out(&fx.root, &["status", "--porcelain", "--", rel]).contains(rel),
        "the path is owed dirt"
    );
    assert_eq!(
        git_out(&fx.root, &["diff", "HEAD", "--name-only", "--", rel]),
        "",
        "and it lands nothing against HEAD"
    );
    assert_eq!(
        classify_executing_dirt(&records, &path),
        DirtClass::CleanOrRecorded,
        "and the ceremony's own record speaks for the bytes it holds"
    );
    let reporter = Reporter { porcelain: true };
    let head_before = git_head(&fx.root);
    let prompt = || panic!("the emptiness refusal is pre-prompt");
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    let err = run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
        .expect_err("an all-lands-nothing owed set refuses");
    let refusal = err
        .downcast_ref::<orchard::ceremony::refusal::Refusal>()
        .unwrap_or_else(|| panic!("expected the typed refusal, got: {err}"));
    assert_eq!(refusal.id.token(), "commit-preview-empty");
    assert_eq!(git_head(&fx.root), head_before, "nothing was committed");

                                                                             
    let (fx2, mut records2, admitted2, mut i2, profile2) = gate_fixture();
    let path2 = fx2.root.join(rel);
    let tok2 = open_path_record(&mut records2, &path2).expect("open entry");
    stage_then_revert(&fx2.root, rel, "a\nb\nc\n");
    finalize_path_record(&mut records2, tok2).expect("finalize");
    let untracked = fx2.root.join("vendor/x.tar.xz");
    std::fs::create_dir_all(untracked.parent().expect("parent")).expect("mk vendor");
    let tok3 = open_path_record(&mut records2, &untracked).expect("open entry");
    std::fs::write(&untracked, "new file bytes\n").expect("write");
    finalize_path_record(&mut records2, tok3).expect("finalize");
    i2.commit = true;
    let reporter2 = Reporter { porcelain: true };
    let head_before2 = git_head(&fx2.root);
    let prompt2 = || panic!("no prompt under the forwarded token");
    let mut exec2 = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps2 = headless_token_deps(&reporter2, &mut exec2, &prompt2);
    run_ceremony(
        &admitted2,
        &i2,
        &fx2.ctx,
        &profile2,
        &mut records2,
        &mut deps2,
    )
    .unwrap_or_else(|e| panic!("a set holding one new file is not empty: {e}"));
    assert_ne!(git_head(&fx2.root), head_before2, "the mixed set commits");

                                                                                     
    let (fx3, sibling) = sibling_fixture();
    let pins = "published-pins.toml";
    let body = format!(
        "schema-version = 1\n\n[artifacts]\nrecipes-app = \"{}\"\n",
        "ab".repeat(32)
    );
    std::fs::write(sibling.join(pins), &body).expect("write pins");
    git_out(&sibling, &["add", "-A"]);
    git_out(&sibling, &["commit", "-qm", "pins"]);
    stage_then_revert(&sibling, pins, &body);
    assert_eq!(
        git_out(&sibling, &["diff", "HEAD", "--name-only", "--", pins]),
        "",
        "arm sanity: the sibling's declared path lands nothing against its own HEAD"
    );
    let profile3 = ceremony_profile();
    let reporter3 = Reporter { porcelain: true };
    let err3 = sibling_gate(
        step_of(StepId::S6TenantRepin),
        &ratified_inv(&fx3, &sibling),
        &fx3.ctx,
        &profile3,
        &reporter3,
    )
    .expect_err("unrecognized sibling content refuses");
    let stop = err3.downcast_ref::<OwedStop>().expect("an owed stop");
    assert_eq!(
        stop.refusal.id.token(),
        "sibling-content-unrecognized",
        "the executing gate's emptiness id must not displace the sibling refusal"
    );
}

                                                                                          
/// emitted block is asserted — one row per owed path with its class phrase, run attribution, sha256
/// prefix and byte count, the path-count footer, and the discard note — against oracles the test
/// computes itself (sha2 over the bytes it wrote, the file's own length, the records handle's run
/// id). A re-wording anywhere in the composition reds it.
#[test]
fn the_record_view_the_operator_reads_is_composed_from_the_records() {
    use sha2::{Digest, Sha256};
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    let bytes = b"a\nb\nc\nd\n";
    let sha12: String = hex::encode(Sha256::digest(bytes))
        .chars()
        .take(12)
        .collect();
    let len = bytes.len();
                                                                             
    for rel in &owed {
        assert_eq!(
            classify_executing_dirt(&records, &fx.root.join(rel)),
            DirtClass::CleanOrRecorded,
            "{rel} is this run's recorded content"
        );
    }
    let expected = format!(
        " {tracked:?} [recorded by this run] this run {sha12} {len} bytes\n \
         {vendor:?} [recorded by this run] this run {sha12} {len} bytes\n \
         2 declared path(s)\n staged edit(s) the commit overwrites: {discards:?}",
        tracked = owed[0],
        vendor = owed[1],
        discards = std::collections::BTreeSet::from([owed[0].clone()]),
    );

    let reporter = Reporter { porcelain: true };
    let prompt = || 'y';
    let mut exec = FakeExec {
        calls: vec![],
        outcomes: vec![],
    };
    let mut deps = RunnerDeps {
        exec: &mut exec,
        reporter: &reporter,
        lock_token: None,
        is_tty: true,
        prompt: &prompt,
        editor: None,
    };
    let (outcome, captured) = capture_fd1(|| {
        run_ceremony(&admitted, &i, &fx.ctx, &profile, &mut records, &mut deps)
            .map_err(|e| e.to_string())
    });
    outcome.unwrap_or_else(|e| panic!("the interactive run commits: {e}"));
    assert!(
        captured.contains(&expected),
        "the composed record view moved.\nwant:\n{expected}\ngot:\n{captured}"
    );
    assert_eq!(
        disclosure_paths(&captured),
        owed,
        "one row per owed path and no other row-shaped line: {captured}"
    );
}
