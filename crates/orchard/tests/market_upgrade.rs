//! `market upgrade` stage-then-swap ATOMICITY self-test (AC5). The executor's contract is: every step's
//! effect lands in a temp stage, `market verify` runs against the staged result, and the real trees + the
//! shared artifact-store are touched ONLY by the final swap — which runs ONLY on full green. A failure at any
//! step OR at the staged verify must leave every tree byte-identical to the pre-run state.
//!
//! These tests drive the REAL `Stage` + swap against a real fixture tree, faking only the (docker/network)
//! step effect and INJECTING the verify verdict — so the security property (swap ⇔ verify-green, fail ⇒
//! untouched) is proven directly + decoupled from the build machinery. The overlay primitives (read-through,
//! stage-write isolation, tree-replace) are unit-tested white-box in `src/deploy/market_exec.rs`.
//!
                                                                                                            
//! (co-located like the armed gate does), real record loop, real swap — against a grocer-publishable
//! fixture eco; ONLY the staged-verify verdict is injected (the canonical-shape verify cannot run on a
//! synthetic eco; the armed grocer gate covers it on the real one).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use orchard::deploy::git_commit::{Consent, UpgradeFlags, compose_message, consent_from};
use orchard::deploy::market_exec::{ShellStepExec, Stage, StepExec, StoreLayout, execute};
use orchard::deploy::market_upgrade::{Step, Target, UpgradeError};
use recipes_image_builder::artifact_store::{ArtifactStore, DirStore};
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};

/// A fake step executor: stages a set of `(real_target, content)` writes into the overlay (mimicking a
/// publish/re-pin), or fails outright (mimicking a publish.sh non-zero exit). Never touches a real path.
struct FakeExec {
    writes: Vec<(PathBuf, String)>,
    fail: bool,
}

impl StepExec for FakeExec {
    fn exec(&mut self, _step: &Step, stage: &mut Stage) -> Result<(), UpgradeError> {
        if self.fail {
            return Err(UpgradeError::StepFailed {
                step: "fake".into(),
                detail: "forced step failure".into(),
            });
        }
        for (real, content) in &self.writes {
            let staged = stage.stage_write(real)?;
            std::fs::write(staged, content)?;
        }
        Ok(())
    }
}

/// A minimal real ecosystem: `<base>/eco/orchard` (+ vendor/) and a sibling `seed-vault/published-pins.toml`
/// holding `"orig"`. Returns the layout + the real published-pins path to assert against.
fn fixture() -> (tempfile::TempDir, StoreLayout, PathBuf) {
    let base = tempfile::tempdir().unwrap();
    let orchard = base.path().join("eco/orchard");
    std::fs::create_dir_all(orchard.join("vendor")).unwrap();
    std::fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
    std::fs::write(orchard.join("repo-manifest.toml"), "schema-version = 1\n").unwrap();
    let sib = base.path().join("eco/seed-vault");
    std::fs::create_dir_all(&sib).unwrap();
    let pub_pins = sib.join("published-pins.toml");
    std::fs::write(&pub_pins, "orig").unwrap();
    let layout = StoreLayout {
        orchard_root: orchard,
        store: base.path().join("eco/artifact-store"),
        repos: BTreeMap::from([("seed-vault".to_string(), sib)]),
        cert_trail: None,
    };
    (base, layout, pub_pins)
}

#[test]
fn fail_before_swap_leaves_trees_untouched() {
    let (_base, layout, pub_pins) = fixture();
    let steps = vec![Step::Publish {
        repo: "seed-vault".into(),
        binary: None,
    }];
    let mut exec = FakeExec {
        writes: vec![(pub_pins.clone(), "NEW".into())],
        fail: false,
    };
                                                                                                                
    let verify = |_: &Stage| Err(UpgradeError::StagedVerify("forced fail".into()));
    let err = execute(&steps, &layout, &mut exec, &verify).unwrap_err();
    assert!(
        matches!(err, UpgradeError::StagedVerify(_)),
        "a staged-verify failure must abort BEFORE the swap, got {err:?}"
    );
                                                                                               
    assert_eq!(
        std::fs::read_to_string(&pub_pins).unwrap(),
        "orig",
        "fail-before-swap must leave the real tree untouched"
    );
}

#[test]
fn step_failure_before_verify_leaves_trees_untouched() {
    let (_base, layout, pub_pins) = fixture();
    let steps = vec![Step::Vendor];
                                                                                        
    let mut exec = FakeExec {
        writes: vec![],
        fail: true,
    };
    let verify = |_: &Stage| Ok(());                                                                 
    let err = execute(&steps, &layout, &mut exec, &verify).unwrap_err();
    assert!(
        matches!(err, UpgradeError::StepFailed { .. }),
        "got {err:?}"
    );
    assert_eq!(std::fs::read_to_string(&pub_pins).unwrap(), "orig");
}

#[test]
fn green_verify_swaps_staged_into_place() {
    let (_base, layout, pub_pins) = fixture();
    let steps = vec![Step::Publish {
        repo: "seed-vault".into(),
        binary: None,
    }];
    let mut exec = FakeExec {
        writes: vec![(pub_pins.clone(), "NEW".into())],
        fail: false,
    };
                                                                                               
    let verify = |_: &Stage| Ok(());
    let report = execute(&steps, &layout, &mut exec, &verify).unwrap();
    assert_eq!(
        std::fs::read_to_string(&pub_pins).unwrap(),
        "NEW",
        "a green verify must swap the staged result into place"
    );
    assert!(
        report.swapped.iter().any(|p| p == &pub_pins),
        "the swapped set must name the published-pins.toml, got {:?}",
        report.swapped
    );
}

                                                                                                       

/// Build the REAL `grocer` binary once and co-locate it beside this test exe, so the executor's
/// production `current_exe().parent()/grocer` resolution finds it (the armed gate's mechanism).
fn colocated_grocer() -> &'static Path {
    static GROCER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    GROCER
        .get_or_init(|| {
            let status = Command::new(env!("CARGO"))
                .args(["build", "-p", "grocer"])
                .status()
                .expect("spawn `cargo build -p grocer`");
            assert!(status.success(), "`cargo build -p grocer` failed");
            let me = std::env::current_exe().expect("current_exe");
            let deps = me.parent().expect("test exe has no parent (deps/)");
            let built = deps
                .parent()
                .expect("deps/ has no parent (target/debug)")
                .join("grocer");
            assert!(built.is_file(), "grocer missing at {}", built.display());
            let dst = deps.join("grocer");
            let _ = std::fs::remove_file(&dst);
            std::fs::copy(&built, &dst).expect("co-locate grocer beside the test exe");
            dst
        })
        .as_path()
}

/// Run `git args` in `cwd`, asserting success (the fixture seed-vault must be a clean git repo for
/// grocer's untracked-guard).
fn git(args: &[&str], cwd: &Path) {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        cwd.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A grocer-PUBLISHABLE fixture eco: the market_upgrade fixture extended with a real (committed)
/// seed-vault carrying `crates/grape` + a publish-manifest, a valid consume/repo manifest pair for
/// the ONE source key, and an existing (empty) store dir.
fn publishable_fixture() -> (tempfile::TempDir, StoreLayout) {
    let base = tempfile::tempdir().unwrap();
    let orchard = base.path().join("eco/orchard");
    std::fs::create_dir_all(orchard.join("vendor")).unwrap();
    std::fs::write(
        orchard.join("consume-pins.toml"),
        format!(
            "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{}\"\nkind = \"source\"\n",
            "0".repeat(64)
        ),
    )
    .unwrap();
    std::fs::write(
        orchard.join("repo-manifest.toml"),
        "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n",
    )
    .unwrap();
    let sib = base.path().join("eco/seed-vault");
    std::fs::create_dir_all(sib.join("crates/grape/src")).unwrap();
    std::fs::write(sib.join("crates/grape/src/lib.rs"), "// rev-A\n").unwrap();
    std::fs::write(
        sib.join("publish-manifest.toml"),
        "schema-version = 1\n[[artifact]]\nkey = \"grape-src\"\nkind = \"source\"\nsource = \"crates/grape\"\n",
    )
    .unwrap();
    std::fs::write(
        sib.join("published-pins.toml"),
        "schema-version = 1\n[artifacts]\n",
    )
    .unwrap();
    git(&["init", "-q"], &sib);
    git(&["config", "user.email", "cas@test"], &sib);
    git(&["config", "user.name", "cas-test"], &sib);
    git(&["add", "-A"], &sib);
    git(&["commit", "-q", "-m", "rev-A"], &sib);
    let store = base.path().join("eco/artifact-store");
    std::fs::create_dir_all(&store).unwrap();
    let layout = StoreLayout {
        orchard_root: orchard,
        store,
        repos: BTreeMap::from([("seed-vault".to_string(), sib)]),
        cert_trail: None,
    };
    (base, layout)
}

/// Run ONE real publish of seed-vault through `execute()` (real grocer + real record loop + real
/// swap; verify verdict injected green) and return the sha the staged publish pinned.
fn publish_through_execute(layout: &StoreLayout) -> String {
    let _ = colocated_grocer();
    let manifest = RepoManifest::load(&layout.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&layout.orchard_root.join("consume-pins.toml")).unwrap();
    let steps = vec![Step::Publish {
        repo: "seed-vault".into(),
        binary: None,
    }];
    let mut exec = ShellStepExec {
        layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let verify = |_: &Stage| Ok(());
    execute(&steps, layout, &mut exec, &verify).expect("the publish must reach the swap");
                                                                                 
    let pub_text =
        std::fs::read_to_string(layout.repos["seed-vault"].join("published-pins.toml")).unwrap();
    let doc: toml::Value = toml::from_str(&pub_text).unwrap();
    doc.get("artifacts")
        .and_then(|a| a.get("grape-src"))
        .and_then(|v| v.as_str())
        .expect("post-swap published-pins carries grape-src")
        .to_string()
}

#[test]
fn parallel_publishes_coexist_in_one_store() {
                                                                                                  
                                                                                                 
                                                                                                   
                                                                                                   
                                                                                                
                                                                                              
                                                                                            
    let (_base, layout) = publishable_fixture();

                                                  
    let sha_a = publish_through_execute(&layout);
    let rev_a_path = layout.store.join(format!("grape-src@{sha_a}"));
    let rev_a_bytes = std::fs::read(&rev_a_path)
        .expect("the production path must land the @sha revision in the real store");

                                                                                            
    let sib = &layout.repos["seed-vault"];
    std::fs::write(sib.join("crates/grape/src/lib.rs"), "// rev-B\n").unwrap();
    git(&["add", "-A"], sib);
    git(&["commit", "-q", "-m", "rev-B"], sib);
    let sha_b = publish_through_execute(&layout);
    assert_ne!(sha_a, sha_b, "the mutation must change the source tar sha");

                                                                                      
    assert_eq!(
        std::fs::read(&rev_a_path).unwrap(),
        rev_a_bytes,
        "rev-A's revision must be byte-identical after rev-B's publish"
    );
                                                                                          
    let store = DirStore::new(&layout.store);
    assert_eq!(
        store
            .fetch_verified("grape-src", &sha_a)
            .expect("branch A's pin must stay green")
            .sha256(),
        sha_a
    );
    assert_eq!(
        store
            .fetch_verified("grape-src", &sha_b)
            .expect("branch B's pin must be green")
            .sha256(),
        sha_b
    );
}

#[test]
fn no_code_path_deletes_from_the_store() {
                                                                                                       
                                                                                               
                         
    let (_base, layout) = publishable_fixture();
                                                                                             
                                                          
    std::fs::write(layout.store.join("stale-bin"), b"OLD-BINARY").unwrap();
    std::fs::write(
        layout.store.join(format!("grape-src@{}", "e".repeat(64))),
        b"STALE-REV",
    )
    .unwrap();
    std::fs::write(layout.store.join("junk@bad@name"), b"JUNK").unwrap();

    let names = |dir: &Path| -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let before = names(&layout.store);
    publish_through_execute(&layout);
    let after = names(&layout.store);
    assert!(
        after.is_superset(&before),
        "the store must be STRICTLY additive across a publish→swap cycle — missing: {:?}",
        before.difference(&after).collect::<Vec<_>>()
    );
    assert!(
        after.len() > before.len(),
        "the publish must have ADDED names (the @sha revision + alias), got {after:?}"
    );
    assert_eq!(
        std::fs::read(layout.store.join("stale-bin")).unwrap(),
        b"OLD-BINARY",
        "an unrelated store file must survive a publish byte-identical"
    );
}

                                                                                                        

/// The tracked config-file bytes the fixture publishes (a small verbatim config, like a real
/// `deploy/epa.json`). Its sha256 is the pin the leg lands.
const EPA_JSON: &[u8] = b"{\"epa\":\"v1\"}\n";
/// The distinctive placeholder the binary record carries pre-run — the config leg must never move it.
const BIN_PLACEHOLDER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// The stale config pin the re-pin must replace (64 hex, distinct from `sha256(EPA_JSON)`).
const CFG_OLD_PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A config-publishable fixture eco, mirroring the Task-5 grocer `build_mixed` but shaped for the
/// executor's `StoreLayout`: `eco/orchard` (consume-pins + repo-manifest) + a git-initialised sibling
/// `eco/dha` owning ONE binary (`creatine-serve`, record pre-seeded — a config subset never re-derives
/// it) + ONE git-TRACKED config (`dha-epa-config`, source `deploy/epa.json`). `dha`'s
/// `published-pins.toml` is pre-seeded with BOTH records (the read-merge-write needs every non-config
/// key present). No `--build-dir`/ELF is needed — the subset skips the binary entirely.
fn config_publishable_fixture() -> (tempfile::TempDir, StoreLayout) {
    let base = tempfile::tempdir().unwrap();
    let eco = base.path().join("eco");
    let orchard = eco.join("orchard");
    let dha = eco.join("dha");
    std::fs::create_dir_all(orchard.join("vendor")).unwrap();
    std::fs::create_dir_all(dha.join("deploy")).unwrap();
    std::fs::write(
        orchard.join("consume-pins.toml"),
        format!(
            "schema-version = 1\n\
             [artifacts.creatine-serve]\nsha256 = \"{BIN_PLACEHOLDER}\"\nkind = \"binary\"\n\
             [artifacts.dha-epa-config]\nsha256 = \"{CFG_OLD_PIN}\"\nkind = \"config\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        orchard.join("repo-manifest.toml"),
        "schema-version = 1\n[repos.dha]\npath = \"../dha\"\nartifacts = [\"creatine-serve\", \"dha-epa-config\"]\n",
    )
    .unwrap();
    std::fs::write(
        dha.join("publish-manifest.toml"),
        "schema-version = 1\n\
         [[artifact]]\nkey = \"creatine-serve\"\nkind = \"binary\"\nsource = \"release/creatine-serve\"\nlinkage = \"static\"\n\
         [[artifact]]\nkey = \"dha-epa-config\"\nkind = \"config\"\nsource = \"deploy/epa.json\"\n",
    )
    .unwrap();
    std::fs::write(dha.join("deploy/epa.json"), EPA_JSON).unwrap();
    std::fs::write(
        dha.join("published-pins.toml"),
        format!(
            "# Published artifact pins — GENERATED by grocer. Do not edit by hand (re-publish to regenerate).\n\
             schema-version = 1\n\n[artifacts]\ncreatine-serve = \"{BIN_PLACEHOLDER}\"\ndha-epa-config = \"{CFG_OLD_PIN}\"\n"
        ),
    )
    .unwrap();
    git(&["init", "-q"], &dha);
    git(&["config", "user.email", "cfg@test"], &dha);
    git(&["config", "user.name", "cfg-test"], &dha);
    git(&["config", "maintenance.auto", "false"], &dha);
    git(&["config", "gc.auto", "0"], &dha);
    git(&["add", "-A"], &dha);
    git(&["commit", "-q", "-m", "dha-init"], &dha);
    let store = eco.join("artifact-store");
    std::fs::create_dir_all(&store).unwrap();
    let layout = StoreLayout {
        orchard_root: orchard,
        store,
        repos: BTreeMap::from([("dha".to_string(), dha)]),
        cert_trail: None,
    };
    (base, layout)
}

/// Drive the config-subset leg (`PublishConfigSubset{dha}` → `Repin{dha-epa-config}`) through the FULL
/// `execute()` (real grocer, real record loop + swap; verify verdict injected green). Returns the
/// swapped paths.
fn run_config_subset(layout: &StoreLayout) -> Vec<PathBuf> {
    let _ = colocated_grocer();
    let manifest = RepoManifest::load(&layout.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&layout.orchard_root.join("consume-pins.toml")).unwrap();
    let steps = vec![
        Step::PublishConfigSubset {
            repo: "dha".into(),
            key: "dha-epa-config".into(),
        },
        Step::Repin {
            keys: vec!["dha-epa-config".into()],
        },
    ];
    let mut exec = ShellStepExec {
        layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let verify = |_: &Stage| Ok(());
    execute(&steps, layout, &mut exec, &verify)
        .expect("the config-subset leg must reach the swap")
        .swapped
}

/// The exact `key = "sha"` line for `key` in a published-pins file (for the byte-preservation assert).
fn published_line(path: &Path, key: &str) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    let anchor = format!("{key} = \"");
    text.lines()
        .find(|l| l.starts_with(&anchor))
        .unwrap_or_else(|| panic!("no {key} line in {}", path.display()))
        .to_string()
}

/// The set of file names in a store dir.
fn store_names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn config_leg_publishes_repins_surgically_and_verifies_then_gates() {
                                                                                                      
                                                                                                     
                                                                                                           
    let (_base, layout) = config_publishable_fixture();
    let consume_before =
        std::fs::read_to_string(layout.orchard_root.join("consume-pins.toml")).unwrap();
    let new_sha = hex::encode(Sha256::digest(EPA_JSON));
    assert_ne!(
        new_sha, CFG_OLD_PIN,
        "the real config bytes must differ from the stale placeholder pin"
    );

    let swapped = run_config_subset(&layout);

                                                                                                        
                                                             
    assert!(
        layout
            .store
            .join(format!("dha-epa-config@{new_sha}"))
            .is_file(),
        "the config @sha revision must land in the real store"
    );
    assert!(
        layout.store.join("dha-epa-config").is_file(),
        "the flat alias must land too"
    );
    let store = DirStore::new(&layout.store);
    let got = store
        .fetch_verified("dha-epa-config", &new_sha)
        .expect("the config pin must fetch_verify green");
    assert_eq!(got.sha256(), new_sha);
    assert_eq!(
        got.bytes(),
        EPA_JSON,
        "the published bytes ARE the tracked config file"
    );

                                                                                                        
                                                                                                
    let consume_after =
        std::fs::read_to_string(layout.orchard_root.join("consume-pins.toml")).unwrap();
    assert_eq!(
        consume_after,
        consume_before.replace(CFG_OLD_PIN, &new_sha),
        "the re-pin must move ONLY the config sha, byte-preserving every other line"
    );
    assert!(
        swapped.contains(&layout.orchard_root.join("consume-pins.toml")),
        "consume-pins.toml must be in the swapped set: {swapped:?}"
    );

                                                                                                               
    let msg = compose_message(
        &Target::Config("dha-epa-config".into()),
        &layout.orchard_root,
        &[layout.orchard_root.join("consume-pins.toml")],
    );
    assert!(
        msg.starts_with("pin(config):"),
        "the config leg's commit subject must be a config re-pin, got: {msg}"
    );
    let flags = UpgradeFlags::default();
    assert_eq!(consent_from(&flags, true, || 'y'), Consent::Commit);
    assert_eq!(consent_from(&flags, true, || '\n'), Consent::PrintOnly);
}

#[test]
fn config_leg_leaves_the_binary_published_pin_byte_identical() {
                                                                                                       
                                                                                                        
                                                                                                     
    let (_base, layout) = config_publishable_fixture();
    let dha_pins = layout.repos["dha"].join("published-pins.toml");
    let bin_line_before = published_line(&dha_pins, "creatine-serve");

    run_config_subset(&layout);                                                                          

    let bin_line_after = published_line(&dha_pins, "creatine-serve");
    assert_eq!(
        bin_line_after, bin_line_before,
        "the binary published-pin line must survive a config subset byte-identical"
    );
    assert_eq!(
        bin_line_after,
        format!("creatine-serve = \"{BIN_PLACEHOLDER}\""),
        "and still hold the untouched placeholder sha"
    );
                                                                                                          
                                                                                               
    assert!(
        !layout
            .store
            .join(format!("creatine-serve@{BIN_PLACEHOLDER}"))
            .exists(),
        "a config subset must NOT store the binary revision"
    );
                                                                
    assert_ne!(
        published_line(&dha_pins, "dha-epa-config"),
        format!("dha-epa-config = \"{CFG_OLD_PIN}\""),
        "the config record must have been re-pinned"
    );
}

#[test]
fn config_leg_untracked_source_aborts_before_the_swap() {
                                                                                                        
                                                                                                   
    let (_base, layout) = config_publishable_fixture();
    let dha = layout.repos["dha"].clone();
                                                                                                
    let out = Command::new("git")
        .current_dir(&dha)
        .args(["rm", "--cached", "-q", "deploy/epa.json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "git rm --cached must succeed");

    let consume_before =
        std::fs::read_to_string(layout.orchard_root.join("consume-pins.toml")).unwrap();
    let store_before = store_names(&layout.store);

    let _ = colocated_grocer();
    let manifest = RepoManifest::load(&layout.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&layout.orchard_root.join("consume-pins.toml")).unwrap();
    let steps = vec![
        Step::PublishConfigSubset {
            repo: "dha".into(),
            key: "dha-epa-config".into(),
        },
        Step::Repin {
            keys: vec!["dha-epa-config".into()],
        },
    ];
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let verify = |_: &Stage| Ok(());
    let err = execute(&steps, &layout, &mut exec, &verify).unwrap_err();
    assert!(
        matches!(err, UpgradeError::StepFailed { .. }),
        "an untracked config source must abort the leg (grocer refusal → StepFailed), got {err:?}"
    );
                                                      
    assert_eq!(
        std::fs::read_to_string(layout.orchard_root.join("consume-pins.toml")).unwrap(),
        consume_before,
        "consume-pins.toml must be byte-identical after a pre-swap refusal"
    );
    assert_eq!(
        store_names(&layout.store),
        store_before,
        "no store name may be added on the pre-swap refusal"
    );
}
