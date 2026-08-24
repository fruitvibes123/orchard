//! grocer publish core — hermetic integration test. Drives `grocer::run` against a synthetic fixture
//! ecosystem (orchard + a git-clean seed-vault) and asserts: the source drop is tarred via the
                                                                                                          
//! is read from `--build-dir`, ELF/linkage-asserted, and its RAW bytes stored + pinned (increment 2); a
//! binary whose declared linkage contradicts the real ELF is refused with the store byte-untouched (the
//! fail-closed "no partial write" invariant); NOTHING outside `--store`/`--published-out` is written
//! (AC-G1); and a source escaping its base is refused (AC-G4b). The committed-pin anchor (the real grape
//! tree == `bdbdcb87…`) is the produced-bytes gate's job (Task 9).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

struct Fx {
    _tmp: tempfile::TempDir,
    eco: PathBuf,
    orchard: PathBuf,
    seed_vault: PathBuf,
    store: PathBuf,
    pins_out: PathBuf,
}

fn build(consume: &str, repo_manifest: &str, publish_manifest: &str) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let eco = tmp.path().join("eco");
    let orchard = eco.join("orchard");
    let seed_vault = eco.join("seed-vault");
    std::fs::create_dir_all(&orchard).unwrap();
    std::fs::create_dir_all(seed_vault.join("crates/x")).unwrap();
    std::fs::write(orchard.join("repo-manifest.toml"), repo_manifest).unwrap();
    std::fs::write(orchard.join("consume-pins.toml"), consume).unwrap();
    std::fs::write(seed_vault.join("publish-manifest.toml"), publish_manifest).unwrap();
    std::fs::write(seed_vault.join("crates/x/lib.rs"), b"pub fn x() {}\n").unwrap();
    std::fs::write(
        seed_vault.join("crates/x/Cargo.toml"),
        b"[package]\nname = \"x\"\n",
    )
    .unwrap();
    let git = |a: &[&str]| {
        let o = Command::new("git")
            .current_dir(&seed_vault)
            .args(a)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {a:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@t"]);
    git(&["config", "user.name", "t"]);
                                                                            
                                                                                               
                          
    git(&["config", "maintenance.auto", "false"]);
    git(&["config", "gc.auto", "0"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]);
    Fx {
        eco: eco.clone(),
        orchard,
        seed_vault,
        store: eco.join("store"),
        pins_out: eco.join("published-out.toml"),
        _tmp: tmp,
    }
}

fn args(fx: &Fx) -> grocer::Args {
    args_bd(fx, None)
}

fn args_bd(fx: &Fx, build_dir: Option<PathBuf>) -> grocer::Args {
    grocer::Args {
        manifest: None,
        repo: "seed-vault".into(),
        repo_manifest: fx.orchard.join("repo-manifest.toml"),
        consume_pins: fx.orchard.join("consume-pins.toml"),
        build_dir,
        store: fx.store.clone(),
        published_out: fx.pins_out.clone(),
        only_configs: false,
        config_key: None,
    }
}

/// Every file under `root`, skipping any rel-path equal to / under a `skip` entry.
fn snapshot(root: &Path, skip: &[&str]) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, base: &Path, skip: &[&str], m: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if skip
                .iter()
                .any(|s| rel == *s || rel.starts_with(&format!("{s}/")))
            {
                continue;
            }
            if p.is_dir() {
                walk(&p, base, skip, m);
            } else {
                m.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut m = BTreeMap::new();
    walk(root, root, skip, &mut m);
    m
}

const Z: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The real dynamic musl service `fb-cert-check` (ELF64/LE/ET_DYN/x86-64, 1 PT_INTERP) — the `--build-dir`
/// binary fixture. Declaring it `static` in a manifest must be refused (its ELF contradicts the claim).
const DYN_ELF: &[u8] = include_bytes!("fixtures/fb-cert-check");

#[test]
fn publishes_source_drop_into_store_and_pins_realpath_only() {
    let consume =
        format!("schema-version = 1\n[artifacts.x-src]\nsha256 = \"{Z}\"\nkind = \"source\"\n");
    let rm = "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"x-src\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"x-src\"\nkind = \"source\"\nsource = \"crates/x\"\n";
    let fx = build(&consume, rm, pm);

                                                                                               
                                                                                               
                                                                                                  
                                                                                         
                                                                                     
    let skip = ["store", "published-out.toml"];
    let before = snapshot(&fx.eco, &skip);

    grocer::run(args(&fx)).expect("publish ok");

                                                        
    assert!(fx.store.join("x-src").is_file(), "store/x-src written");
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();

                                                                                                          
    let expected = hex::encode(Sha256::digest(
        recipes_image_builder::vendor::deterministic_source_tar(
            &fx.seed_vault.join("crates"),
            "x",
            true,
        )
        .unwrap(),
    ));
    assert!(
        pins.contains(&format!("x-src = \"{expected}\"")),
        "pins:\n{pins}"
    );
    assert_eq!(
        hex::encode(Sha256::digest(
            std::fs::read(fx.store.join("x-src")).unwrap()
        )),
        expected,
        "the store blob is the tar"
    );

                                                                                                          
    assert_eq!(
        snapshot(&fx.eco, &skip),
        before,
        "grocer wrote only --store + --published-out"
    );
}

#[test]
fn publishes_a_dynamic_binary_from_build_dir() {
    let consume =
        format!("schema-version = 1\n[artifacts.y-bin]\nsha256 = \"{Z}\"\nkind = \"binary\"\n");
    let rm = "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"y-bin\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"y-bin\"\nkind = \"binary\"\nsource = \"release/y\"\nlinkage = \"dynamic\"\n";
    let fx = build(&consume, rm, pm);

                                                                                                       
    let build_dir = fx.eco.join("build");
    std::fs::create_dir_all(build_dir.join("release")).unwrap();
    std::fs::write(build_dir.join("release/y"), DYN_ELF).unwrap();

    grocer::run(args_bd(&fx, Some(build_dir))).expect("publish ok");

                                                                               
    let expected = hex::encode(Sha256::digest(DYN_ELF));
    assert!(fx.store.join("y-bin").is_file(), "store/y-bin written");
    assert_eq!(
        hex::encode(Sha256::digest(
            std::fs::read(fx.store.join("y-bin")).unwrap()
        )),
        expected,
        "the store blob is the raw ELF"
    );
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();
    assert!(
        pins.contains(&format!("y-bin = \"{expected}\"")),
        "pins:\n{pins}"
    );
}

#[test]
fn refuses_a_binary_whose_declared_linkage_contradicts_the_elf() {
                                                                                                             
                                                                                                    
                                                                                                                    
    let consume = format!(
        "schema-version = 1\n[artifacts.x-src]\nsha256 = \"{Z}\"\nkind = \"source\"\n[artifacts.y-bin]\nsha256 = \"{Z}\"\nkind = \"binary\"\n"
    );
    let rm = "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"x-src\", \"y-bin\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"x-src\"\nkind = \"source\"\nsource = \"crates/x\"\n[[artifact]]\nkey = \"y-bin\"\nkind = \"binary\"\nsource = \"release/y\"\nlinkage = \"static\"\n";
    let fx = build(&consume, rm, pm);
    let build_dir = fx.eco.join("build");
    std::fs::create_dir_all(build_dir.join("release")).unwrap();
    std::fs::write(build_dir.join("release/y"), DYN_ELF).unwrap();                                 

    let err = grocer::run(args_bd(&fx, Some(build_dir))).unwrap_err();
    assert!(
        matches!(err, grocer::publish::GrocerError::Elf { .. }),
        "got {err:?}"
    );
                                                                                                           
    assert!(
        !fx.store.join("x-src").exists(),
        "no partial store write on the linkage refusal"
    );
    assert!(
        !fx.store.join("y-bin").exists(),
        "the refused binary is not in the store"
    );
    assert!(!fx.pins_out.exists(), "no published-pins on refusal");
}

#[test]
fn refuses_a_binary_manifest_without_build_dir() {
                                                                                                      
                                                                                                             
    let consume =
        format!("schema-version = 1\n[artifacts.y-bin]\nsha256 = \"{Z}\"\nkind = \"binary\"\n");
    let rm = "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"y-bin\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"y-bin\"\nkind = \"binary\"\nsource = \"release/y\"\nlinkage = \"dynamic\"\n";
    let fx = build(&consume, rm, pm);
                                                
    let err = grocer::run(args(&fx)).unwrap_err();
    assert!(
        matches!(err, grocer::publish::GrocerError::MissingBuildDir { .. }),
        "got {err:?}"
    );
    assert!(
        !fx.store.join("y-bin").exists(),
        "no store write when --build-dir is absent"
    );
    assert!(
        !fx.pins_out.exists(),
        "no published-pins when --build-dir is absent"
    );
}

#[test]
fn refuses_a_source_escaping_its_base() {
    let consume =
        format!("schema-version = 1\n[artifacts.x-src]\nsha256 = \"{Z}\"\nkind = \"source\"\n");
    let rm = "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"x-src\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"x-src\"\nkind = \"source\"\nsource = \"../../escape\"\n";
    let fx = build(&consume, rm, pm);
    let err = grocer::run(args(&fx)).unwrap_err();
    assert!(
        matches!(err, grocer::publish::GrocerError::Cross(_)),
        "got {err:?}"
    );
}

                                                                                          

const CFG_A: &[u8] = b"{\"a\":1}\n";
const CFG_B: &[u8] = b"{\"b\":2}\n";

/// A MIXED repo fixture: one binary (from `--build-dir`, the DYN_ELF) + two git-TRACKED config files, the
/// three manifests, and an OPTIONAL pre-existing `published-pins.toml` to merge into. Returns
/// `(Fx, build_dir)`; `Fx.seed_vault` is the git-initialised owning repo `dha`.
fn build_mixed(published_pins: Option<&str>) -> (Fx, PathBuf) {
    let consume = format!(
        "schema-version = 1\n[artifacts.thebin]\nsha256 = \"{Z}\"\nkind = \"binary\"\n[artifacts.cfg-a]\nsha256 = \"{Z}\"\nkind = \"config\"\n[artifacts.cfg-b]\nsha256 = \"{Z}\"\nkind = \"config\"\n"
    );
    let rm =
        "schema-version = 1\n[repos.dha]\npath = \"../dha\"\nartifacts = [\"thebin\", \"cfg-a\", \"cfg-b\"]\n";
    let pm = "schema-version = 1\n[[artifact]]\nkey = \"thebin\"\nkind = \"binary\"\nsource = \"release/thebin\"\nlinkage = \"dynamic\"\n[[artifact]]\nkey = \"cfg-a\"\nkind = \"config\"\nsource = \"deploy/a.json\"\n[[artifact]]\nkey = \"cfg-b\"\nkind = \"config\"\nsource = \"deploy/b.json\"\n";
    let tmp = tempfile::tempdir().unwrap();
    let eco = tmp.path().join("eco");
    let orchard = eco.join("orchard");
    let dha = eco.join("dha");
    std::fs::create_dir_all(&orchard).unwrap();
    std::fs::create_dir_all(dha.join("deploy")).unwrap();
    std::fs::write(orchard.join("repo-manifest.toml"), rm).unwrap();
    std::fs::write(orchard.join("consume-pins.toml"), &consume).unwrap();
    std::fs::write(dha.join("publish-manifest.toml"), pm).unwrap();
    std::fs::write(dha.join("deploy/a.json"), CFG_A).unwrap();
    std::fs::write(dha.join("deploy/b.json"), CFG_B).unwrap();
    let git = |a: &[&str]| {
        let o = Command::new("git")
            .current_dir(&dha)
            .args(a)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {a:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@t"]);
    git(&["config", "user.name", "t"]);
    git(&["config", "maintenance.auto", "false"]);
    git(&["config", "gc.auto", "0"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]);
    let build_dir = eco.join("bd");
    std::fs::create_dir_all(build_dir.join("release")).unwrap();
    std::fs::write(build_dir.join("release/thebin"), DYN_ELF).unwrap();
    let pins_out = eco.join("dha-published-pins.toml");
    if let Some(p) = published_pins {
        std::fs::write(&pins_out, p).unwrap();
    }
    let fx = Fx {
        eco: eco.clone(),
        orchard,
        seed_vault: dha,
        store: eco.join("store"),
        pins_out,
        _tmp: tmp,
    };
    (fx, build_dir)
}

fn cfg_args(fx: &Fx, build_dir: &Path, only_configs: bool) -> grocer::Args {
    grocer::Args {
        manifest: None,
        repo: "dha".into(),
        repo_manifest: fx.orchard.join("repo-manifest.toml"),
        consume_pins: fx.orchard.join("consume-pins.toml"),
        build_dir: Some(build_dir.to_path_buf()),
        store: fx.store.clone(),
        published_out: fx.pins_out.clone(),
        only_configs,
        config_key: None,
    }
}

/// A pre-existing published-pins with ALL THREE records — the binary sha a distinctive placeholder so the
/// byte-preservation check is unambiguous.
fn existing_pins_all_three() -> String {
    format!(
        "# Published artifact pins — GENERATED by grocer. Do not edit by hand (re-publish to regenerate).\nschema-version = 1\n\n[artifacts]\nthebin = \"{bin}\"\ncfg-a = \"{Z}\"\ncfg-b = \"{Z}\"\n",
        bin = "b".repeat(64)
    )
}

#[test]
fn config_subset_updates_configs_preserves_binary_and_cas_stores_only_configs() {
    let (fx, bd) = build_mixed(Some(&existing_pins_all_three()));
    grocer::run(cfg_args(&fx, &bd, true)).expect("config-subset publish ok");
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();
    let sha_a = hex::encode(Sha256::digest(CFG_A));
    let sha_b = hex::encode(Sha256::digest(CFG_B));
                                                                
    assert!(
        pins.contains(&format!("cfg-a = \"{sha_a}\"")),
        "cfg-a updated:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-b = \"{sha_b}\"")),
        "cfg-b updated:\n{pins}"
    );
                                                                                
    assert!(
        pins.contains(&format!("thebin = \"{}\"", "b".repeat(64))),
        "binary line preserved:\n{pins}"
    );
                                                                                                       
    assert!(fx.store.join("cfg-a").is_file());
    assert!(fx.store.join(format!("cfg-a@{sha_a}")).is_file());
    assert!(fx.store.join("cfg-b").is_file());
    assert!(fx.store.join(format!("cfg-b@{sha_b}")).is_file());
    assert!(
        !fx.store.join("thebin").exists(),
        "the binary must NOT be re-stored by a config subset"
    );
}

#[test]
fn config_subset_targeted_publishes_only_the_named_config() {
                                                                                                        
                                                                                              
    let (fx, bd) = build_mixed(Some(&existing_pins_all_three()));
    let mut a = cfg_args(&fx, &bd, true);
    a.config_key = Some("cfg-a".into());
    grocer::run(a).expect("targeted config-subset publish ok");
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();
    let sha_a = hex::encode(Sha256::digest(CFG_A));
                                                                                                             
    assert!(
        pins.contains(&format!("cfg-a = \"{sha_a}\"")),
        "cfg-a re-pinned:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-b = \"{Z}\"")),
        "cfg-b byte-preserved — a targeted subset must NOT republish the sibling:\n{pins}"
    );
    assert!(
        pins.contains(&format!("thebin = \"{}\"", "b".repeat(64))),
        "the binary line is byte-preserved:\n{pins}"
    );
                                                                                                
    assert!(fx.store.join("cfg-a").is_file());
    assert!(fx.store.join(format!("cfg-a@{sha_a}")).is_file());
    assert!(
        !fx.store.join("cfg-b").exists(),
        "the sibling config must NOT be re-stored by a targeted subset"
    );
}

#[test]
fn config_subset_targeted_rejects_a_non_config_key() {
                                                                                                            
                                                                    
    let (fx, bd) = build_mixed(Some(&existing_pins_all_three()));
    let mut a = cfg_args(&fx, &bd, true);
    a.config_key = Some("thebin".into());                
    let err = grocer::run(a).unwrap_err();
    assert!(
        matches!(err, grocer::publish::GrocerError::ConfigKeyNotConfig(_)),
        "a non-config --config-key must be refused, got {err:?}"
    );
    assert!(
        !fx.store.exists(),
        "no store write on the config-key validation refusal"
    );
}

#[test]
fn config_subset_refuses_an_untracked_config_source() {
    let (fx, bd) = build_mixed(Some(&existing_pins_all_three()));
                                                                                                       
    Command::new("git")
        .current_dir(&fx.seed_vault)
        .args(["rm", "--cached", "-q", "deploy/b.json"])
        .output()
        .unwrap();
    let err = grocer::run(cfg_args(&fx, &bd, true)).unwrap_err();
    assert!(
        matches!(
            err,
            grocer::publish::GrocerError::Cross(
                grocer::crosscheck::CrossError::UntrackedConfigSource { .. }
            )
        ),
        "got {err:?}"
    );
}

#[test]
fn config_subset_refuses_a_symlink_config_source() {
                                                                                                    
                                                                                                       
                                                                                                     
    let (fx, bd) = build_mixed(Some(&existing_pins_all_three()));
    let git = |args: &[&str]| {
        Command::new("git")
            .current_dir(&fx.seed_vault)
            .args(args)
            .output()
            .unwrap();
    };
                                                                                                           
    let a = fx.seed_vault.join("deploy/a.json");
    std::fs::remove_file(&a).unwrap();
    std::os::unix::fs::symlink("b.json", &a).unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "symlink-a"]);
    let err = grocer::run(cfg_args(&fx, &bd, true)).unwrap_err();
    assert!(
        matches!(
            err,
            grocer::publish::GrocerError::Cross(
                grocer::crosscheck::CrossError::SymlinkConfigSource { .. }
            )
        ),
        "a symlink config source must be refused, got {err:?}"
    );
                                                         
    assert!(
        !fx.store.exists(),
        "the symlink refusal must create no store entry"
    );
}

#[test]
fn config_subset_refuses_absent_published_pins() {
    let (fx, bd) = build_mixed(None);                                      
    let err = grocer::run(cfg_args(&fx, &bd, true)).unwrap_err();
    assert!(
        matches!(
            err,
            grocer::publish::GrocerError::MissingPublishedPins { .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn config_subset_refuses_when_a_non_config_record_is_missing() {
                                                                                                          
                                             
    let pins_no_bin =
        "# Published artifact pins — GENERATED by grocer. Do not edit by hand (re-publish to regenerate).\nschema-version = 1\n\n[artifacts]\ncfg-a = \"".to_string()
            + Z
            + "\"\ncfg-b = \""
            + Z
            + "\"\n";
    let (fx, bd) = build_mixed(Some(&pins_no_bin));
    let err = grocer::run(cfg_args(&fx, &bd, true)).unwrap_err();
    assert!(
        matches!(
            err,
            grocer::publish::GrocerError::PublishedPinsMissingRecord { .. }
        ),
        "got {err:?}"
    );
                                                                                                      
                                                                                          
    assert!(
        !fx.store.exists(),
        "the missing-record refusal must create no store entry (no partial write)"
    );
}

#[test]
fn config_subset_appends_a_new_config_key() {
                                                                                                           
                                       
    let pins_no_cfgb = format!(
        "# Published artifact pins — GENERATED by grocer. Do not edit by hand (re-publish to regenerate).\nschema-version = 1\n\n[artifacts]\nthebin = \"{bin}\"\ncfg-a = \"{Z}\"\n",
        bin = "b".repeat(64)
    );
    let (fx, bd) = build_mixed(Some(&pins_no_cfgb));
    grocer::run(cfg_args(&fx, &bd, true)).expect("config-subset publish ok");
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();
    let sha_a = hex::encode(Sha256::digest(CFG_A));
    let sha_b = hex::encode(Sha256::digest(CFG_B));
    assert!(
        pins.contains(&format!("thebin = \"{}\"", "b".repeat(64))),
        "binary preserved:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-a = \"{sha_a}\"")),
        "cfg-a spliced:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-b = \"{sha_b}\"")),
        "cfg-b appended:\n{pins}"
    );
}

#[test]
fn whole_scope_publishes_all_three_fresh() {
                                                                                                               
                                                     
    let (fx, bd) = build_mixed(None);
    grocer::run(cfg_args(&fx, &bd, false)).expect("whole publish ok");
    let pins = std::fs::read_to_string(&fx.pins_out).unwrap();
    let sha_bin = hex::encode(Sha256::digest(DYN_ELF));
    let sha_a = hex::encode(Sha256::digest(CFG_A));
    let sha_b = hex::encode(Sha256::digest(CFG_B));
    assert!(
        pins.contains(&format!("thebin = \"{sha_bin}\"")),
        "pins:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-a = \"{sha_a}\"")),
        "pins:\n{pins}"
    );
    assert!(
        pins.contains(&format!("cfg-b = \"{sha_b}\"")),
        "pins:\n{pins}"
    );
    assert!(fx.store.join("thebin").is_file());
    assert!(fx.store.join("cfg-a").is_file());
    assert!(fx.store.join("cfg-b").is_file());
}
