                                                                                                      
                                                                                           
//! (`RECIPES_GROCER_GATE`), wired into `make boot-gate`; PANICS if run `--ignored` without the env, so it
                                                                                                             
                               
//!
//! ## Why not the unit suite
//! `tests/market_upgrade.rs` fakes `StepExec` (a fixed staged write) — it proves the stage/swap MACHINERY
//! but never runs grocer, so it CANNOT catch a real-grocer atomicity regression. This gate drives the
//! **real** `grocer` binary through the **real** `ShellStepExec`/`execute` end-to-end on seed-vault's
//! `--source` leg `[Publish, Repin, Vendor]` (build-free → no docker → cheap).
//!
//! ## Two phases, two ecosystems
                                                                                                           
//!   anchor publishes to a *throwaway* store, and the fail-before-swap probe forces the staged verify to
//!   fail — which (the whole point) mutates NOTHING, so it is safe to run against the real trees: after a
//!   forced fail the real store + real `published-pins.toml` + real `consume-pins.toml` are byte-identical.
                                                                                                                
//!   so it must not touch the repo. The copy mirrors orchard + the store + the repo-manifest-resolved
//!   seed-vault/fruit-basket trees (each at the offset the copied repo-manifest resolves — the same
//!   resolution grocer/verify use) as real copies (small) and SYMLINKS the read-only `recipes` (218 MB) +
//!   the cookbook cert-trail — `market verify` only READS them and the grape-src swap never targets them, so
//!   a read-through symlink is faithful AND swap-safe (a `rename` over a symlink replaces the *link*, never
//!   writing through to the real target). The bump runs the full chain GREEN (gated on the real `market
//!   verify --all` of the staged result), then a FRESH `market verify` (default + `--all`) on the post-swap
//!   copy must be green.
//!
//! The minimal-synthetic fixture an earlier ad-hoc harness used cannot satisfy AC-G5c: `market verify`'s
//! first leg locks the consume set to the canonical 8/4/1 shape, so a real verify needs the whole canonical
//! ecosystem — hence the copy-of-real.
//!
//! The **binary-repo** path (the §6 linkage assert + `--build-dir`) gets NO produced-bytes proof here — it is
//! increment 2's own gate. This gap is named, not hidden.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use orchard::deploy::market::{VerifyOpts, verify};
use orchard::deploy::market_exec::{ShellStepExec, Stage, default_store, execute, resolve_layout};
use orchard::deploy::market_upgrade::{Target, UpgradeError, plan};
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;
use recipes_image_builder::vendor::deterministic_source_tar;
use sha2::{Digest, Sha256};

/// The env that ARMS this gate. Without it the test PANICS (no silent skip) when run `--ignored`.
const ENV_GATE: &str = "RECIPES_GROCER_GATE";

                                                                                                        

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Run `cmd args` in `cwd`, asserting success (used only for `git` in the disposable copy).
fn sh(cmd: &str, args: &[&str], cwd: &Path) {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("spawn `{cmd} {args:?}`: {e}"));
    assert!(
        out.status.success(),
        "`{cmd} {args:?}` in {} failed: {}",
        cwd.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Build the REAL `grocer` binary and co-locate it beside THIS test exe, so the executor's production
/// `current_exe().parent()/grocer` resolution (`market_exec::grocer_path`) finds it — the operator and the
/// gate exercise the IDENTICAL binary.
fn build_and_locate_grocer() -> PathBuf {
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "grocer"])
        .status()
        .expect("spawn `cargo build -p grocer`");
    assert!(status.success(), "`cargo build -p grocer` failed");
    let me = std::env::current_exe().expect("current_exe");
    let deps = me.parent().expect("test exe has no parent (deps/)");
    let target_debug = deps.parent().expect("deps/ has no parent (target/debug)");
    let built = target_debug.join("grocer");
    assert!(
        built.is_file(),
        "grocer missing at {} after `cargo build -p grocer`",
        built.display()
    );
    let dst = deps.join("grocer");
    let _ = fs::remove_file(&dst);
    fs::copy(&built, &dst).expect("co-locate grocer beside the test exe");
    eprintln!("[setup] grocer co-located at {}", dst.display());
    dst
}

                                                                                                        

/// The pinned host's real ecosystem, discovered from the orchard crate's location.
struct RealEco {
    orchard_root: PathBuf,
    store: PathBuf,
    manifest: RepoManifest,
    consume: PinManifest,
}

impl RealEco {
    fn discover() -> Self {
        let orchard_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonicalize the orchard repo root");
        let manifest = RepoManifest::load(&orchard_root.join("repo-manifest.toml"))
            .expect("load the real repo-manifest.toml");
        let consume = PinManifest::load(&orchard_root.join("consume-pins.toml"))
            .expect("load the real consume-pins.toml");
        let store = default_store(&orchard_root);
        assert!(
            store.is_dir(),
            "the real artifact-store is missing at {} — run `orchard build` first",
            store.display()
        );
        Self {
            orchard_root,
            store,
            manifest,
            consume,
        }
    }

    /// The currently-committed `consume-pins` sha for `key`.
    fn committed(&self, key: &str) -> String {
        self.consume
            .artifact(key)
            .unwrap_or_else(|_| panic!("no committed consume pin for {key}"))
            .sha256
            .clone()
    }
}

/// **AC-G2** — grocer's published `grape-src` (+ `dragonfruit-src`) and ≥1 fruit-basket source drop equal the
/// *currently-committed* `consume-pins` value (the `-C`=parent / entry=basename recipe; not merely
                                                                                                      
/// fruit-basket source drops are anchored via the SHARED tar primitive grocer wraps, over the
/// repo-manifest-resolved fruit-basket root (grocer's own resolution).
fn anchor_committed_pins(grocer: &Path, real: &RealEco) {
    eprintln!("\n[AC-G2] committed-pin anchor");
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store");
    fs::create_dir_all(&store).unwrap();
    let pins = tmp.path().join("published-pins.toml");
    let out = Command::new(grocer)
        .args(["--repo", "seed-vault"])
        .arg("--repo-manifest")
        .arg(real.orchard_root.join("repo-manifest.toml"))
        .arg("--consume-pins")
        .arg(real.orchard_root.join("consume-pins.toml"))
        .arg("--store")
        .arg(&store)
        .arg("--published-out")
        .arg(&pins)
        .output()
        .expect("run grocer for the AC-G2 anchor");
    assert!(
        out.status.success(),
        "AC-G2: grocer anchor publish failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for key in ["grape-src", "dragonfruit-src"] {
        let got = sha256_hex(&read(&store.join(key)));
        let want = real.committed(key);
        assert_eq!(
            got, want,
            "AC-G2: grocer's published {key} ({got}) != the committed consume-pins value ({want}) — the \
             -C/entry rule or the tar recipe drifted"
        );
        eprintln!("  seed-vault   {key:<16} == committed {}…", &got[..16]);
    }
                                                                                                      
                                                                                                      
                                                                                                        
                                                                                                    
                                                                          
    let fb_crates = real
        .manifest
        .repo_path("fruit-basket", &real.orchard_root)
        .expect("repo-manifest has a fruit-basket entry")
        .join("crates");
    for (entry, key) in [
        ("rambutan", "rambutan-src"),
        ("fb-manifest", "fb-manifest-src"),
    ] {
        let tar = deterministic_source_tar(&fb_crates, entry, true)
            .unwrap_or_else(|e| panic!("tar fruit-basket {entry}: {e}"));
        let got = sha256_hex(&tar);
        let want = real.committed(key);
        assert_eq!(
            got, want,
            "AC-G2: fruit-basket {key} live-source tar ({got}) != committed ({want})"
        );
        eprintln!("  fruit-basket {key:<16} == committed {}…", &got[..16]);
    }
}

/// **AC-G5a** — fail-before-swap. Plan the real `--source grape-src` leg `[Publish, Repin, Vendor]`, run all
/// three INTO the stage with the real grocer, then force the staged verify to FAIL — and assert every real
/// artifact the swap would have touched (plus a binary control) is byte-identical before vs after. This is
                                                                                                        
/// trees precisely because a forced fail must not swap.
fn fail_before_swap_is_byte_identical(real: &RealEco) {
    eprintln!("\n[AC-G5a] fail-before-swap leaves the REAL trees byte-identical");
    let layout = resolve_layout(
        &real.manifest,
        real.orchard_root.clone(),
        real.store.clone(),
    );
    let steps = plan(
        &Target::Source("grape-src".into()),
        &real.manifest,
        &real.consume,
    )
    .expect("plan the --source leg");
    assert_eq!(
        steps.len(),
        3,
        "the --source leg is [Publish, Repin, Vendor]"
    );

    let published_pins = real
        .manifest
        .repo_path("seed-vault", &real.orchard_root)
        .expect("repo-manifest has a seed-vault entry")
        .join("published-pins.toml");
    let consume_pins = real.orchard_root.join("consume-pins.toml");
    let snapshot = || -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        for key in ["grape-src", "dragonfruit-src", "fb-acme"] {
            m.insert(
                format!("store/{key}"),
                sha256_hex(&read(&real.store.join(key))),
            );
        }
        m.insert(
            "seed-vault/published-pins".into(),
            sha256_hex(&read(&published_pins)),
        );
        m.insert(
            "orchard/consume-pins".into(),
            sha256_hex(&read(&consume_pins)),
        );
        m
    };

    let before = snapshot();
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &real.manifest,
        consume: &real.consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let forced = |_: &Stage| {
        Err(UpgradeError::StagedVerify(
            "forced fail (gate AC-G5a)".into(),
        ))
    };
    let res = execute(&steps, &layout, &mut exec, &forced);
    assert!(
        matches!(
            res,
            Err(UpgradeError::StagedVerify(_)) | Err(UpgradeError::StepFailed { .. })
        ),
        "AC-G5a: a forced staged-verify fail must abort BEFORE the swap, got {res:?}"
    );
    let after = snapshot();
    assert_eq!(
        before, after,
        "a REAL artifact changed on a forced-fail run — atomicity is NOT closed (a pre-verify write \
         leaked to a real tree)"
    );
    eprintln!(
        "  AC-G5a PASS: {} real artifacts byte-identical after a forced-fail run",
        before.len()
    );
}

                                                                                                        

/// Recursively copy `src` → `dst`, pruning `.git` and `target` at every level (never source bytes).
fn copy_tree_pruned(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|e| panic!("mkdir {}: {e}", dst.display()));
    for entry in fs::read_dir(src).unwrap_or_else(|e| panic!("read_dir {}: {e}", src.display())) {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            copy_tree_pruned(&from, &to);
        } else if ft.is_symlink() {
            symlink(fs::read_link(&from).unwrap(), &to).unwrap();
        } else {
            fs::copy(&from, &to).unwrap_or_else(|e| panic!("copy {}: {e}", from.display()));
        }
    }
}

/// A disposable, canonical-shape copy of the real ecosystem: orchard + seed-vault + fruit-basket + the store
/// copied real; `recipes` + the cookbook cert-trail symlinked read-through. Every repo sits at the offset
/// the copied repo-manifest resolves, sourced from the real manifest-resolved tree.
struct CanonicalCopy {
    _base: tempfile::TempDir,
    orchard_root: PathBuf,
    seed_vault: PathBuf,
}

impl CanonicalCopy {
    fn build(real: &RealEco) -> Self {
        let base = tempfile::Builder::new()
            .prefix("grocer-gate-eco-")
            .tempdir()
            .unwrap();
        let projects = base.path().join("Projects");
        let eco = projects.join("fruit-ecosystem");
        fs::create_dir_all(&eco).unwrap();

                                                                                                    
                                                                                                      
                                                                                                          
                                                                                                      
                                                                                                  
                                     
        let orchard_root = eco.join("orchard");
        copy_tree_pruned(&real.orchard_root, &orchard_root);
        let place = |name: &str| -> (PathBuf, PathBuf) {
            let src = real
                .manifest
                .repo_path(name, &real.orchard_root)
                .unwrap_or_else(|| panic!("repo-manifest has no `{name}` entry"));
            let dst = real.manifest.repo_path(name, &orchard_root).unwrap();
            (src, dst)
        };
        let (sv_src, seed_vault) = place("seed-vault");
        copy_tree_pruned(&sv_src, &seed_vault);
        let (fb_src, fb_dst) = place("fruit-basket");
        copy_tree_pruned(&fb_src, &fb_dst);
        let store = eco.join("artifact-store");
        copy_tree_pruned(&real.store, &store);

                                                                                                
        fs::create_dir_all(&projects).unwrap();
        let (recipes_src, recipes_dst) = place("recipes");
        fs::create_dir_all(recipes_dst.parent().expect("recipes offset has a parent")).unwrap();
        symlink(recipes_src, &recipes_dst).expect("symlink recipes read-through");
        let cert_src = real
            .manifest
            .cert_trail_path(&real.orchard_root)
            .expect("repo-manifest declares a cert-trail");
        let cert_dst = real.manifest.cert_trail_path(&orchard_root).unwrap();
        fs::create_dir_all(cert_dst.parent().expect("cert-trail offset has a parent")).unwrap();
        symlink(cert_src, &cert_dst).expect("symlink the cookbook cert-trail read-through");

                                                                                                  
                                                                                          
                                                                                                  
                                                                                                  
                                                                                                 
                                                                                     
                                                                    
        for name in real.manifest.repos.keys() {
            if matches!(name.as_str(), "seed-vault" | "fruit-basket" | "recipes") {
                continue;                                                     
            }
            let (src, dst) = place(name);
            fs::create_dir_all(&dst).unwrap();
            for f in ["pins.toml", "published-pins.toml"] {
                fs::copy(src.join(f), dst.join(f))
                    .unwrap_or_else(|e| panic!("copy {name}/{f} into the canonical copy: {e}"));
            }
        }

                                                                                                        
        sh("git", &["init", "-q"], &seed_vault);
        sh("git", &["config", "user.email", "gate@test"], &seed_vault);
        sh("git", &["config", "user.name", "grocer-gate"], &seed_vault);
        sh("git", &["add", "-A"], &seed_vault);
        sh("git", &["commit", "-q", "-m", "gate baseline"], &seed_vault);

        Self {
            _base: base,
            orchard_root,
            seed_vault,
        }
    }
}

/// **AC-G5b + AC-G5c** — bump grape's live source in the copy, run the full `[Publish, Repin, Vendor]` chain
/// GREEN (gated on the real `market verify --all` of the staged result), assert the new sha LANDED in the
/// copied consume-pins + store + published-pins (not a silent no-op), then assert a FRESH, independent
/// `market verify` (default + `--all`) on the post-swap copy is GREEN (store + published-pins + `vendor/`
/// mutually consistent).
fn green_bump_lands_and_verifies(real: &RealEco, copy: &CanonicalCopy) {
    eprintln!(
        "\n[AC-G5b/G5c] green bump lands + post-swap `market verify` GREEN (disposable canonical copy)"
    );

                                                                                                         
                                                                                                        
                                                                                                          
                                                                                                            
                                                                                                         
                                                                    
                                                                                          
    unsafe {
        std::env::remove_var("FRUIT_ARTIFACT_STORE");
    }

                                                                                                          
    fs::write(
        copy.seed_vault.join("crates/grape/GROCER_GATE_BUMP"),
        b"grocer produced-bytes gate: grape source bump\n",
    )
    .unwrap();
    sh("git", &["add", "-A"], &copy.seed_vault);
    sh(
        "git",
        &["commit", "-q", "-m", "bump grape"],
        &copy.seed_vault,
    );

    let new_grape = sha256_hex(
        &deterministic_source_tar(&copy.seed_vault.join("crates"), "grape", true).unwrap(),
    );
    assert_ne!(
        new_grape,
        real.committed("grape-src"),
        "the bump must change the grape-src sha (else AC-G5b cannot distinguish a no-op)"
    );

    let store = copy.orchard_root.join("../artifact-store");
    let manifest = RepoManifest::load(&copy.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&copy.orchard_root.join("consume-pins.toml")).unwrap();
                                                                                                
                                                                                           
    let pre_consume_text =
        String::from_utf8(read(&copy.orchard_root.join("consume-pins.toml"))).unwrap();
    let old_grape = consume.artifact("grape-src").unwrap().sha256.clone();
    let layout = resolve_layout(&manifest, copy.orchard_root.clone(), store.clone());
    let steps = plan(&Target::Source("grape-src".into()), &manifest, &consume).unwrap();
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

                                                                                                            
                                                                                                          
                                                                                                        
                                                                                                              
                                                                                                              
                                                                                                                
                                         
    let staged_verify = |stage: &Stage| -> Result<(), UpgradeError> {
        let opts = VerifyOpts {
            repo_root: stage.verify_root().to_path_buf(),
            certs: false,
            all: false,
            allow_missing: vec![],
        };
        verify(&opts)
            .map(|s| eprintln!("  [staged verify] {}", s.lines().next().unwrap_or("")))
            .map_err(|e| UpgradeError::StagedVerify(e.to_string()))
    };
    let report = execute(&steps, &layout, &mut exec, &staged_verify).expect(
        "AC-G5b: the green --source bump must reach the swap (Vendor + the real staged verify all green)",
    );
    let swapped: Vec<String> = report
        .swapped
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    eprintln!("  [swapped] {swapped:?}");

                                                          
    let post_consume = PinManifest::load(&copy.orchard_root.join("consume-pins.toml")).unwrap();
    assert_eq!(
        post_consume.artifact("grape-src").unwrap().sha256,
        new_grape,
        "AC-G5b: post-swap consume-pins grape-src must be the NEW sha"
    );
    assert_eq!(
        sha256_hex(&read(&store.join("grape-src"))),
        new_grape,
        "AC-G5b: post-swap store/grape-src must be grocer's NEW tar"
    );
                                                                                              
                                                                                             
                                                                                                 
                                                                                         
                                                                   
    assert!(
        store.join(format!("grape-src@{new_grape}")).exists(),
        "post-swap store must carry the grape-src@<sha> revision blob, not just the flat alias"
    );
    let post_pub = String::from_utf8(read(&copy.seed_vault.join("published-pins.toml"))).unwrap();
    assert!(
        post_pub.contains(&new_grape),
        "AC-G5b: post-swap published-pins.toml must carry the NEW grape sha"
    );
    eprintln!("  AC-G5b PASS: the bump landed in consume-pins + store + published-pins");

                                                              
                                                                                               
                                                                                              
                                                                                        
    let post_consume_text =
        String::from_utf8(read(&copy.orchard_root.join("consume-pins.toml"))).unwrap();
    assert_eq!(
        post_consume_text,
        pre_consume_text.replace(&old_grape, &new_grape),
        "the Repin step must move ONLY the changed sha value (comment/order fidelity)"
    );
                                                                                                 
                                                                 
    assert_eq!(
        String::from_utf8(read(&copy.orchard_root.join("vendor/PROVENANCE.md"))).unwrap(),
        orchard::deploy::vendor_cmd::PROVENANCE_DOC,
        "vendor/PROVENANCE.md must survive the vendor dir swap"
    );
    eprintln!("  repin-fidelity + PROVENANCE survival PASS");

                                                                                                   
    for (label, all) in [("default", false), ("--all", true)] {
        let opts = VerifyOpts {
            repo_root: copy.orchard_root.clone(),
            certs: false,
            all,
            allow_missing: vec![],
        };
        let summary = verify(&opts)
            .unwrap_or_else(|e| panic!("AC-G5c: post-swap `market verify {label}` is RED:\n{e}"));
        eprintln!(
            "  AC-G5c [{label:<7}] GREEN: {}",
            summary.lines().next().unwrap_or("")
        );
    }
}

                                                                                                        

#[test]
#[ignore = "produced-bytes gate — run via `make boot-gate` with RECIPES_GROCER_GATE=1"]
fn grocer_source_bump_is_atomic() {
    assert!(
        std::env::var_os(ENV_GATE).is_some(),
        "REFUSING a false green: {ENV_GATE} is unset. This produced-bytes gate drives the REAL grocer \
         end-to-end and must be ARMED via `make boot-gate` (RECIPES_GROCER_GATE=1) — it must never be \
         counted as passing when silently skipped."
    );

    let grocer = build_and_locate_grocer();
    let real = RealEco::discover();

                                                                                                               
    anchor_committed_pins(&grocer, &real);         
    fail_before_swap_is_byte_identical(&real);          

                                                                                    
    let copy = CanonicalCopy::build(&real);
    green_bump_lands_and_verifies(&real, &copy);                   

    eprintln!(
        "
grocer_source_bump_is_atomic: all legs PASS — atomicity proven on produced bytes."
    );
}
