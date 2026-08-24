//! PRODUCED-BYTES gate for `market upgrade --rust` (Component C; AC-C-7). `#[ignore]`d + env-gated
//! (`RECIPES_RUST_GATE`), wired into `make boot-gate`; PANICS if run `--ignored` without the env, so it
                                                                                           
//!
//! ## What it proves on produced bytes
                                                                                                   
//!   vendored Rust key (`keyring/rust-lang/rust-signing.asc`) via `load_pinned_bare` — the REAL-KEY
//!   ANCHOR: the actual SHA-1-self-signed Rust key MUST load through the §3.2 exception on its real
//!   bytes. The fixture manifest is signed by a throwaway key, so `finalize` REJECTS it → the executor
//!   aborts before the swap → all four real `pins.toml` + the real keyring are byte-identical after.
                                                                                                      
//!   the fixture signer (a simulated keyring-rotation review event), so the fixture manifest verifies.
//!   `[BumpUpstream(rust), SyncPins]` runs GREEN (gated on the real staged `market verify`, incl. the
//!   generalized §3a-8), the swap lands the four-way pin write, and a FRESH `market verify` is green. A
//!   tampered manifest leaves the copy byte-identical.
                                                                                                          
//!   drives the REAL `DockerContainerBuilder` against a 2-line Containerfile (`FROM alpine` + a
//!   file-writing `RUN` — the written file makes the double-build mtime-honest) —
//!   the `docker build --iidfile` → double-build repro → digest-capture → stage → swap path on produced
//!   bytes, WITHOUT a real toolchain download. The REAL full toolchain rebuild is the NAMED operator
//!   step (`keyring/rust-lang/README.md`), never CI-claimed.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use orchard::deploy::market::{VerifyOpts, verify};
use orchard::deploy::market_exec::{
    DockerContainerBuilder, ShellStepExec, Stage, StepExec, StoreLayout, default_store, execute,
    resolve_layout,
};
use orchard::deploy::market_upgrade::{Step, Target, UpgradeError, plan};
use orchard::deploy::rust_bump::{RUST_MANIFEST_BASE, RustBump, bump_rust};
use recipes_image_builder::Fetcher;
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};

const ENV_GATE: &str = "RECIPES_RUST_GATE";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Phase-2 executor: the REAL `ShellStepExec` for every step EXCEPT the rust bump, which runs via the
                                                                                                     
/// the PRODUCTION `RUST_SIGNER_FPR` rejects a wrong signer on the real trees, so substituting ONLY the
/// signer fpr here is honest — the keyring-pin check, `load_pinned_bare`, verify, parse, version-bind,
/// four-way pin write, sync-pins, and the staged verify all run for real.
struct Phase2Exec<'a> {
    inner: ShellStepExec<'a>,
    fetch: &'a dyn Fetcher,
    signer_fpr: &'a str,
}
impl StepExec for Phase2Exec<'_> {
    fn exec(&mut self, step: &Step, stage: &mut Stage) -> Result<(), UpgradeError> {
        match step {
            Step::BumpUpstream { which, version } if *which == "rust" => {
                let bump = RustBump {
                    fetch: self.fetch,
                    now: SystemTime::now(),
                    signer_fpr: self.signer_fpr,
                };
                bump_rust(&bump, version, self.inner.layout, stage)
            }
            other => self.inner.exec(other, stage),
        }
    }
}

struct Fixture {
    version: String,
    signer_fpr: String,
    signer_asc: Vec<u8>,
    signer_sha: String,
    manifest: Vec<u8>,
    manifest_asc: Vec<u8>,
    tampered: Vec<u8>,
    musl_sha: String,
    uefi_sha: String,
}

fn load_fixture() -> Fixture {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_bump/gen");
    let man: toml::Value =
        toml::from_str(&String::from_utf8(read(&d.join("MANIFEST.toml"))).unwrap()).unwrap();
    let signer_asc = read(&d.join("signer.asc"));
    Fixture {
        version: man["version"].as_str().unwrap().to_string(),
        signer_fpr: man["keys"]["signer"].as_str().unwrap().to_string(),
        signer_sha: sha256_hex(&signer_asc),
        signer_asc,
        manifest: read(&d.join("manifest.toml")),
        manifest_asc: read(&d.join("manifest.toml.asc")),
        tampered: read(&d.join("manifest-tampered.toml")),
                                                                                         
        musl_sha: "1".repeat(64),
        uefi_sha: "2".repeat(64),
    }
}

/// URL→bytes transport fake; counts calls.
struct MapFetcher {
    map: BTreeMap<String, Vec<u8>>,
    calls: Cell<usize>,
}
impl Fetcher for MapFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get() + 1);
        self.map
            .get(url)
            .cloned()
            .ok_or_else(|| format!("fixture 404: {url}"))
    }
}
fn transport(fx: &Fixture, asc: &[u8], manifest: &[u8]) -> MapFetcher {
    MapFetcher {
        map: BTreeMap::from([
            (
                format!("{RUST_MANIFEST_BASE}/channel-rust-{}.toml.asc", fx.version),
                asc.to_vec(),
            ),
            (
                format!("{RUST_MANIFEST_BASE}/channel-rust-{}.toml", fx.version),
                manifest.to_vec(),
            ),
        ]),
        calls: Cell::new(0),
    }
}

fn real_orchard_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize the orchard repo root")
}
fn four_pins(orchard_root: &Path, manifest: &RepoManifest) -> Vec<PathBuf> {
    let mut v = vec![orchard_root.join("pins.toml")];
    for e in manifest.repos.values() {
        v.push(orchard_root.join(&e.path).join("pins.toml"));
    }
    v
}
fn snapshot(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| sha256_hex(&read(p))).collect()
}

                                                                                                        

fn phase1_real_key_rejects_and_is_atomic(fx: &Fixture) {
    eprintln!(
        "\n[Phase 1] real ecosystem — the REAL Rust key loads via load_pinned_bare + rejects a throwaway sig"
    );
    let orchard_root = real_orchard_root();
    let manifest = RepoManifest::load(&orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&orchard_root.join("consume-pins.toml")).unwrap();
    let store = default_store(&orchard_root);
    let layout = resolve_layout(&manifest, orchard_root.clone(), store);

    let watched: Vec<PathBuf> = four_pins(&orchard_root, &manifest)
        .into_iter()
        .chain([orchard_root.join("keyring/rust-lang/rust-signing.asc")])
        .collect();
    let before = snapshot(&watched);

                                                                                              
    let steps = plan(&Target::Rust(fx.version.clone()), &manifest, &consume).unwrap();
    let fetcher = transport(fx, &fx.manifest_asc, &fx.manifest);
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: Some(&fetcher),                                                         
        container_builder: None,                                           
        rebuilt_digest: None,
    };
    let staged_verify = |_: &Stage| -> Result<(), UpgradeError> { Ok(()) };
    match execute(&steps, &layout, &mut exec, &staged_verify) {
        Err(UpgradeError::StepFailed { step, detail }) => {
            assert_eq!(step, "bump-upstream");
            assert!(
                detail.contains("PGP verify"),
                "the throwaway-signed manifest must fail the REAL Rust key at finalize, got: {detail}"
            );
        }
        other => panic!(": expected a bump-upstream PGP-verify failure, got {other:?}"),
    }
    assert_eq!(
        snapshot(&watched),
        before,
        "Phase 1: a REAL pins.toml or the rust keyring changed on a fail run — NOT atomic"
    );
    eprintln!(
        "  Phase 1 PASS: the real SHA-1-self-signed Rust key loaded via load_pinned_bare + rejected \
         the throwaway sig; {} real files byte-identical (nothing pinned)",
        watched.len()
    );
}

                                                                                                        

fn copy_tree_pruned(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        let (from, to) = (entry.path(), dst.join(&name));
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            copy_tree_pruned(&from, &to);
        } else if ft.is_symlink() {
            symlink(fs::read_link(&from).unwrap(), &to).unwrap();
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// Replace the `[rust-keyring]` table with a single fixture pin, leaving every other table
/// intact. LINE-ANCHORED + STRUCTURE-AWARE (same shape as kernel_upgrade_gate's
/// `swap_pins_table`): the old rfind-and-truncate assumed `[rust-keyring]` was the LAST table
/// with no later textual mention — true today, but exactly that assumption rotted the kernel
/// gate when Component C appended a table after `[kernel-keyring]` (see kernel_upgrade_gate.rs);
/// this keeps the rust fixture immune to the same class.
fn swap_rust_keyring(pins_text: &str, file: &str, sha: &str) -> String {
    let header = "[rust-keyring]";
    let mut out = String::new();
    let mut skipping = false;
    let mut replaced = false;
    for line in pins_text.lines() {
        if skipping {
            if line.trim_start().starts_with('[') {
                skipping = false;
            } else {
                continue;
            }
        }
        if line.trim() == header {
            skipping = true;
            replaced = true;
            out.push_str(header);
            out.push('\n');
            out.push_str(&format!("\"{file}\" = \"{sha}\"\n"));
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    assert!(replaced, "pins.toml has a {header} table");
    out
}

struct Copy {
    _base: tempfile::TempDir,
    orchard_root: PathBuf,
    pins: Vec<PathBuf>,
}

fn build_copy(fx: &Fixture) -> Copy {
    let real_orchard = real_orchard_root();
                                                                                                    
                                                                                                  
                                                                                               
                                                                                                   
                                                       
    let real_manifest = RepoManifest::load(&real_orchard.join("repo-manifest.toml")).unwrap();

    let base = tempfile::Builder::new()
        .prefix("rust-gate-eco-")
        .tempdir()
        .unwrap();
    let projects = base.path().join("Projects");
    let eco = projects.join("fruit-ecosystem");
    fs::create_dir_all(&eco).unwrap();

    let orchard_root = eco.join("orchard");
    copy_tree_pruned(&real_orchard, &orchard_root);
    let place = |name: &str| -> (PathBuf, PathBuf) {
        let src = real_manifest
            .repo_path(name, &real_orchard)
            .unwrap_or_else(|| panic!("repo-manifest has no `{name}` entry"));
        (src, real_manifest.repo_path(name, &orchard_root).unwrap())
    };
    let (sv_src, sv_dst) = place("seed-vault");
    copy_tree_pruned(&sv_src, &sv_dst);
    let (fb_src, fb_dst) = place("fruit-basket");
    copy_tree_pruned(&fb_src, &fb_dst);
    copy_tree_pruned(&default_store(&real_orchard), &eco.join("artifact-store"));

    let (recipes_src, recipes) = place("recipes");
    fs::create_dir_all(&recipes).unwrap();
    for f in ["pins.toml", "published-pins.toml", "service-manifest.toml"] {
        fs::copy(recipes_src.join(f), recipes.join(f)).unwrap();
    }
                                                                                                
                                                                                                    
                                                                                         
                                                                                                 
                                                                                            
                                                                                         
    for name in real_manifest.repos.keys() {
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
    let cert_src = real_manifest
        .cert_trail_path(&real_orchard)
        .expect("repo-manifest declares a cert-trail");
    let cert_dst = real_manifest.cert_trail_path(&orchard_root).unwrap();
    fs::create_dir_all(cert_dst.parent().expect("cert-trail offset has a parent")).unwrap();
    symlink(cert_src, &cert_dst).unwrap();

                                                                                                      
                                                                                                  
    let rust_keyring_dir = orchard_root.join("keyring/rust-lang");
    fs::remove_file(rust_keyring_dir.join("rust-signing.asc")).unwrap();
    fs::write(rust_keyring_dir.join("rust-signing.asc"), &fx.signer_asc).unwrap();

    let manifest = RepoManifest::load(&orchard_root.join("repo-manifest.toml")).unwrap();
    let pins = four_pins(&orchard_root, &manifest);
    let swapped = swap_rust_keyring(
        &String::from_utf8(read(&pins[0])).unwrap(),
        "rust-signing.asc",
        &fx.signer_sha,
    );
    for p in &pins {
        fs::write(p, &swapped).unwrap();
    }
    Copy {
        _base: base,
        orchard_root,
        pins,
    }
}

fn phase2_green_bump_lands_and_verifies(fx: &Fixture) {
    eprintln!("\n[] disposable copy — a verifiable bump lands + post-swap verify GREEN");
    let copy = build_copy(fx);
    let manifest = RepoManifest::load(&copy.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&copy.orchard_root.join("consume-pins.toml")).unwrap();
    let store = copy.orchard_root.join("../artifact-store");
    let layout = resolve_layout(&manifest, copy.orchard_root.clone(), store);

                                                                                                         
                                                                                                        
    let steps = vec![
        Step::BumpUpstream {
            which: "rust",
            version: fx.version.clone(),
        },
        Step::SyncPins,
    ];
    let fetcher = transport(fx, &fx.manifest_asc, &fx.manifest);
    let mut exec = Phase2Exec {
        inner: ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        },
        fetch: &fetcher,
        signer_fpr: fx.signer_fpr.as_str(),
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
    let report = execute(&steps, &layout, &mut exec, &staged_verify)
        .expect("Phase 2: the verifiable bump must reach the swap (staged market verify green)");
    eprintln!("  [swapped] {} path(s)", report.swapped.len());

    let texts: Vec<String> = copy
        .pins
        .iter()
        .map(|p| String::from_utf8(read(p)).unwrap())
        .collect();
    for t in &texts {
        assert!(
            t.contains(&format!("version = \"{}\"", fx.version)),
            "post-swap pins.toml must carry the new rust version"
        );
        assert!(
            t.contains(&fx.musl_sha) && t.contains(&fx.uefi_sha),
            "post-swap pins.toml must carry the two verified component shas"
        );
    }
    assert!(
        texts.windows(2).all(|w| w[0] == w[1]),
        "the four post-swap pins.toml copies byte-agree (§3a-2)"
    );
    for (label, all) in [("default", false), ("--all", true)] {
        let opts = VerifyOpts {
            repo_root: copy.orchard_root.clone(),
            certs: false,
            all,
            allow_missing: vec![],
        };
        let summary = verify(&opts)
            .unwrap_or_else(|e| panic!(": post-swap `market verify {label}` is RED:\n{e}"));
        eprintln!(
            "  Phase 2 verify [{label:<7}] GREEN: {}",
            summary.lines().next().unwrap_or("")
        );
    }
}

fn phase2_tampered_leaves_copy_byte_identical(fx: &Fixture) {
    eprintln!("\n[ negative] a tampered manifest on the copy mutates nothing");
    let copy = build_copy(fx);
    let manifest = RepoManifest::load(&copy.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&copy.orchard_root.join("consume-pins.toml")).unwrap();
    let store = copy.orchard_root.join("../artifact-store");
    let layout = resolve_layout(&manifest, copy.orchard_root.clone(), store);
    let steps = vec![Step::BumpUpstream {
        which: "rust",
        version: fx.version.clone(),
    }];
    let watched: Vec<PathBuf> = copy
        .pins
        .iter()
        .cloned()
        .chain([copy.orchard_root.join("keyring/rust-lang/rust-signing.asc")])
        .collect();
    let before = snapshot(&watched);

                                                                                      
    let fetcher = transport(fx, &fx.manifest_asc, &fx.tampered);
    let mut exec = Phase2Exec {
        inner: ShellStepExec {
            layout: &layout,
            manifest: &manifest,
            consume: &consume,
            apk_container_image: None,
            build_dir: None,
            kernel_fetcher: None,
            rust_fetcher: None,
            container_builder: None,
            rebuilt_digest: None,
        },
        fetch: &fetcher,
        signer_fpr: fx.signer_fpr.as_str(),
    };
    let ok = |_: &Stage| -> Result<(), UpgradeError> { Ok(()) };
    let res = execute(&steps, &layout, &mut exec, &ok);
    assert!(
        matches!(res, Err(UpgradeError::StepFailed { .. })),
        "Phase 2 negative: a tampered manifest must fail the bump, got {res:?}"
    );
    assert_eq!(
        snapshot(&watched),
        before,
        "Phase 2 negative: a failed bump changed a copied file — not atomic"
    );
    eprintln!(" negative PASS: tampered bump failed; copy byte-identical");
}

                                                                                                        

fn phase3_container_rebuild_mechanism() {
    eprintln!("\n[Phase 3] the RebuildContainer mechanism on a 2-line Containerfile (real docker)");
    let base = tempfile::Builder::new()
        .prefix("rust-gate-rebuild-")
        .tempdir()
        .unwrap();
    let orchard = base.path().join("eco/orchard");
    let ibuilder = orchard.join("crates/image-builder");
    fs::create_dir_all(&ibuilder).unwrap();
                                                                                                       
                                                                                                
                                                                                        
                                                                                                 
                                                                                                  
                                                                                                 
                    
    let alpine_digest = "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40";
    fs::write(
        ibuilder.join("Containerfile"),
        format!("FROM alpine:3.23@{alpine_digest}\nRUN echo repro-probe > /probe\n"),
    )
    .unwrap();
    fs::write(
        orchard.join("pins.toml"),
        "[rust]\nversion = \"1.96.0\"\ncontainer_digest = \"sha256:old\"\n",
    )
    .unwrap();

                                                                                         
    let layout = StoreLayout {
        orchard_root: orchard.clone(),
        store: base.path().join("eco/artifact-store"),
        repos: BTreeMap::new(),
        cert_trail: None,
    };
                                                                                          
    let manifest = RepoManifest::from_toml_str(
        "schema-version = 1\n[repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n",
    )
    .unwrap();
    let z = "a".repeat(64);
    let consume = PinManifest::from_toml_str(&format!(
        "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{z}\"\nkind = \"source\"\n"
    ))
    .unwrap();
    let builder = DockerContainerBuilder {
        source_date_epoch: 0,
    };
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: Some(&builder),
        rebuilt_digest: None,
    };
    let mut stage = Stage::new(&layout).unwrap();
    exec.exec(&Step::RebuildContainer, &mut stage)
        .expect(": the RebuildContainer mechanism must succeed on the tiny Containerfile");
    let digest = exec
        .rebuilt_digest
        .clone()
        .expect("RebuildContainer captured the image digest");
    assert!(
        digest.starts_with("sha256:") && digest.len() > "sha256:".len() + 40,
        "the captured digest must be a real docker image id, got {digest:?}"
    );
                                                                                   
    assert!(
        String::from_utf8(read(&orchard.join("pins.toml")))
            .unwrap()
            .contains("sha256:old")
    );
    stage.swap().unwrap();
    assert!(
        String::from_utf8(read(&orchard.join("pins.toml")))
            .unwrap()
            .contains(&format!("container_digest = \"{digest}\"")),
        "the swapped pins.toml must carry the rebuilt digest as [rust].container_digest"
    );
                                                                                                      
                                                                                                     
                                                                                                  
                                                                                                     
                                                                                                  
                                                                   
    let probe = Command::new("docker")
        .args(["run", "--rm", &digest, "stat", "-c", "%Y", "/probe"])
        .output()
        .expect("epoch-probe docker run must spawn");
    assert!(
        probe.status.success(),
        "epoch-probe docker run failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let mtime = String::from_utf8_lossy(&probe.stdout).trim().to_string();
    assert_eq!(
        mtime, "0",
        "rewrite-timestamp did not clamp /probe to epoch 0 (mtime {mtime}) — a silent \
         rewrite-skip (BuildKit < 0.13?); the exporter attr was accepted but had no effect"
    );
    eprintln!(
        "  Phase 3 PASS: docker build → double-build repro → captured {digest} → pinned + swapped \
         (+ /probe mtime clamped to epoch 0)"
    );
    eprintln!(
        "  (NOTE: the REAL full toolchain rebuild is the operator step — keyring/rust-lang/README.md)"
    );
}

                                                                                                        

#[test]
#[ignore = "produced-bytes gate — run via `make boot-gate` with RECIPES_RUST_GATE=1"]
fn rust_upgrade_is_verified_and_atomic() {
    assert!(
        std::env::var_os(ENV_GATE).is_some(),
        "REFUSING a false green: {ENV_GATE} is unset. This produced-bytes gate drives the REAL \
         market-upgrade rust bump + verify + swap + the docker container-rebuild mechanism, and must \
         be ARMED via `make boot-gate` (RECIPES_RUST_GATE=1) — it must never count as passing when \
         silently skipped."
    );
    let fx = load_fixture();
    phase1_real_key_rejects_and_is_atomic(&fx);
    phase2_green_bump_lands_and_verifies(&fx);
    phase2_tampered_leaves_copy_byte_identical(&fx);
    phase3_container_rebuild_mechanism();
    eprintln!(
        "\nrust_upgrade_is_verified_and_atomic: Phase 1 (real-key anchor, fail-atomic) + Phase 2 \
         (copy, green-lands + tampered-atomic) + Phase 3 (container-rebuild mechanism) all PASS — \
         --rust proven on produced bytes."
    );
}
