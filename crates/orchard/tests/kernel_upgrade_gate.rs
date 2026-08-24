                                                                                                       
//! env-gated (`RECIPES_KERNEL_GATE`), wired into `make boot-gate`; PANICS if run `--ignored` without
                                                                                                          
//!
//! ## Why this + the unit suite both
//! `tests/kernel_bump.rs` calls `bump_kernel` DIRECTLY on a synthetic temp ecosystem — it proves the
                                                                                                           
//! This gate drives the REAL `ShellStepExec` through the REAL `execute` + the REAL `market verify`, on
                                                                                                      
//! the network transport is faked (a committed-fixture `(tar, sign)` pair) — the keyring pin check,
//! cashew verify, liblzma decode, the four-way pin write, and the staged verify all run for real.
//!
//! ## Two phases
                                                                                                         
//!   by a throwaway key, so it CANNOT verify against the real vendored Greg/Sasha keyring → the bump
//!   fails at `finalize`, the executor aborts before the swap, and all four real `pins.toml` + the real
//!   keyring are byte-identical after. This is the atomicity + fail-closed proof on the real trees.
                                                                                                     
//!   fixture signer (a simulated keyring-rotation review event: fixture `signer.asc` + all four
//!   `[kernel-keyring]` re-pinned to it), so the fixture tarball verifies. The full `[BumpUpstream,
//!   SyncPins]` chain runs GREEN (gated on the real staged `market verify`), the swap lands, and a
//!   FRESH `market verify` (default + `--all`) on the post-swap copy is green. `recipes` is a MINIMAL
//!   REAL dir (not a symlink like the grocer gate) because the kernel bump WRITES `recipes/pins.toml`.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use std::time::SystemTime;

use orchard::deploy::kernel_bump::{KERNEL_ORG_BASE, KERNEL_TAR_CEILING, KernelBump, bump_kernel};
use orchard::deploy::market::{VerifyOpts, verify};
use orchard::deploy::market_exec::{
    ShellStepExec, Stage, StepExec, default_store, execute, resolve_layout,
};
use orchard::deploy::market_upgrade::{Step, Target, UpgradeError, plan};
use recipes_image_builder::Fetcher;
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};

const ENV_GATE: &str = "RECIPES_KERNEL_GATE";

/// Phase-2 executor: the REAL `ShellStepExec` for every step EXCEPT the kernel bump, which it runs
/// via the REAL `bump_kernel` with the FIXTURE signer fingerprint set. We cannot sign as Greg/Sasha,
                                                                                                     
/// `KERNEL_ORG_SIGNER_FPRS` const REJECTS a wrong signer on the real trees, so substituting the
/// fixture fpr set here (and ONLY the fpr set) is honest: execute → staged verify → swap, sync-pins,
/// the four-way pin write, and the bump's own verify/decode/ceiling logic all run for real.
struct Phase2Exec<'a> {
    inner: ShellStepExec<'a>,
    fetch: &'a dyn Fetcher,
    fprs: &'a [&'a str],
}
impl StepExec for Phase2Exec<'_> {
    fn exec(&mut self, step: &Step, stage: &mut Stage) -> Result<(), UpgradeError> {
        match step {
            Step::BumpUpstream { which, version } if *which == "kernel" => {
                let bump = KernelBump {
                    fetch: self.fetch,
                    now: SystemTime::now(),
                    tar_ceiling: KERNEL_TAR_CEILING,
                    signer_fprs: self.fprs,
                };
                bump_kernel(&bump, version, self.inner.layout, stage)
            }
            other => self.inner.exec(other, stage),
        }
    }
}

                                                                                                        

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

struct Fixture {
    version: String,
    signer_fpr: String,
    signer_asc: Vec<u8>,
    signer_sha: String,
    tar_xz: Vec<u8>,
    tar_sign: Vec<u8>,
    xz_sha: String,
}

fn load_fixture() -> Fixture {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel_bump/gen");
    let man: toml::Value =
        toml::from_str(&String::from_utf8(read(&d.join("MANIFEST.toml"))).unwrap()).unwrap();
    let signer_asc = read(&d.join("signer.asc"));
    let tar_xz = read(&d.join("payload.tar.xz"));
    Fixture {
        version: man["version"].as_str().unwrap().to_string(),
        signer_fpr: man["keys"]["signer"].as_str().unwrap().to_string(),
        signer_sha: sha256_hex(&signer_asc),
        signer_asc,
        xz_sha: sha256_hex(&tar_xz),
        tar_xz,
        tar_sign: read(&d.join("payload.tar.sign")),
    }
}

/// URL→bytes transport fake; counts calls so we can assert what was (not) fetched.
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
fn transport(fx: &Fixture) -> MapFetcher {
    MapFetcher {
        map: BTreeMap::from([
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.sign", fx.version),
                fx.tar_sign.clone(),
            ),
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.xz", fx.version),
                fx.tar_xz.clone(),
            ),
        ]),
        calls: Cell::new(0),
    }
}

                                                                                                        

/// The orchard repo root discovered from the test crate's location (the real ecosystem anchor).
fn real_orchard_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize the orchard repo root")
}

/// The four real `pins.toml` paths (orchard + every owning repo), resolved from the manifest — exactly
/// the write set `bump_kernel` targets.
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

/// Rewrite the `[kernel-keyring]` TABLE to pin a single file (the fixture signer) — a simulated
/// keyring-rotation review event. LINE-ANCHORED + STRUCTURE-AWARE: the header must be a whole
/// line, and the replacement spans to the next `[` table-header line, so every other table
/// survives verbatim. The old `rfind`-and-truncate assumed `[kernel-keyring]` was the LAST table
/// with no later textual mention — Component C appended `[rust-keyring]` whose comment says
/// "alongside [kernel-keyring]", so rfind matched the COMMENT, glued the new header into a
/// comment line, attached the fixture pin to `[rust-keyring]`, and left the production
/// gregkh/sashal pins in force → the Phase-2 bump read a keyring file the fixture had deleted
/// (the gate was red on main from the C merge until this fix).
fn swap_keyring_section(pins_text: &str, file: &str, sha: &str) -> String {
    swap_pins_table(pins_text, "[kernel-keyring]", file, sha)
}

/// Structural single-table replace shared by the keyring fixtures: emit every line verbatim,
/// except the exact `header` line starts a replacement (header + one fixture pin) that swallows
/// lines up to (not including) the next table-header line. Comment mentions of the header never
/// match (they are not a whole line equal to the header).
fn swap_pins_table(pins_text: &str, header: &str, file: &str, sha: &str) -> String {
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

                                                                                                        

fn phase1_fail_before_swap_is_byte_identical(fx: &Fixture) {
    eprintln!("\n[] real ecosystem — an unverifiable tarball mutates nothing");
    let orchard_root = real_orchard_root();
    let manifest = RepoManifest::load(&orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&orchard_root.join("consume-pins.toml")).unwrap();
    let store = default_store(&orchard_root);
    let layout = resolve_layout(&manifest, orchard_root.clone(), store);

    let pins = four_pins(&orchard_root, &manifest);
    let keyring_dir = orchard_root.join("keyring/kernel.org");
    let watched: Vec<PathBuf> = pins
        .iter()
        .cloned()
        .chain([
            keyring_dir.join("gregkh.asc"),
            keyring_dir.join("sashal.asc"),
        ])
        .collect();
    let before = snapshot(&watched);

    let steps = plan(&Target::Kernel(fx.version.clone()), &manifest, &consume).unwrap();
    assert_eq!(
        steps.len(),
        2,
        "the --kernel plan is [BumpUpstream, SyncPins]"
    );
    let fetcher = transport(fx);
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &manifest,
        consume: &consume,
        apk_container_image: None,
        build_dir: None,
        kernel_fetcher: Some(&fetcher),
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
            .map(|_| ())
            .map_err(|e| UpgradeError::StagedVerify(e.to_string()))
    };
    let res = execute(&steps, &layout, &mut exec, &staged_verify);
    match res {
        Err(UpgradeError::StepFailed { step, detail }) => {
            assert_eq!(step, "bump-upstream");
            assert!(
                detail.contains("PGP verify"),
                "the fixture tarball must fail the REAL keyring at finalize, got: {detail}"
            );
        }
        other => panic!(": expected a bump-upstream PGP-verify failure, got {other:?}"),
    }
    assert_eq!(
        snapshot(&watched),
        before,
        "Phase 1: a REAL pins.toml or keyring file changed on a fail run — the executor is NOT atomic"
    );
    eprintln!(
        "  Phase 1 PASS: bump failed at PGP verify; {} real files byte-identical (nothing pinned)",
        watched.len()
    );
}

                                                                                                        

/// Recursively copy `src` → `dst`, pruning `.git`/`target` (never source bytes).
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

struct Copy {
    _base: tempfile::TempDir,
    orchard_root: PathBuf,
    pins: Vec<PathBuf>,
}

/// Build the disposable eco: orchard + seed-vault + fruit-basket + store copied real; recipes a MINIMAL
/// real dir (the 3 files verify reads + the bump writes); the cookbook cert-trail symlinked read-through.
/// Then overlay the fixture keyring (fixture `signer.asc`; all four `[kernel-keyring]` re-pinned to it).
fn build_copy(fx: &Fixture) -> Copy {
    let real_orchard = real_orchard_root();
                                                                                                    
                                                                                                  
                                                                                               
                                                                                                   
                                                       
    let real_manifest = RepoManifest::load(&real_orchard.join("repo-manifest.toml")).unwrap();

    let base = tempfile::Builder::new()
        .prefix("kernel-gate-eco-")
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

                                                                                                           
                                                                                                           
    let keyring_dir = orchard_root.join("keyring/kernel.org");
    for f in ["gregkh.asc", "sashal.asc"] {
        fs::remove_file(keyring_dir.join(f)).unwrap();
    }
    fs::write(keyring_dir.join("signer.asc"), &fx.signer_asc).unwrap();

    let manifest = RepoManifest::load(&orchard_root.join("repo-manifest.toml")).unwrap();
    let pins = four_pins(&orchard_root, &manifest);
                                                                                       
    let swapped = swap_keyring_section(
        &String::from_utf8(read(&pins[0])).unwrap(),
        "signer.asc",
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
    let steps = plan(&Target::Kernel(fx.version.clone()), &manifest, &consume).unwrap();

    let fetcher = transport(fx);
    let fprs = [fx.signer_fpr.as_str()];
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
        fprs: &fprs,
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
            "post-swap pins.toml must carry the new kernel version"
        );
        assert!(
            t.contains(&fx.xz_sha),
            "post-swap pins.toml must carry sha256(payload.tar.xz) as the [kernel] pin"
        );
    }
    assert!(
        texts.windows(2).all(|w| w[0] == w[1]),
        "the four post-swap pins.toml copies byte-agree (§3a-2)"
    );
    eprintln!(
        "  Phase 2 land PASS: 4 copies carry {} + the .xz sha, byte-identical",
        fx.version
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
    eprintln!("\n[ negative] a tampered tarball on the copy mutates nothing");
    let copy = build_copy(fx);
    let manifest = RepoManifest::load(&copy.orchard_root.join("repo-manifest.toml")).unwrap();
    let consume = PinManifest::load(&copy.orchard_root.join("consume-pins.toml")).unwrap();
    let store = copy.orchard_root.join("../artifact-store");
    let layout = resolve_layout(&manifest, copy.orchard_root.clone(), store);
    let steps = plan(&Target::Kernel(fx.version.clone()), &manifest, &consume).unwrap();

    let keyring = copy.orchard_root.join("keyring/kernel.org/signer.asc");
    let watched: Vec<PathBuf> = copy.pins.iter().cloned().chain([keyring]).collect();
    let before = snapshot(&watched);

                                                                                                       
                                                                       
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel_bump/gen");
    let tampered = read(&d.join("payload-tampered.tar.xz"));
    let fetcher = MapFetcher {
        map: BTreeMap::from([
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.sign", fx.version),
                fx.tar_sign.clone(),
            ),
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.xz", fx.version),
                tampered,
            ),
        ]),
        calls: Cell::new(0),
    };
    let fprs = [fx.signer_fpr.as_str()];
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
        fprs: &fprs,
    };
    let verify_closure = |_: &Stage| -> Result<(), UpgradeError> { Ok(()) };
    let res = execute(&steps, &layout, &mut exec, &verify_closure);
    assert!(
        matches!(res, Err(UpgradeError::StepFailed { .. })),
        "Phase 2 negative: a tampered tarball must fail the bump, got {res:?}"
    );
    assert_eq!(
        snapshot(&watched),
        before,
        "Phase 2 negative: a failed bump changed a copied file — not atomic"
    );
    eprintln!(" negative PASS: tampered bump failed; copy byte-identical");
}

                                                                                                        

#[test]
#[ignore = "produced-bytes gate — run via `make boot-gate` with RECIPES_KERNEL_GATE=1"]
fn kernel_upgrade_is_verified_and_atomic() {
    assert!(
        std::env::var_os(ENV_GATE).is_some(),
        "REFUSING a false green: {ENV_GATE} is unset. This produced-bytes gate drives the REAL \
         market-upgrade executor + verify + swap end-to-end and must be ARMED via `make boot-gate` \
         (RECIPES_KERNEL_GATE=1) — it must never count as passing when silently skipped."
    );
    let fx = load_fixture();
    phase1_fail_before_swap_is_byte_identical(&fx);
    phase2_green_bump_lands_and_verifies(&fx);
    phase2_tampered_leaves_copy_byte_identical(&fx);
    eprintln!(
        "\nkernel_upgrade_is_verified_and_atomic: Phase 1 (real, fail-atomic) + Phase 2 (copy, \
         green-lands + tampered-atomic) all PASS — --kernel proven on produced bytes."
    );
}
