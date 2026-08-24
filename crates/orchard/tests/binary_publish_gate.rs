                                                                                                        
//! gap grocer §9 named ("the binary-repo path — the §6 linkage assert + `--build-dir` — gets NO
//! produced-bytes proof here; it is increment 2's own gate"). On REAL built binaries it proves a
//! `market upgrade --binary` publish through the REAL grocer (ELF/linkage-assert + hash + put) + the REAL
//! executor is:
                                                                                                           
//!       on the binary path too), and
//!   (2) ELF-guarded — a static-PIE swapped in where a dynamic service is declared is REFUSED before any
//!       store write (the §6 control fires end-to-end through grocer + the executor).
//!
//! `#[ignore]`'d + env-gated (`RECIPES_BINARY_GATE`); PANICS if run `--ignored` without the env, so it can
                                                                                                  
//! `make boot-gate`. Needs docker (the build-only compile).
//!
//! Runs against the REAL trees safely: BOTH cases abort BEFORE any swap (forced-fail / ELF-refusal → nothing
                                                                                                           
//! §9 proves on the source path, and grocer's binary OUTPUT was byte-anchored to `consume-pins` by A-4's
//! real-tree smoke; this gate adds the executor-level atomicity + the end-to-end ELF-control proof the
//! binary path lacked — named, not hidden.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use orchard::deploy::market_exec::{ShellStepExec, Stage, default_store, execute, resolve_layout};
use orchard::deploy::market_upgrade::{Target, UpgradeError, plan};
use recipes_image_builder::pin_manifest::PinManifest;
use recipes_image_builder::repo_manifest::RepoManifest;
use sha2::{Digest, Sha256};

/// The env that ARMS this gate. Without it the test PANICS (no silent skip) when run `--ignored`.
const ENV_GATE: &str = "RECIPES_BINARY_GATE";

/// The fruit-basket store keys a `--binary` publish of that repo touches (grocer republishes the WHOLE
/// manifest), plus the two pin files — the atomicity byte-identity set.
const FB_KEYS: &[&str] = &[
    "fb-acme",
    "fb-oneshots",
    "fb-backup",
    "fb-cert-check",
    "box-init",
    "initramfs-init",
    "rambutan-src",
    "fb-manifest-src",
];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Build the grocer binary and co-locate it beside the test exe (`target/debug/deps/grocer`) so the
/// executor's `current_exe`-based `grocer_path()` finds it — the same trick the grocer §9 gate uses.
fn build_and_locate_grocer() {
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "grocer"])
        .status()
        .expect("spawn `cargo build -p grocer`");
    assert!(status.success(), "`cargo build -p grocer` failed");
    let me = env::current_exe().expect("current_exe");
    let deps = me.parent().expect("test exe has no parent (deps/)");
    let built = deps
        .parent()
        .expect("deps/ has no parent (target/debug)")
        .join("grocer");
    assert!(
        built.is_file(),
        "grocer missing at {} after `cargo build -p grocer`",
        built.display()
    );
    let dst = deps.join("grocer");
    let _ = fs::remove_file(&dst);
    fs::copy(&built, &dst).expect("co-locate grocer beside the test exe");
    eprintln!("[setup] grocer co-located at {}", dst.display());
}

/// The pinned host's real ecosystem, discovered from the orchard crate's location.
struct RealEco {
    orchard_root: PathBuf,
    fruit_basket: PathBuf,
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
                                                                                                        
                                                                                                     
                                                                                                         
        let fruit_basket = manifest
            .repo_path("fruit-basket", &orchard_root)
            .expect("repo-manifest has a fruit-basket entry")
            .canonicalize()
            .expect(
                "canonicalize fruit-basket (the market-increment-2 branch must be checked out)",
            );
        assert!(
            fruit_basket.join("publish-manifest.toml").is_file(),
            "fruit-basket/publish-manifest.toml missing — check out the market-increment-2 branch (A-4)"
        );
        Self {
            orchard_root,
            fruit_basket,
            store,
            manifest,
            consume,
        }
    }

    /// Snapshot every real artifact a fruit-basket `--binary` publish could touch (the 8 store keys + the
    /// two pin files), for the byte-identical atomicity assertions.
    fn snapshot(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        for key in FB_KEYS {
            m.insert(
                format!("store/{key}"),
                sha256_hex(&read(&self.store.join(key))),
            );
        }
        m.insert(
            "fruit-basket/published-pins".into(),
            sha256_hex(&read(&self.fruit_basket.join("published-pins.toml"))),
        );
        m.insert(
            "orchard/consume-pins".into(),
            sha256_hex(&read(&self.orchard_root.join("consume-pins.toml"))),
        );
        m
    }
}

/// Run fruit-basket's build-only step (the docker compile → normalized handoff). These are the PRODUCED
/// BYTES this gate proves the publish path on. Returns the handoff dir (dynamic services at `release/`, the
/// static PID-1/installer pair at `x86_64-unknown-linux-musl/release/`).
fn build_fb_handoff(real: &RealEco) -> PathBuf {
    eprintln!("[setup] fruit-basket build-only.sh (docker compile → handoff)");
    let handoff = env::temp_dir().join("fb-binary-gate-handoff");
    let out = Command::new("sh")
        .arg(real.fruit_basket.join("build-only.sh"))
        .arg(&handoff)
        .output()
        .expect("run fruit-basket build-only.sh");
    assert!(
        out.status.success(),
        "build-only.sh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for rel in [
        "release/fb-acme",
        "release/fb-oneshots",
        "release/fb-backup",
        "release/fb-cert-check",
        "x86_64-unknown-linux-musl/release/box-init",
        "x86_64-unknown-linux-musl/release/initramfs-init",
    ] {
        assert!(
            handoff.join(rel).is_file(),
            "build-only handoff is missing {rel}"
        );
    }
    handoff
}

                                                                                                            
/// byte-identical. grocer publishes the real built binaries into the STAGE, then the forced staged-verify
/// fails → the executor aborts BEFORE the swap → nothing in the real ecosystem changed.
fn fail_before_swap_is_byte_identical(real: &RealEco, handoff: &Path) {
    eprintln!(
        "\n[atomicity] fail-before-swap on --binary fb-acme leaves the REAL trees byte-identical"
    );
    let layout = resolve_layout(
        &real.manifest,
        real.orchard_root.clone(),
        real.store.clone(),
    );
    let steps = plan(
        &Target::Binary("fb-acme".into()),
        &real.manifest,
        &real.consume,
    )
    .expect("plan the --binary fb-acme leg");

    let before = real.snapshot();
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &real.manifest,
        consume: &real.consume,
        apk_container_image: None,
        build_dir: Some(handoff.to_path_buf()),
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let forced = |_: &Stage| {
        Err(UpgradeError::StagedVerify(
            "forced fail (binary gate — atomicity)".into(),
        ))
    };
    let res = execute(&steps, &layout, &mut exec, &forced);
                                                                                                         
                                                                                                              
                                                                                          
    assert!(
        matches!(res, Err(UpgradeError::StagedVerify(_))),
        "atomicity: the forced staged-verify (StagedVerify) must abort before the swap after grocer publishes \
         the real binaries into the stage, got {res:?}"
    );
    let after = real.snapshot();
    assert_eq!(
        before, after,
        "atomicity: a REAL artifact changed on a forced-fail --binary run — a pre-verify write leaked to a \
         real tree (the class, on the binary path)"
    );
    eprintln!(
        "  atomicity PASS: {} real artifacts byte-identical after a forced-fail --binary run",
        before.len()
    );
}

                                                                                                              
/// where the manifest declares `fb-acme` as `dynamic` is REFUSED by grocer before any store write; the
/// executor aborts before the swap → the REAL trees are byte-identical. Uses a passthrough verify to prove
/// the refusal comes from the ELF assert, NOT the staged verify.
fn elf_assert_fires_and_is_byte_identical(real: &RealEco, handoff: &Path) {
    eprintln!(
        "\n[elf-control] a static-PIE where fb-acme (dynamic) is declared is refused end-to-end"
    );
                                                                                                         
                                                                                                       
    let static_pie = handoff.join("x86_64-unknown-linux-musl/release/box-init");
    let fb_acme = handoff.join("release/fb-acme");
                                                                                                   
                                                                                                      
    let real_fb_acme =
        fs::read(&fb_acme).expect("read the real fb-acme before corrupting the handoff");
    fs::copy(&static_pie, &fb_acme).expect("swap the static-PIE over fb-acme in the handoff");

    let layout = resolve_layout(
        &real.manifest,
        real.orchard_root.clone(),
        real.store.clone(),
    );
    let steps = plan(
        &Target::Binary("fb-acme".into()),
        &real.manifest,
        &real.consume,
    )
    .expect("plan the --binary fb-acme leg");

    let before = real.snapshot();
    let mut exec = ShellStepExec {
        layout: &layout,
        manifest: &real.manifest,
        consume: &real.consume,
        apk_container_image: None,
        build_dir: Some(handoff.to_path_buf()),
        kernel_fetcher: None,
        rust_fetcher: None,
        container_builder: None,
        rebuilt_digest: None,
    };
    let passthrough = |_: &Stage| Ok(());
    let res = execute(&steps, &layout, &mut exec, &passthrough);
                                                                                                          
                                                                                                                
                                                         
    match res {
        Err(UpgradeError::StepFailed { ref detail, .. })
            if detail.contains("ELF") || detail.contains("linkage") => {}
        other => panic!(
            "elf-control: grocer must REFUSE the static-PIE-as-dynamic fb-acme with an ELF/linkage error, \
             got {other:?}"
        ),
    }
    let after = real.snapshot();
    assert_eq!(
        before, after,
        "elf-control: a REAL artifact changed on the refused publish — grocer wrote before the ELF assert"
    );
    fs::write(&fb_acme, &real_fb_acme)
        .expect("restore the real fb-acme (leave the handoff intact)");
    eprintln!(
        "  elf-control PASS: the ELF/linkage assert refused the swap; {} real artifacts byte-identical",
        before.len()
    );
}

#[test]
#[ignore = "produced-bytes gate — run via `make boot-gate` with RECIPES_BINARY_GATE=1 (needs docker)"]
fn binary_publish_is_atomic_and_elf_asserts() {
    assert!(
        env::var_os(ENV_GATE).is_some(),
        "REFUSING a false green: {ENV_GATE} is unset. This produced-bytes gate drives a REAL --binary \
         publish end-to-end and must be ARMED via `make boot-gate` (RECIPES_BINARY_GATE=1) — it must never \
         be counted as passing when silently skipped."
    );

    build_and_locate_grocer();
    let real = RealEco::discover();
    let handoff = build_fb_handoff(&real);

    fail_before_swap_is_byte_identical(&real, &handoff);
    elf_assert_fires_and_is_byte_identical(&real, &handoff);

    eprintln!(
        "\nbinary_publish_is_atomic_and_elf_asserts: atomicity + the §6 ELF/linkage control both PASS on \
         produced bytes — the increment-2 binary path proven."
    );
}
