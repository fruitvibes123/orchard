//! Integration tests for the `market upgrade --kernel` bump — fixture-driven, NON-ignored (they run
//! in `make verify` via `cargo test -p orchard`; the env-armed produced-bytes chain lives in
//! `tests/kernel_upgrade_gate.rs`).

use std::time::{Duration, UNIX_EPOCH};

use cashew::{Fingerprint, Keyring};
use orchard::deploy::kernel_bump::KERNEL_ORG_SIGNER_FPRS;
use recipes_image_builder::store_checks::KEYRING_SUBDIR;
use sha2::{Digest, Sha256};

/// cashew's shared anchor clock (`crates/cashew/tests/fixtures/real/METADATA.toml` fixture_now):
/// ≥ Greg's 2026-05 governing re-sign, > the generated corpus's faked gen_time — one consistent
/// evaluation clock for real-key anchors.
const FIXTURE_NOW_UNIX: u64 = 1_781_100_000;

fn orchard_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize the orchard repo root")
}

/// THE REAL-KEYRING ANCHOR: the PRODUCTION vendored keyring (`keyring/kernel.org/*`) loads through
/// cashew with the two REAL consumer fingerprint pins at the pinned anchor clock, and each file's
/// bytes hash to its `pins.toml [kernel-keyring]` pin — the files ↔ pins ↔ fingerprints triangle
/// closes on the actual trust anchors a real `--kernel` bump would use.
#[test]
fn production_keyring_loads_with_the_real_pins() {
    let root = orchard_root();
    let pins = recipes_image_builder::pins::Pins::load(&root).expect("pins.toml parses");
    let dir = root.join(KEYRING_SUBDIR);

                                                                                                      
                                                                                               
    let mut concat = Vec::new();
    for (name, want) in &pins.kernel_keyring {
        let bytes = std::fs::read(dir.join(name)).expect("pinned keyring file readable");
        assert_eq!(
            &hex::encode(Sha256::digest(&bytes)),
            want,
            "{name} drifted from its [kernel-keyring] pin"
        );
        concat.extend_from_slice(&bytes);
    }

                                                                                             
                                                                                              
    let fprs: Vec<Fingerprint> = KERNEL_ORG_SIGNER_FPRS
        .iter()
        .map(|h| Fingerprint::from_hex(h).expect("const fingerprint parses"))
        .collect();
    let now = UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_UNIX);
    Keyring::load(&concat, &fprs, now)
        .expect("the production keyring must load with the real consumer pins");
}

                                                                                                     
  
                                                                                                  
                                                                                        
                                                                                                    

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use orchard::deploy::kernel_bump::{KERNEL_ORG_BASE, KernelBump, bump_kernel};
use orchard::deploy::market_exec::{Stage, StoreLayout, resolve_layout};
use recipes_image_builder::Fetcher;
use recipes_image_builder::repo_manifest::RepoManifest;

struct Fx {
    version: String,
    now: SystemTime,
    signer_fpr: String,
    signer_asc: Vec<u8>,
    signer_sha: String,
    tar_xz: Vec<u8>,
    tar_sign: Vec<u8>,
    tampered_xz: Vec<u8>,
    unpinned_sign: Vec<u8>,
    bomb_xz: Vec<u8>,
    crafted_sign: Vec<u8>,
}

fn fx() -> Fx {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel_bump/gen");
    let man: toml::Value =
        toml::from_str(&fs::read_to_string(d.join("MANIFEST.toml")).expect("manifest"))
            .expect("manifest parses");
    let read = |n: &str| fs::read(d.join(n)).unwrap_or_else(|e| panic!("fixture {n}: {e}"));
    let signer_asc = read("signer.asc");
    Fx {
        version: man["version"].as_str().expect("version").to_string(),
        now: UNIX_EPOCH
            + Duration::from_secs(man["fixture_now"].as_integer().expect("fixture_now") as u64),
        signer_fpr: man["keys"]["signer"]
            .as_str()
            .expect("signer fpr")
            .to_string(),
        signer_sha: hex::encode(Sha256::digest(&signer_asc)),
        signer_asc,
        tar_xz: read("payload.tar.xz"),
        tar_sign: read("payload.tar.sign"),
        tampered_xz: read("payload-tampered.tar.xz"),
        unpinned_sign: read("unpinned.tar.sign"),
        bomb_xz: read("bomb.tar.xz"),
        crafted_sign: read("crafted.sign"),
    }
}

struct Eco {
    _tmp: tempfile::TempDir,
    layout: StoreLayout,
    /// The four REAL pins.toml paths (orchard + seed-vault + fruit-basket + recipes).
    pins_paths: Vec<PathBuf>,
}

/// `<tmp>/eco/orchard` (+ keyring/kernel.org/signer.asc) with three sibling repos, each carrying the
/// SAME pins.toml whose `[kernel-keyring]` pins signer.asc at `keyring_sha`.
fn eco(fx: &Fx, keyring_sha: &str) -> Eco {
    let tmp = tempfile::tempdir().unwrap();
    let orchard = tmp.path().join("eco/orchard");
    fs::create_dir_all(orchard.join("keyring/kernel.org")).unwrap();
    fs::write(
        orchard.join("keyring/kernel.org/signer.asc"),
        &fx.signer_asc,
    )
    .unwrap();
    fs::create_dir_all(orchard.join("vendor")).unwrap();
    let z = "a".repeat(64);
    let pins = format!(
        "# fixture pins\n[kernel]\n# pinned kernel\nversion = \"6.18.34\"\nsha256 = \"{z}\"\n\n\
         [syslinux]\nversion = \"6.04-pre1\"\nsha256 = \"{z}\"\n\n\
         [rust]\nversion = \"1.96.0\"\nalpine_base = \"alpine:3.23\"\n\
         alpine_base_digest = \"sha256:{z}\"\n\
         toolchain_musl_url = \"https://static.rust-lang.org/dist/d/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"\n\
         toolchain_musl_sha256 = \"{z}\"\n\
         std_uefi_url = \"https://static.rust-lang.org/dist/d/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"\n\
         std_uefi_sha256 = \"{z}\"\ncontainer_digest = \"sha256:{z}\"\n\n\
         [kernel-keyring]\n\"signer.asc\" = \"{keyring_sha}\"\n\n\
         [rust-keyring]\n\"rust-signing.asc\" = \"{z}\"\n"
    );
    fs::write(
        orchard.join("repo-manifest.toml"),
        "schema-version = 1\n\
         [repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n\
         [repos.fruit-basket]\npath = \"../fruit-basket\"\nartifacts = [\"fb-acme\"]\n\
         [repos.recipes]\npath = \"../../recipes\"\nartifacts = [\"recipes-app\"]\n",
    )
    .unwrap();
    fs::write(orchard.join("consume-pins.toml"), "schema-version = 1\n").unwrap();
    let mut pins_paths = vec![orchard.join("pins.toml")];
    fs::write(&pins_paths[0], &pins).unwrap();
    for rel in ["eco/seed-vault", "eco/fruit-basket", "recipes"] {
        let dir = tmp.path().join(rel);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pins.toml");
        fs::write(&p, &pins).unwrap();
        pins_paths.push(p);
    }
    let manifest = RepoManifest::load(&orchard.join("repo-manifest.toml")).unwrap();
    let store = tmp.path().join("eco/artifact-store");
    let layout = resolve_layout(&manifest, orchard, store);
    Eco {
        _tmp: tmp,
        layout,
        pins_paths,
    }
}

/// URL→bytes transport fake; counts calls (proves fail-fast ordering: which fetches ever happened).
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

fn transport(fx: &Fx, sign: &[u8], xz: &[u8]) -> MapFetcher {
    MapFetcher {
        map: BTreeMap::from([
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.sign", fx.version),
                sign.to_vec(),
            ),
            (
                format!("{KERNEL_ORG_BASE}/linux-{}.tar.xz", fx.version),
                xz.to_vec(),
            ),
        ]),
        calls: Cell::new(0),
    }
}

fn snapshot(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| hex::encode(Sha256::digest(fs::read(p).unwrap())))
        .collect()
}

const TEST_CEILING: u64 = 1024 * 1024;                                                           

/// Leak the run's fixture fingerprint into a `&'static` slice — test-lifetime convenience only.
fn fprs_of(fx: &Fx) -> &'static [&'static str] {
    let s: &'static str = Box::leak(fx.signer_fpr.clone().into_boxed_str());
    Box::leak(vec![s].into_boxed_slice())
}

fn bump<'a>(fx: &Fx, f: &'a MapFetcher) -> KernelBump<'a> {
    KernelBump {
        fetch: f,
        now: fx.now,
        tar_ceiling: TEST_CEILING,
        signer_fprs: fprs_of(fx),
    }
}

#[test]
fn green_bump_stages_all_four_pins_and_swaps_byte_identically() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.tar_sign, &fx.tar_xz);
    let before = snapshot(&eco.pins_paths);

    let mut stage = Stage::new(&eco.layout).unwrap();
    bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).expect("green bump");
    assert_eq!(
        snapshot(&eco.pins_paths),
        before,
        "REAL trees untouched before the swap"
    );

    let swapped = stage.swap().unwrap();
    assert_eq!(swapped.len(), 4, "all four pins.toml copies swapped");
    let expected_sha = hex::encode(Sha256::digest(&fx.tar_xz));
    let texts: Vec<String> = eco
        .pins_paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect();
    for t in &texts {
        assert!(t.contains(&format!("version = \"{}\"", fx.version)));
        assert!(t.contains(&expected_sha), "the .xz sha is the new pin");
        assert!(t.contains("# pinned kernel"), "comments preserved");
        assert!(t.contains("[kernel-keyring]"), "keyring section untouched");
    }
    assert!(
        texts.windows(2).all(|w| w[0] == w[1]),
        "the four copies byte-agree (§3a-2)"
    );
}

#[test]
fn tampered_tarball_fails_with_nothing_pinned() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.tar_sign, &fx.tampered_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("PGP verify"),
        "a tampered tarball must fail the signature, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn unpinned_signer_fails_with_nothing_pinned() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.unpinned_sign, &fx.tar_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("PGP verify"),
        "an unpinned signer must fail try-all verification, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn keyring_pin_mismatch_fails_before_any_parse_or_fetch() {
    let fx = fx();
                                                                                                  
                                                                      
    let eco = eco(&fx, &"c".repeat(64));
    let f = transport(&fx, &fx.tar_sign, &fx.tar_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string()
            .contains("keyring pin mismatch BEFORE parse"),
        "got: {err}"
    );
    assert_eq!(
        f.calls.get(),
        0,
        "no fetch may precede the keyring pin check"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn decompression_bomb_trips_the_ceiling_and_survives() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.tar_sign, &fx.bomb_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("decompression-bomb"),
        "the 4 MiB bomb must trip the 1 MiB test ceiling, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn crafted_sign_fails_cleanly_before_the_tarball_fetch() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.crafted_sign, &fx.tar_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("parse") && err.to_string().contains(".tar.sign"),
        "a crafted .sign must fail at parse (cashew Malformed), got: {err}"
    );
    assert_eq!(
        f.calls.get(),
        1,
        "the crafted .sign must abort BEFORE the ~150 MB tarball fetch"
    );
    drop(stage);
    assert_eq!(
        snapshot(&eco.pins_paths),
        before,
        "nothing pinned — process alive"
    );
}

#[test]
fn trailing_bytes_after_the_xz_stream_fail_closed() {
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                  
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let mut poisoned = fx.tar_xz.clone();
    poisoned.extend_from_slice(b"attacker-controlled suffix the bake would extract");
    let f = transport(&fx, &fx.tar_sign, &poisoned);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("trailing byte") || err.to_string().contains("verify-bypass"),
        "trailing bytes past the xz stream must fail closed, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn a_concatenated_second_xz_stream_fails_closed() {
                                                                                                     
                                                                                                 
                                                                     
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let mut concat = fx.tar_xz.clone();
    concat.extend_from_slice(&fx.tar_xz);                                    
    let f = transport(&fx, &fx.tar_sign, &concat);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("trailing byte") || err.to_string().contains("verify-bypass"),
        "a concatenated second stream must fail closed, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn empty_and_truncated_xz_fail_closed() {
                                                                                               
                                                                                             
                                                                                                      
                                                                                                     
                                                                                              
    let fx = fx();
    for xz in [Vec::new(), fx.tar_xz[..fx.tar_xz.len() / 2].to_vec()] {
        let eco = eco(&fx, &fx.signer_sha);
        let f = transport(&fx, &fx.tar_sign, &xz);
        let before = snapshot(&eco.pins_paths);
        let mut stage = Stage::new(&eco.layout).unwrap();
        assert!(
            bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).is_err(),
            "an empty/truncated .xz must fail closed"
        );
        drop(stage);
        assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
    }
}

#[test]
fn oversized_sign_is_refused_before_parse() {
                                                                                                  
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let huge = vec![b'A'; 200 * 1024];                                 
    let f = transport(&fx, &huge, &fx.tar_xz);
    let before = snapshot(&eco.pins_paths);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    assert!(
        err.to_string().contains("sanity bound"),
        "an oversized .sign must be refused, got: {err}"
    );
    drop(stage);
    assert_eq!(snapshot(&eco.pins_paths), before, "nothing pinned");
}

#[test]
fn bad_version_is_refused_before_any_fetch() {
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    let f = transport(&fx, &fx.tar_sign, &fx.tar_xz);
    let mut stage = Stage::new(&eco.layout).unwrap();
    for bad in ["7.1", "6.1x", "6.1/../evil"] {
        let err = bump_kernel(&bump(&fx, &f), bad, &eco.layout, &mut stage).unwrap_err();
        assert!(err.to_string().contains("must be 6.N"), "got: {err}");
    }
    assert_eq!(f.calls.get(), 0, "a refused version never fetches");
}

#[test]
fn missing_sibling_pins_copy_fails_closed() {
                                                                                                  
                                                                                           
    let fx = fx();
    let eco = eco(&fx, &fx.signer_sha);
    fs::remove_file(&eco.pins_paths[3]).unwrap();                    
    let f = transport(&fx, &fx.tar_sign, &fx.tar_xz);
    let mut stage = Stage::new(&eco.layout).unwrap();
    let _err = bump_kernel(&bump(&fx, &f), &fx.version, &eco.layout, &mut stage).unwrap_err();
    drop(stage);
                                                                                                  
    for p in &eco.pins_paths[..3] {
        let t = fs::read_to_string(p).unwrap();
        assert!(
            t.contains("version = \"6.18.34\""),
            "no partial write landed in {}",
            p.display()
        );
    }
}
