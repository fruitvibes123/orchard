                                                                                                      
//! EXCEPTION). Everything through the PUBLIC API only. This is the path the Rust release key forces:
//! its self-certs are all SHA-1, so the strict `Keyring::load` (E-2 `{SHA-256,512}`-only) CANNOT load
//! it. The bare path trusts the key by the caller's sha256 pin (established by the consumer, NOT here)
//! plus the out-of-band-grounded fingerprint, binds the PRIMARY ONLY, and reuses the SAME
//! `DetachedVerifier::finalize` for a strong (RSA/SHA-512) DATA signature. Fixture fingerprints come
//! from rust/gen/MANIFEST.toml (fresh per regeneration — never hardcoded).

use cashew::{DetachedVerifier, Error, Fingerprint, Keyring, SigningKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Stable corpus clocks (rust/gen.sh / MANIFEST.toml).
const GEN_TIME: u64 = 1_781_000_000;
const FIXTURE_NOW: u64 = 1_781_100_000;

fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A gen key's fingerprint out of rust/gen/MANIFEST.toml (`key = "HEX…"` lines).
fn manifest_fpr(key: &str) -> Fingerprint {
    let manifest = String::from_utf8(fixture("gen/MANIFEST.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key} ")))
        .unwrap_or_else(|| panic!("no {key} in MANIFEST"));
    let hex = line.split('"').nth(1).unwrap();
    Fingerprint::from_hex(hex).unwrap()
}

fn rust_fpr() -> Fingerprint {
    manifest_fpr("rust_key")
}

/// Verify `sig_rel` (armored detached) over the fixture manifest against `keyring`.
fn verify(keyring: &Keyring, sig_rel: &str) -> Result<cashew::Verified, Error> {
    let mut v = DetachedVerifier::new(&fixture(sig_rel)).unwrap();
    v.update(&fixture("gen/manifest.bin"));
    v.finalize(keyring)
}

/// (a) The SHA-1-self-signed key LOADS via `load_pinned_bare` — and is REFUSED by the strict
/// `Keyring::load` with `WeakHash(2)` (the self-cert digest). This is the exception being exercised
/// AND the norm staying intact.
#[test]
fn bare_loads_sha1_key_that_strict_load_refuses() {
    let key = fixture("gen/rust_key.asc");
    let pins = [rust_fpr()];

    assert!(Keyring::load_pinned_bare(&key, &pins, at(FIXTURE_NOW)).is_ok());
    assert_eq!(
        Keyring::load(&key, &pins, at(FIXTURE_NOW)).unwrap_err(),
        Error::WeakHash(2),
    );
}

/// (b) A detached RSA/SHA-512 sig by the pinned PRIMARY verifies against the bare keyring, and the
/// sealed `Verified` names the pinned primary + `SigningKey::Primary`.
#[test]
fn bare_primary_data_sig_verifies() {
    let key = fixture("gen/rust_key.asc");
    let kr = Keyring::load_pinned_bare(&key, &[rust_fpr()], at(FIXTURE_NOW)).unwrap();

    let verified = verify(&kr, "gen/sig_primary_sha512.asc").unwrap();
    assert_eq!(*verified.signer_fingerprint(), rust_fpr());
    assert_eq!(*verified.signing_key(), SigningKey::Primary);
    assert_eq!(verified.hash_algo(), 10);                        
}

                                                                                              
/// primary's own sig still verifies, but a sig by the APPENDED SUBKEY does NOT — the bare path never
/// binds subkey material, so an attacker who appends a signing subkey to the genuine key gains nothing.
#[test]
fn bare_binds_primary_only_appended_subkey_sig_fails() {
    let key = fixture("gen/rust_key_appended_subkey.asc");
    let kr = Keyring::load_pinned_bare(&key, &[rust_fpr()], at(FIXTURE_NOW)).unwrap();

                                                                                  
    assert!(verify(&kr, "gen/sig_primary_sha512.asc").is_ok());
                                                                                               
    assert_eq!(
        verify(&kr, "gen/sig_subkey_sha512.asc").unwrap_err(),
        Error::BadSignature,
    );
}

/// (d) A sig by an UNPINNED (foreign) key does not verify — the bare keyring holds only the pinned
/// primary's material.
#[test]
fn bare_unpinned_signer_sig_fails() {
    let key = fixture("gen/rust_key.asc");
    let kr = Keyring::load_pinned_bare(&key, &[rust_fpr()], at(FIXTURE_NOW)).unwrap();
    assert_eq!(
        verify(&kr, "gen/sig_foreign_sha512.asc").unwrap_err(),
        Error::BadSignature,
    );
}

/// (e) A pinned fingerprint absent from the blob is `UnknownSigner` at LOAD (E-1 preserved) — the
/// foreign fingerprint is not the rust key's.
#[test]
fn bare_pin_absent_from_blob_is_unknown_signer() {
    let key = fixture("gen/rust_key.asc");
    assert_eq!(
        Keyring::load_pinned_bare(&key, &[manifest_fpr("foreign_key")], at(FIXTURE_NOW))
            .unwrap_err(),
        Error::UnknownSigner,
    );
}

                                                                                                   
/// bare keyring built with a clock BEFORE the sig's creation rejects the genuine sig as future-dated.
/// A `now=0` (epoch) bare keyring would reject every real manifest — the bump must pass its wall clock.
#[test]
fn bare_carries_now_for_the_data_sig_future_check() {
    let key = fixture("gen/rust_key.asc");
                                                                                     
    let kr = Keyring::load_pinned_bare(&key, &[rust_fpr()], at(GEN_TIME - 100_000)).unwrap();
    assert_eq!(
        verify(&kr, "gen/sig_primary_sha512.asc").unwrap_err(),
        Error::PolicyViolation("data signature created in the future"),
    );
}

                                                                                            
/// vendoring-tamper that appends material) fails to LOAD — mirroring the strict path's every-block-
/// pinned discipline. (Within-block junk is already rejected by the reused `parse_block` grammar.)
#[test]
fn bare_rejects_unaccounted_appended_block() {
    let mut blob = fixture("gen/rust_key.asc");
    blob.extend_from_slice(&fixture("gen/foreign_key.asc"));
    assert_eq!(
        Keyring::load_pinned_bare(&blob, &[rust_fpr()], at(FIXTURE_NOW)).unwrap_err(),
        Error::Malformed("unpinned key block in keyring input"),
    );
}
