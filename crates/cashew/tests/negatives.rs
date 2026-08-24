                                                              
//!
//! Every §7.3 row must fail with its NAMED error class. Most rows are asserted at the layer that
//! owns them; this file adds the rows only visible through the public API and records the
//! coverage map so a reviewer can cross the spec list off row-for-row:
//!
//! | §7.3 row                                    | where asserted                               |
//! |---------------------------------------------|----------------------------------------------|
//! | payload byte flip                           | api.rs `tampered_payload_is_bad_signature`   |
//! | sig-MPI byte flip (data sig)                | HERE `data_sig_mpi_flip`                     |
//! | each B field flipped / 8↔10 swap            | verify.rs unit `every_b_field_mutation_fails`|
//! | left16 corrupted                            | verify.rs unit `left16_quick_reject`         |
//! | sig by valid-but-UNPINNED key ⇒ BadSignature| api.rs `foreign_signer_is_bad_signature`     |
//! | expired subkey                              | policy.rs `expired_subkey_is_not_a_candidate`|
//! | enc-only subkey forced to sign              | policy.rs unit (below-crypto; gpg cannot     |
//! |                                             | produce a crypto-valid enc-signed sig)       |
//! | key-flags only unhashed                     | sig.rs unit + policy.rs `explicit_flags_law` |
//! | binding without back-sig                    | policy.rs unit (below-crypto)                |
//! | revoked subkey                              | policy.rs `revoked_subkey_is_not_a_candidate`|
//! | flipped byte in any keyring sig ⇒ load fails| policy.rs `tampered_real_self_cert…`         |
//! | trailing garbage in hashed area             | sig.rs unit                                  |
//! | critical unknown hashed                     | sig.rs unit                                  |
//! | duplicate creation-time                     | sig.rs unit                                  |
//! | SHA-1 subkey binding ⇒ WeakHash             | policy.rs `sha1_keyring_signatures…`         |
//! | UAT/Marker packet in keyring                | key.rs unit + HERE `uat_keyring_at_the_api`  |
//! | two primaries in one block                  | key.rs unit                                  |
//! | v3 sig ⇒ Unsupported                        | sig.rs unit + HERE `v3_data_sig_at_the_api`  |
//! | algo-3 sig ⇒ Unsupported                    | sig.rs unit                                  |
//! | SHA-1 data sig ⇒ WeakHash                   | api.rs `weak_hash_data_sig…`                 |
//! | multi-sig .sign ⇒ Unsupported               | api.rs `multi_sig_packet_input…`             |
//! | non-minimal MPI ⇒ Malformed                 | sig.rs unit                                  |
//! | binary (unarmored) input ⇒ Malformed        | armor.rs unit + HERE `binary_inputs_at_api`  |
//!
//! Unconstructible rows (documented, not silently skipped): a data signature BY an
//! encryption-only subkey and a crypto-valid governing self-cert WITHOUT key-flags cannot be
//! produced by gpg (it refuses both); their policy predicates are unit-tested below the crypto
//! layer in policy.rs (the no-skip law makes forged carriers die as BadSignature first).

#[path = "common/forge.rs"]
mod forge;

use cashew::{DetachedVerifier, Error, Fingerprint, Keyring};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_NOW: u64 = 1_781_100_000;

fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn manifest_fpr(key: &str) -> Fingerprint {
    let manifest = String::from_utf8(fixture("gen/MANIFEST.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key} ")))
        .unwrap();
    Fingerprint::from_hex(line.split('"').nth(1).unwrap()).unwrap()
}

/// A flipped byte inside the DATA signature's MPI region fails as BadSignature (the armored sig
/// re-armored around the mutated binary packet).
#[test]
fn data_sig_mpi_flip() {
    let keyring = Keyring::load(
        &fixture("gen/key_a.asc"),
        &[manifest_fpr("key_a")],
        at(FIXTURE_NOW),
    )
    .unwrap();
                                                                                             
                                                                     
    let mut bin = fixture("gen/sig_a_1b_sha256_leadingzero.sig");
    let last = bin.len() - 1;
    bin[last] ^= 0x01;
    let armored = forge::armor_block("SIGNATURE", &bin);
    let mut v = DetachedVerifier::new(&armored).unwrap();
    v.update(&fixture("gen/payload_1b.bin"));
    assert_eq!(v.finalize(&keyring).unwrap_err(), Error::BadSignature);
}

/// A User-Attribute packet inside a keyring is Malformed at the API (`Keyring::load`), not just
/// at the parse layer.
#[test]
fn uat_keyring_at_the_api() {
    let mut bin = {
        let armored = fixture("gen/key_a.asc");
                                                                                                 
                                                                                                 
                                         
                                                                                                 
                                                                                                  
                                                                                                
        drop(armored);
        let mut stream = forge::KeyForge::baseline(1_781_000_000).packet(6);
        stream.extend_from_slice(&forge::uid_packet(b"u"));
        stream.extend_from_slice(&forge::sig_packet_of_type(0x13, 1_781_000_000));
        stream
    };
    bin.extend_from_slice(&forge::frame_new_format(17, b"uat-payload"));
    let armored = forge::armor_block("PUBLIC KEY BLOCK", &bin);
                                                                         
    let pin = manifest_fpr("key_a");
    assert_eq!(
        Keyring::load(&armored, &[pin], at(FIXTURE_NOW)).unwrap_err(),
        Error::Malformed("packet tag outside keyring whitelist")
    );
}

/// A v3 data signature is Unsupported at the API.
#[test]
fn v3_data_sig_at_the_api() {
    let mut f = forge::SigForge::baseline(1);
    f.version = 3;
    let armored = forge::armor_block("SIGNATURE", &f.packet());
    assert_eq!(
        DetachedVerifier::new(&armored).unwrap_err(),
        Error::Unsupported("non-v4 signature version")
    );
}

/// Binary (unarmored) input to BOTH public entry points is Malformed (§5.1: armored only).
#[test]
fn binary_inputs_at_the_api() {
    let sig_bin = forge::SigForge::baseline(1).packet();
    assert_eq!(
        DetachedVerifier::new(&sig_bin).unwrap_err(),
        Error::Malformed("expected armor BEGIN line")
    );
    let key_bin = forge::KeyForge::baseline(1).packet(6);
    let pin = manifest_fpr("key_a");
    assert_eq!(
        Keyring::load(&key_bin, &[pin], at(FIXTURE_NOW)).unwrap_err(),
        Error::Malformed("expected armor BEGIN line")
    );
}
