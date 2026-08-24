                                                                                              
//! `Keyring::load` / `DetachedVerifier` / sealed `Verified`. Fixture fingerprints come from
//! gen/MANIFEST.toml (fresh per regeneration — never hardcoded); the real pins are the vendored
//! METADATA constants.

#[path = "common/forge.rs"]
mod forge;

use cashew::{DetachedVerifier, Error, Fingerprint, Keyring, SigningKey, Verified};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Stable corpus clocks (gen.sh / MANIFEST.toml; stable across regenerations by design).
const GEN_TIME: u64 = 1_781_000_000;
const FIXTURE_NOW: u64 = 1_781_100_000;
const GREG_PIN: &str = "647F28654894E3BD457199BE38DBBDC86092693E";
const SASHA_PIN: &str = "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC";

fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A gen key's fingerprint out of MANIFEST.toml (`key_x = "HEX…"` lines).
fn manifest_fpr(key: &str) -> Fingerprint {
    let manifest = String::from_utf8(fixture("gen/MANIFEST.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key} ")))
        .unwrap_or_else(|| panic!("no {key} in MANIFEST"));
    let hex = line.split('"').nth(1).unwrap();
    Fingerprint::from_hex(hex).unwrap()
}

/// Load a keyring from concatenated gen blocks with MANIFEST-derived pins.
fn load_gen(file_keys: &[&str], pin_keys: &[&str], now: u64) -> Result<Keyring, Error> {
    let mut bytes = Vec::new();
    for k in file_keys {
        bytes.extend_from_slice(&fixture(&format!("gen/key_{k}.asc")));
    }
    let pins: Vec<Fingerprint> = pin_keys
        .iter()
        .map(|p| manifest_fpr(&format!("key_{p}")))
        .collect();
    Keyring::load(&bytes, &pins, at(now))
}

fn verify(sig_rel: &str, payload: &[u8], keyring: &Keyring) -> Result<Verified, Error> {
    let mut v = DetachedVerifier::new(&fixture(sig_rel))?;
    v.update(payload);
    v.finalize(keyring)
}

/// Shape (a): the primary-signs kernel-dev shape verifies via `SigningKey::Primary` with the
                                                      
#[test]
fn shape_a_verifies_via_primary() {
    let keyring = load_gen(&["a"], &["a"], FIXTURE_NOW).unwrap();
    let v = verify(
        "gen/sig_a_1kib_sha256.asc",
        &fixture("gen/payload_1kib.bin"),
        &keyring,
    )
    .unwrap();
    assert_eq!(*v.signing_key(), SigningKey::Primary);
    assert_eq!(*v.signer_fingerprint(), manifest_fpr("key_a"));
    assert_eq!(v.hash_algo(), 8);
    assert_eq!(v.created(), at(GEN_TIME));
}

/// Shape (b): the chain shape verifies via `SigningKey::Subkey(_)` under the PRIMARY's pin
                
#[test]
fn shape_b_verifies_via_subkey() {
    let keyring = load_gen(&["b"], &["b"], FIXTURE_NOW).unwrap();
    let v = verify(
        "gen/sig_b_1b_sha512.asc",
        &fixture("gen/payload_1b.bin"),
        &keyring,
    )
    .unwrap();
    assert!(matches!(v.signing_key(), SigningKey::Subkey(_)));
    assert_eq!(*v.signer_fingerprint(), manifest_fpr("key_b"));
    assert_eq!(v.hash_algo(), 10);
}

                                                                                                
/// identical `Verified` fields.
#[test]
fn chunk_invariance_end_to_end() {
    let keyring = load_gen(&["a"], &["a"], FIXTURE_NOW).unwrap();
    let payload = fixture("gen/payload_1kib.bin");
    let sig = fixture("gen/sig_a_1kib_sha256.asc");

    let run = |chunks: &[&[u8]]| -> Verified {
        let mut v = DetachedVerifier::new(&sig).unwrap();
        for c in chunks {
            v.update(c);
        }
        v.finalize(&keyring).unwrap()
    };
    let slab = run(&[&payload]);
    let bytewise = run(&payload.chunks(1).collect::<Vec<_>>());
    let mut ragged_chunks: Vec<&[u8]> = Vec::new();
    let mut off = 0;
    for step in [3usize, 17, 128, 400, 476] {
        ragged_chunks.push(&payload[off..off + step]);
        off += step;
    }
    ragged_chunks.push(&payload[off..]);
    let ragged = run(&ragged_chunks);

    for v in [&bytewise, &ragged] {
        assert_eq!(v.signer_fingerprint(), slab.signer_fingerprint());
        assert_eq!(v.signing_key(), slab.signing_key());
        assert_eq!(v.created(), slab.created());
        assert_eq!(v.hash_algo(), slab.hash_algo());
    }
}

/// A signature by a key NOT in the keyring — including a subkey-signed sig against a
/// primary-only keyring — is `BadSignature`, NEVER `UnknownSigner` (§14 E-1: issuer hints do not
/// select an error class; try-all just fails).
#[test]
fn foreign_signer_is_bad_signature() {
    let keyring = load_gen(&["a"], &["a"], FIXTURE_NOW).unwrap();
    assert_eq!(
        verify(
            "gen/sig_b_1b_sha256.asc",
            &fixture("gen/payload_1b.bin"),
            &keyring,
        )
        .unwrap_err(),
        Error::BadSignature
    );
}

#[test]
fn tampered_payload_is_bad_signature() {
    let keyring = load_gen(&["a"], &["a"], FIXTURE_NOW).unwrap();
    assert_eq!(
        verify("gen/sig_a_1b_sha256.asc", b"B", &keyring).unwrap_err(),
        Error::BadSignature
    );
}

/// A pinned fingerprint absent from the keyring FILE fails at LOAD — the only place
/// `UnknownSigner` exists (§14 E-1).
#[test]
fn absent_pin_is_unknown_signer_at_load() {
    assert_eq!(
        load_gen(&["a"], &["a", "c"], FIXTURE_NOW).unwrap_err(),
        Error::UnknownSigner
    );
}

/// An UNPINNED extra block in the keyring file is `Malformed` — the vendored file is the
/// contract's output; nothing unaccounted loads (§6.5).
#[test]
fn extra_unpinned_block_is_malformed() {
    assert_eq!(
        load_gen(&["a", "c"], &["a"], FIXTURE_NOW).unwrap_err(),
        Error::Malformed("unpinned key block in keyring input")
    );
}

/// The REAL vendored keyring (both signers concatenated, §5.0 shape) loads under the real pins at
/// fixture_now.
#[test]
fn real_keyring_loads_under_the_real_pins() {
    let mut bytes = fixture("real/greg-pruned.asc");
    bytes.extend_from_slice(&fixture("real/sasha-pruned.asc"));
    let pins = [
        Fingerprint::from_hex(GREG_PIN).unwrap(),
        Fingerprint::from_hex(SASHA_PIN).unwrap(),
    ];
    assert!(Keyring::load(&bytes, &pins, at(FIXTURE_NOW)).is_ok());
}

                                                                                              
/// admitted); finalizing over the WRONG stream against the real keyring fails as `BadSignature`
/// (the 1.4 GB tar is not a test asset — full verify is the consumer cycle's gate).
#[test]
fn real_sign_constructs_and_wires_end_to_end() {
    let mut bytes = fixture("real/greg-pruned.asc");
    bytes.extend_from_slice(&fixture("real/sasha-pruned.asc"));
    let pins = [
        Fingerprint::from_hex(GREG_PIN).unwrap(),
        Fingerprint::from_hex(SASHA_PIN).unwrap(),
    ];
    let keyring = Keyring::load(&bytes, &pins, at(FIXTURE_NOW)).unwrap();
    let mut v = DetachedVerifier::new(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
    v.update(b"not the kernel tarball");
    assert_eq!(v.finalize(&keyring).unwrap_err(), Error::BadSignature);
}

/// The finalize-time sig-expiry pair (hashed critical subpacket 3): EXPIRED at fixture_now,
/// verifying fine at gen_time+1000 (§6.3 finalize policy).
#[test]
fn expired_data_sig_is_policy_violation() {
    let keyring = load_gen(&["a"], &["a"], FIXTURE_NOW).unwrap();
    assert_eq!(
        verify(
            "gen/sig_a_1b_sha256_expiring.asc",
            &fixture("gen/payload_1b.bin"),
            &keyring,
        )
        .unwrap_err(),
        Error::PolicyViolation("data signature expired")
    );
    let early = load_gen(&["a"], &["a"], GEN_TIME + 1000).unwrap();
    assert!(verify(
        "gen/sig_a_1b_sha256_expiring.asc",
        &fixture("gen/payload_1b.bin"),
        &early,
    )
    .is_ok());
}

/// The `.sign` whitelist at the API: a SHA-1 data signature is `WeakHash(2)` at construction
/// (§14 E-2 — before any byte is streamed).
#[test]
fn weak_hash_data_sig_refused_at_construction() {
    assert_eq!(
        DetachedVerifier::new(&fixture("gen/sig_a_1b_sha1_weak.asc")).unwrap_err(),
        Error::WeakHash(2)
    );
}

/// Two signature packets inside ONE armor block = the multi-sig form, `Unsupported` (§5.2).
#[test]
fn multi_sig_packet_input_is_unsupported() {
    let one = forge::SigForge::baseline(1).packet();
    let two = [one.clone(), one].concat();
    let armored = forge::armor_block("SIGNATURE", &two);
    assert_eq!(
        DetachedVerifier::new(&armored).unwrap_err(),
        Error::Unsupported("multi-signature .sign input")
    );
}

/// A non-0x00 signature type in a `.sign` is `Unsupported` (the detached-binary whitelist).
#[test]
fn non_binary_document_sig_type_is_unsupported() {
    let mut f = forge::SigForge::baseline(1);
    f.sig_type = 0x01;                           
    let armored = forge::armor_block("SIGNATURE", &f.packet());
    assert_eq!(
        DetachedVerifier::new(&armored).unwrap_err(),
        Error::Unsupported("non-binary-document signature type")
    );
}

/// An embedded-signature subpacket on a DATA signature is outside the whitelist (the same
/// structural rule the keyring policy applies — an unverifiable blob has no legal carrier here).
#[test]
fn embedded_sig_on_data_sig_is_malformed() {
    let mut f = forge::SigForge::baseline(1);
    f.unhashed = forge::subpacket(32, false, b"blob");
    let armored = forge::armor_block("SIGNATURE", &f.packet());
    assert_eq!(
        DetachedVerifier::new(&armored).unwrap_err(),
        Error::Malformed("embedded signature outside a subkey binding")
    );
}

/// The forge's independent armor round-trips through the real decoder (a writer/decoder
/// differential on the armor layer itself).
#[test]
fn forge_armor_roundtrips_through_the_api() {
    let sig = forge::SigForge::baseline(1).packet();
    let armored = forge::armor_block("SIGNATURE", &sig);
                                                                                               
                     
    assert!(DetachedVerifier::new(&armored).is_ok());
}
