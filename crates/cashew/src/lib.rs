//! `cashew` — a verify-only OpenPGP/RSA detached-signature checker.
//!
//! cashew verifies an **armored detached OpenPGP signature** (the kernel.org `linux-X.Y.Z.tar.sign`
//! shape) over a **caller-streamed** byte sequence, against a **caller-supplied vendored keyring**
//! filtered by **caller-supplied pinned fingerprints**. It is the verify primitive the `market
//! upgrade --kernel` pin bump consumes; a verify BYPASS here would let an attacker-supplied kernel
//! source tree enter the box build supply chain, so the whole crate is a whitelist: every form not
//! explicitly permitted is a named [`Error`], and refusal is the only non-success outcome.
//!
//! What makes it safe by construction:
//! - **Whitelist grammar** (RFC 4880 subset): v4 signatures, RSA, SHA-256/512 only; every unlisted
//!   version/algorithm/packet/length form is rejected (see the module docs under `src/`).
//! - **No-skip law** (the strict [`Keyring::load`] default): every signature in a strict-loaded
//!   keyring must cryptographically verify in its positional role, or the whole load fails — there is
//!   no tolerate-and-skip channel. The ONE documented exception is [`Keyring::load_pinned_bare`]
                                                                                                      
//!   by the caller's sha256 byte-pin + an out-of-band fingerprint, binds the PRIMARY ONLY, and SKIPS
//!   self-cert verification — never accepting SHA-1 as a verify input (the data sig is RSA/SHA-512).
//!   It is scoped by a fail-closed call-site allowlist (`tests/scoping.rs`); see `src/pinned.rs`.
//! - **SHA-1 is a fingerprint-only primitive** (§14 E-2): it is constructed at exactly one site
//!   (the v4 fingerprint in `key.rs`) and NEVER for any signature of any role — the bare path skips
//!   self-certs, it does not hash them.
//! - **Zero hand-rolled cryptography:** the RFC-4880 *format* layer is hand-rolled; all hashing and
//!   RSA verification delegate to the in-tree audited `rsa` / `sha2` / `sha1` crates. Zero net-new
//!   crates enter the workspace closure.
//! - **No-panic parse paths** behind a `catch_unwind` boundary at every fallible public entry, so
//!   hostile `.sign` / keyring bytes yield a structured [`Error::ParserPanic`], never a crash.
//! - **Issuer hints carry no trust** (§6.1/§14 E-1): verification computes H once and tries every
//!   validated candidate key of every pinned signer; [`Error::UnknownSigner`] exists at LOAD time
//!   only (a pin absent from the file) — a failed verification is always [`Error::BadSignature`].
//! - **Sealed [`Verified`]:** no public constructor; the only way to hold one is a successful
//!   verification.
//!
                                                                                                
//! (audit-converged R1→R4) in the cookbook launchpad. Consumers vendoring a keyring must follow the
//! §5.0 pruned, toolchain-pinned export contract + sha256-pin the keyring file.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

                                                                                                 
                                                                                      
                                                                                                  
                                                                                       
                                                                      
const _: () = assert!(
    cfg!(panic = "unwind"),
    "cashew's catch_unwind fail-closed boundary requires panic = \"unwind\""
);

pub(crate) mod armor;
pub mod error;
pub(crate) mod key;
pub(crate) mod packet;
                                                                                                         
                                                                                                     
pub(crate) mod pinned;
pub(crate) mod policy;
pub(crate) mod reader;
pub(crate) mod sig;
pub(crate) mod verify;

                                                                                                    
                                                                                     
#[cfg(test)]
#[path = "../tests/common/forge.rs"]
pub(crate) mod forge;

pub use error::Error;
pub use key::Fingerprint;
pub use policy::SigningKey;

use crate::limits::SKEW_SECS;
use crate::policy::validate_block;
use crate::sig::{parse_sig, SigPacket};
use crate::verify::{left16_matches, rsa_verify, SigHash};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

                                                                                                  
/// never re-literal'd at a use site.
pub(crate) mod limits {
    /// A detached `.sign` file is tiny (~1 KiB); cap generously.
    pub const SIGN_MAX: usize = 64 * 1024;
    /// A pruned kernel-dev keyring is a few KiB (real: Greg 3439 B, Sasha 1644 B); cap generously.
    pub const KEYRING_MAX: usize = 4 * 1024 * 1024;
    /// Largest legitimate single packet body (a certification-laden signature; an RSA-8192 key body
    /// is ~1 KiB).
    pub const PACKET_BODY_MAX: usize = 64 * 1024;
    /// Upper bound on packets in one keyring input.
    pub const PACKETS_MAX: usize = 4096;
    /// Upper bound on subpackets in one signature subpacket area.
    pub const SUBPACKETS_MAX: usize = 256;
    /// Clock skew tolerance for creation-time sanity (24 h).
    pub const SKEW_SECS: u64 = 86_400;
}

/// One pinned signer's owned, validated signing material (extracted from the keyring bytes at
/// load — nothing borrows the input after `load` returns).
#[derive(Debug)]
struct OwnedCandidate {
    n: Vec<u8>,
    e: Vec<u8>,
    created: u32,
    id: SigningKey,
}

#[derive(Debug)]
struct OwnedSigner {
    primary_fpr: Fingerprint,
    candidates: Vec<OwnedCandidate>,
}

/// A fully-validated keyring: every pinned fingerprint resolved to a block that passed the whole
/// §6.3 load policy (the no-skip law included), with `now` captured ONCE so a bump run evaluates
/// one consistent clock.
#[derive(Debug)]
pub struct Keyring {
    signers: Vec<OwnedSigner>,
    now: u64,
}

impl Keyring {
    /// Load + validate a vendored keyring (§6.5): caps → armor → per-block grammar → the §6.3
    /// policy per pin. EVERY pin must resolve to a block (absent = [`Error::UnknownSigner`] — the
    /// only place it fires, §14 E-1); every block must be pinned (an extra block =
    /// [`Error::Malformed`] — the vendored file is the contract's output, nothing unaccounted).
    pub fn load(
        keyring_bytes: &[u8],
        pins: &[Fingerprint],
        now: SystemTime,
    ) -> Result<Self, Error> {
        catch_unwind(AssertUnwindSafe(|| load_inner(keyring_bytes, pins, now)))
            .map_err(|_| Error::ParserPanic)?
    }
}

fn load_inner(
    keyring_bytes: &[u8],
    pins: &[Fingerprint],
    now: SystemTime,
) -> Result<Keyring, Error> {
    let now_secs = unix_secs(now)?;
    let blocks_bin = armor::decode_keyring(keyring_bytes)?;
    let walked = blocks_bin
        .iter()
        .map(|b| packet::walk(b))
        .collect::<Result<Vec<_>, _>>()?;
    let parsed = walked
        .iter()
        .map(|p| key::parse_block(p))
        .collect::<Result<Vec<_>, _>>()?;

    let mut used = vec![false; parsed.len()];
    let mut signers = Vec::new();
    for pin in pins {
        let idx = parsed
            .iter()
            .position(|b| b.primary_fpr == *pin)
            .ok_or(Error::UnknownSigner)?;
        let already_used = used
            .get(idx)
            .copied()
            .ok_or(Error::Malformed("keyring block index out of range"))?;
        if already_used {
                                                                        
            continue;
        }
        if let Some(slot) = used.get_mut(idx) {
            *slot = true;
        }
        let block = parsed
            .get(idx)
            .ok_or(Error::Malformed("keyring block index out of range"))?;
        let v = validate_block(block, pin, now_secs)?;
        signers.push(OwnedSigner {
            primary_fpr: v.primary_fpr,
            candidates: v
                .candidates
                .iter()
                .map(|c| OwnedCandidate {
                    n: c.n.to_vec(),
                    e: c.e.to_vec(),
                    created: c.created,
                    id: c.id.clone(),
                })
                .collect(),
        });
    }
    if used.iter().any(|u| !u) {
        return Err(Error::Malformed("unpinned key block in keyring input"));
    }
    Ok(Keyring {
        signers,
        now: now_secs,
    })
}

/// A streaming detached-signature verification in progress: parse the `.sign` once, stream the
/// signed bytes, then [`DetachedVerifier::finalize`] against a [`Keyring`]. The verifier is
/// CONSUMED by `finalize` — no retry-with-mutated-state surface exists (§6.2).
pub struct DetachedVerifier {
    /// The owned tag-2 packet body (re-parsed at finalize — same bytes, deterministic parse).
    sig_body: Vec<u8>,
    hash: SigHash,
}

impl core::fmt::Debug for DetachedVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DetachedVerifier").finish_non_exhaustive()
    }
}

impl DetachedVerifier {
    /// Parse an armored `.sign` under the detached-signature whitelist (§5.2/§5.3): exactly one
    /// tag-2 packet; v4; RSA; type 0x00 (binary document); hash ∈ {SHA-256, SHA-512} — the digest
    /// is initialized here, so a refused hash never processes a byte.
    pub fn new(armored_sig: &[u8]) -> Result<Self, Error> {
        catch_unwind(AssertUnwindSafe(|| Self::new_inner(armored_sig)))
            .map_err(|_| Error::ParserPanic)?
    }

    fn new_inner(armored_sig: &[u8]) -> Result<Self, Error> {
        let bin = armor::decode_sign(armored_sig)?;
        let packets = packet::walk(&bin)?;
        let only = match packets.as_slice() {
            [only] => only,
            _ => return Err(Error::Unsupported("multi-signature .sign input")),
        };
        if only.tag != 2 {
            return Err(Error::Unsupported("non-signature packet in .sign input"));
        }
        let sig = parse_sig(only.body)?;
        if sig.sig_type != 0x00 {
            return Err(Error::Unsupported("non-binary-document signature type"));
        }
                                                                                                   
                                                                                             
        if sig.embedded_sig.is_some() {
            return Err(Error::Malformed(
                "embedded signature outside a subkey binding",
            ));
        }
        let hash = SigHash::for_algo(sig.hash_algo)?;
        Ok(DetachedVerifier {
            sig_body: only.body.to_vec(),
            hash,
        })
    }

    /// Stream the signed bytes (the uncompressed tar, at the consumer). Infallible digest feed;
                                         
    pub fn update(&mut self, chunk: &[u8]) {
        self.hash.update(chunk);
    }

    /// Append the v4 trailer, quick-reject on left16, then try EVERY candidate signing key of
    /// EVERY pinned signer (§6.1 — issuer hints select nothing); on the winner, apply the
    /// finalize-time policy (§6.3): creation sanity, creation ≥ the verifying key's, signature
    /// expiry. ALL candidates failing = [`Error::BadSignature`] (never `UnknownSigner`, §14 E-1).
    pub fn finalize(self, keyring: &Keyring) -> Result<Verified, Error> {
        catch_unwind(AssertUnwindSafe(move || {
            finalize_inner(self.sig_body, self.hash, keyring)
        }))
        .map_err(|_| Error::ParserPanic)?
    }
}

fn finalize_inner(sig_body: Vec<u8>, hash: SigHash, keyring: &Keyring) -> Result<Verified, Error> {
    let sig = parse_sig(&sig_body)?;
                                                                                                   
                                                                                                   
                                                                                                
                                                                                                    
                                                                                                   
                                                                                                 
    if sig.sig_type != 0x00 {
        return Err(Error::Unsupported("non-binary-document signature type"));
    }
    if sig.embedded_sig.is_some() {
        return Err(Error::Malformed(
            "embedded signature outside a subkey binding",
        ));
    }
    let digest = hash.finalize_with_sig_fields(&sig);
    if !left16_matches(&sig, &digest) {
        return Err(Error::BadSignature);
    }
    let winner = keyring
        .signers
        .iter()
        .flat_map(|s| s.candidates.iter().map(move |c| (s, c)))
        .find(|(_, c)| rsa_verify(&c.n, &c.e, sig.hash_algo, &digest, sig.s_mpi).is_ok())
        .ok_or(Error::BadSignature)?;
    winner_policy(&sig, winner.1.created, keyring.now)?;
    Ok(Verified {
        signer_fingerprint: winner.0.primary_fpr,
        signing_key: winner.1.id.clone(),
        created: sig.created,
        hash_algo: sig.hash_algo,
    })
}

/// The finalize-time data-signature policy (§6.3), applied to the WINNING candidate: hashed
/// creation ≤ now + skew; creation ≥ the verifying key's creation; hashed signature-expiration
/// honored when set (value 0 = never expires, per RFC 4880 §5.2.3.10 — same convention as
/// key-expiration).
fn winner_policy(sig: &SigPacket<'_>, key_created: u32, now: u64) -> Result<(), Error> {
    if u64::from(sig.created) > now.saturating_add(SKEW_SECS) {
        return Err(Error::PolicyViolation(
            "data signature created in the future",
        ));
    }
    if sig.created < key_created {
        return Err(Error::PolicyViolation(
            "data signature predates its verifying key",
        ));
    }
    if let Some(exp) = sig.sig_expiry.filter(|&e| e != 0) {
        if now > u64::from(sig.created).saturating_add(u64::from(exp)) {
            return Err(Error::PolicyViolation("data signature expired"));
        }
    }
    Ok(())
}

fn unix_secs(now: SystemTime) -> Result<u64, Error> {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::PolicyViolation("clock before the unix epoch"))
}

/// A successful verification — SEALED: no public constructor, getters only. Holding one means the
/// data stream verified against a pinned signer's validated key under the whole policy.
#[derive(Debug)]
pub struct Verified {
    signer_fingerprint: Fingerprint,
    signing_key: SigningKey,
    created: u32,
    hash_algo: u8,
}

impl Verified {
    /// The PINNED PRIMARY fingerprint of the signer that verified (even when a subkey signed).
    pub fn signer_fingerprint(&self) -> &Fingerprint {
        &self.signer_fingerprint
    }

                                                                                      
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The signature's hashed creation time.
    pub fn created(&self) -> SystemTime {
                                                                                                    
                                                                       
        UNIX_EPOCH
            .checked_add(Duration::from_secs(u64::from(self.created)))
            .unwrap_or(UNIX_EPOCH)
    }

    /// The signature's (whitelisted) hash algorithm id: 8 = SHA-256, 10 = SHA-512.
    pub fn hash_algo(&self) -> u8 {
        self.hash_algo
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod anchor_tests {
    use super::*;
    use crate::forge::SigForge;

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    const FIXTURE_NOW: u64 = 1_781_100_000;
    const GREG_PIN: &str = "647F28654894E3BD457199BE38DBBDC86092693E";
    const SASHA_PIN: &str = "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC";

                                                                                              
    /// under the real pins, Greg's candidate set is exactly {Primary}, AND the real `.sign`'s
    /// HASHED issuer fingerprint equals that pinned primary — the two real fixtures are mutually
    /// verifiable in structure.
    #[test]
    fn real_issuer_consistency_anchor() {
        let mut bytes = fixture("real/greg-pruned.asc");
        bytes.extend_from_slice(&fixture("real/sasha-pruned.asc"));
        let greg = Fingerprint::from_hex(GREG_PIN).unwrap();
        let sasha = Fingerprint::from_hex(SASHA_PIN).unwrap();
        let keyring = Keyring::load(
            &bytes,
            &[greg, sasha],
            UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW),
        )
        .unwrap();

        let greg_signer = keyring
            .signers
            .iter()
            .find(|s| s.primary_fpr == greg)
            .unwrap();
        assert_eq!(greg_signer.candidates.len(), 1);
        assert!(matches!(greg_signer.candidates[0].id, SigningKey::Primary));

                                                                                                     
        let bin = armor::decode_sign(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
        let packets = packet::walk(&bin).unwrap();
        let sig = parse_sig(packets[0].body).unwrap();
        assert_eq!(sig.issuer_fpr_diag, Some(greg.0));
    }

    /// The finalize winner-policy branches, unit-level (gpg cannot produce a signature that
    /// predates its key — it refuses to sign with a not-yet-existing key — so this branch is
    /// tested on the pure function; documented in the T10 battery).
    #[test]
    fn winner_policy_branches() {
        let parse = |f: &SigForge| -> Vec<u8> { f.body() };

                                    
        let body = parse(&SigForge::baseline(1000));
        let sig = parse_sig(&body).unwrap();
        assert!(winner_policy(&sig, 1000, 5000).is_ok());

                                                                                                 
                                                              
        let body = parse(&SigForge::baseline(1_000_000));
        let sig = parse_sig(&body).unwrap();
        assert_eq!(
            winner_policy(&sig, 500, 1_000_000 - 86_400 - 1).unwrap_err(),
            Error::PolicyViolation("data signature created in the future")
        );

                                      
        let body = parse(&SigForge::baseline(999));
        let sig = parse_sig(&body).unwrap();
        assert_eq!(
            winner_policy(&sig, 1000, 5000).unwrap_err(),
            Error::PolicyViolation("data signature predates its verifying key")
        );

                                                                                
        let mut f = SigForge::baseline(1000);
        f.hashed
            .extend_from_slice(&crate::forge::subpacket(3, false, &100u32.to_be_bytes()));
        let body = f.body();
        let sig = parse_sig(&body).unwrap();
        assert_eq!(
            winner_policy(&sig, 1000, 2000).unwrap_err(),
            Error::PolicyViolation("data signature expired")
        );
        let mut f = SigForge::baseline(1000);
        f.hashed
            .extend_from_slice(&crate::forge::subpacket(3, false, &0u32.to_be_bytes()));
        let body = f.body();
        let sig = parse_sig(&body).unwrap();
        assert!(winner_policy(&sig, 1000, u64::from(u32::MAX)).is_ok());
    }

    /// A pre-epoch clock is refused, named (not a panic, not a wrap).
    #[test]
    fn pre_epoch_clock_is_refused() {
        let bytes = fixture("real/greg-pruned.asc");
        let greg = Fingerprint::from_hex(GREG_PIN).unwrap();
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            Keyring::load(&bytes, &[greg], before_epoch).unwrap_err(),
            Error::PolicyViolation("clock before the unix epoch")
        );
    }
}
