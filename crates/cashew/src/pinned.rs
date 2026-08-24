                                                                                             
//!
//! **The one documented SHA-1 exception, scoped so it proves the norm.** cashew's strict
//! [`Keyring::load`] is and stays THE default: it verifies every keyring self-signature under the
//! E-2 `{SHA-256, SHA-512}`-only whitelist + the no-skip law, so a key that self-signs with SHA-1
//! fails closed as [`Error::WeakHash`]. The Rust *release* signing key is exactly such a key — all
//! four of its self-certs are SHA-1 (it has never re-signed), yet it signs release manifests with a
                                                                                            
//!
//! `load_pinned_bare` is the bounded exception for a **pinned, single-purpose** key: it trusts the
//! key by the caller's **sha256 pin of `key_bytes`** (established by the consumer BEFORE calling this
//! — the `[rust-keyring]` pin, checked byte-exact; NOT re-established here) plus an
//! **out-of-band-grounded fingerprint** (Arch's git-reviewed `validpgpkeys`, independent of the rust
//! CDN). It:
                                                                                                      
//!   fingerprint equals a caller pin. It NEVER collects subkey material: a subkey binding is validated
//!   (in the strict path) by a 0x18/0x19 chain this path deliberately skips, so trusting a subkey
//!   would trust un-binding-verified material, and an attacker who tampered the INITIAL vendoring
//!   could append a malicious signing subkey that the sha256 pin (set from the tampered bytes) and the
//!   genuine primary fingerprint would both accept. rust signs with its primary today; a future
//!   subkey-signed manifest fails closed ([`Error::BadSignature`]) → a keyring-refresh REVIEW EVENT.
//! - **does NOT run `policy.rs`** — no self-cert verification, no validity/expiry/revocation, no
//!   key-flags check. It reuses only `armor`/`packet`/`key` PARSING (so the block grammar's
//!   exact-consumption still holds) + the SAME [`DetachedVerifier::finalize`] for the strong data sig.
//! - **preserves E-2**: SHA-1 self-certs are SKIPPED, never accepted as a verify input. The only SHA-1
//!   in the crate is still the one fingerprint construction in `key.rs`; nothing here hashes a
//!   signature. The data sig is verified with SHA-512 through the unchanged `verify.rs`.
                                                                                           
//!   `finalize` applies its DATA-signature creation-time future-check exactly as for a strict keyring
//!   (a `now=0` bare keyring would reject every genuine, present-dated manifest).
                                                                                                    
//!   (an appended, unpinned block fails the load), mirroring the strict path's exact block
//!   accounting; within-block junk is already rejected by the reused `key::parse_block` grammar.
//!
//! Scoping (the exception can't become an escape hatch): this is a DISTINCT, documented constructor;
//! the strict [`Keyring::load`] is byte-unchanged and stays the default; and a fail-closed CALL-SITE
//! ALLOWLIST test (`tests/scoping.rs`) asserts `load_pinned_bare` is referenced by EXACTLY the
                                                                                                      

use crate::key::{self, Fingerprint};
use crate::{armor, packet, unix_secs, Error, Keyring, OwnedCandidate, OwnedSigner, SigningKey};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::SystemTime;

impl Keyring {
    /// Load a keyring for a PINNED, single-purpose key whose SELF-signatures use a weak hash (SHA-1),
    /// so the strict [`Keyring::load`] (E-2) cannot load it. Trust is by the caller's sha256 pin of
    /// `key_bytes` (established by the consumer, NOT re-established here) + the out-of-band-grounded
    /// fingerprints in `pins`. Binds ONLY each primary whose v4 fingerprint equals a pin — never
                                                                                               
    /// Rejects unaccounted-for blocks. `now` is carried for `finalize`'s DATA-signature creation-time
                                                                                         
    ///
    /// THE ESCAPE-HATCH, SCOPED: for SHA-1-self-signed single-purpose keys anchored by an external
    /// sha256 pin ONLY; a call-site allowlist test bounds its use to the rust bump. Prefer
    /// [`Keyring::load`] for every strong-self-signed key (the kernel keyring).
    pub fn load_pinned_bare(
        key_bytes: &[u8],
        pins: &[Fingerprint],
        now: SystemTime,
    ) -> Result<Self, Error> {
        catch_unwind(AssertUnwindSafe(|| {
            load_pinned_bare_inner(key_bytes, pins, now)
        }))
        .map_err(|_| Error::ParserPanic)?
    }
}

fn load_pinned_bare_inner(
    key_bytes: &[u8],
    pins: &[Fingerprint],
    now: SystemTime,
) -> Result<Keyring, Error> {
    let now_secs = unix_secs(now)?;
                                                                                                  
                                                                                             
                                                                                                   
    let blocks_bin = armor::decode_keyring(key_bytes)?;
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
        signers.push(OwnedSigner {
            primary_fpr: block.primary_fpr,
            candidates: vec![OwnedCandidate {
                n: block.primary.n.to_vec(),
                e: block.primary.e.to_vec(),
                created: block.primary.created,
                                                                                              
                                                                                
                id: SigningKey::Primary,
            }],
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
