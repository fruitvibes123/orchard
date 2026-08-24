//! Bundle verification — the explicit cascade + the mandatory artifact binding.

use crate::statement::{Attestation, Delegation, Purpose, StatementError};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Why a bundle (or a single signature) failed to verify. Every variant is a
/// fail-closed reject.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid public key encoding")]
    BadPublicKey,
    #[error("signature did not verify")]
    BadSignature,
    #[error("statement parse error: {0}")]
    Statement(#[from] StatementError),
    #[error("delegation_id does not match SHA-256(delegation)")]
    DelegationIdMismatch,
    #[error("attestation purpose does not match delegation purpose")]
    PurposeMismatch,
    #[error("delegation authorizes the root key as its own worker (role collapse)")]
    RootWorkerKeyReuse,
    #[error("delegation window invalid (not_after <= not_before)")]
    WindowInvalid,
    #[error("not yet valid (now < not_before)")]
    WindowNotYetValid,
    #[error("expired (now > not_after)")]
    WindowExpired,
    #[error("artifact hash does not match the attestation")]
    ArtifactHashMismatch,
    #[error(
        "attestation purpose {got:?} does not match the caller's expected purpose {expected:?}"
    )]
    UnexpectedPurpose { expected: Purpose, got: Purpose },
    #[error("delegation monotonic_ctr is below the caller's min_ctr floor (rollback)")]
    CounterRollback,
}

/// Crate-internal single-signature primitive: verify an ed25519 signature over
/// the exact message bytes, fail-closed. This is NOT a bundle acceptance gate —
/// it does NOT bind the artifact, so it is deliberately `pub(crate)`: callers
                                                                 
/// Uses `verify_strict` (rejects small-order / non-canonical points). The
                                                                           
/// cross-version replay fails here because the bytes differ.
pub(crate) fn verify_single(
    pubkey: &[u8; 32],
    message: &[u8],
    sig: &[u8; 64],
) -> Result<(), VerifyError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| VerifyError::BadPublicKey)?;
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(message, &signature)
        .map_err(|_| VerifyError::BadSignature)
}

                                                                          
/// canonical bytes + the two signatures; deliberately does NOT carry the
/// artifact (the artifact hash is a required argument to `verify_bundle`).
pub struct Bundle<'a> {
    pub delegation_bytes: &'a [u8],
    pub root_sig: &'a [u8; 64],
    pub attestation_bytes: &'a [u8],
    pub worker_sig: &'a [u8; 64],
}

/// Walk the explicit cascade. PRIVATE on purpose: success here is necessary but
/// not sufficient — the artifact-hash binding (the public `verify_bundle`) is
/// the step that ties the chain to bytes in hand. Returns the parsed attestation,
/// the delegation window, and the accepted delegation's monotonic_ctr. This walk
/// is CLOCK-FREE — the currency check (now vs the window) is the caller's:
/// `verify_bundle` applies it on the returned bounds; `verify_bundle_no_window`
                       
fn verify_chain(
    bundle: &Bundle,
    root_pubkey: &[u8; 32],
) -> Result<(Attestation, u64, u64, u64), VerifyError> {
                                      
    verify_single(root_pubkey, bundle.delegation_bytes, bundle.root_sig)?;
    let delegation = Delegation::from_canonical(bundle.delegation_bytes)?;

                                                                              
                                                                                   
                                                                                  
                                                                               
                   
    if &delegation.worker_pubkey == root_pubkey {
        return Err(VerifyError::RootWorkerKeyReuse);
    }

                                                                      
                                                                           
                                                                               
                                                                                  
                                                                          
                                                                                  
                                                                                
                                                                                  
                                                                  
                                                                                 
                                                                                  
                                                                                 
    if delegation.not_after <= delegation.not_before {
        return Err(VerifyError::WindowInvalid);
    }

                                                                            
    verify_single(
        &delegation.worker_pubkey,
        bundle.attestation_bytes,
        bundle.worker_sig,
    )?;
    let attestation = Attestation::from_canonical(bundle.attestation_bytes)?;

                                                                      
    let delegation_id: [u8; 32] = Sha256::digest(bundle.delegation_bytes).into();
    if attestation.delegation_id != delegation_id {
        return Err(VerifyError::DelegationIdMismatch);
    }

                                             
    if attestation.purpose != delegation.purpose {
        return Err(VerifyError::PurposeMismatch);
    }

                                                                                   
                                                                            
                                                                                   
    Ok((
        attestation,
        delegation.not_before,
        delegation.not_after,
        delegation.monotonic_ctr,
    ))
}

/// Proof that a bundle verified AND its attestation binds the artifact in hand.
/// Only `verify_bundle` / `verify_bundle_over_bytes` mint one, and both require
/// the artifact hash AND the caller's expected purpose. The chain walk
/// (`verify_chain`) and the single-signature primitive (`verify_single`) are
/// crate-private, so this crate exposes no public path that verifies a chain
/// without binding the artifact — the binding cannot be skipped via the public
                   
///
/// The fields are PRIVATE and there is no public constructor, so a value of this
/// type cannot be forged by a consumer: possessing one is type-level proof that
/// the full cascade + the mandatory artifact-hash + expected-purpose binding all
                                                                          
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    purpose: Purpose,
    artifact_hash: [u8; 32],
    not_before: u64,
    not_after: u64,
    monotonic_ctr: u64,
}

impl VerifiedArtifact {
    /// The artifact kind the cascade attested (equals the caller's `expected_purpose`).
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// The SHA-256 the attestation binds (equals the `artifact_hash` the caller passed).
    pub fn artifact_hash(&self) -> &[u8; 32] {
        &self.artifact_hash
    }
    /// The authorizing delegation's `not_before` bound (unix seconds).
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    /// The authorizing delegation's `not_after` bound (unix seconds).
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    /// The accepted delegation's `monotonic_ctr`. Additive DiD accessor: a clocked
    /// storage-bearing consumer (S0) MAY counter-check supersession against its own
                                                                                    
    /// is still breaking for the §9 enum reasons — this accessor is additive, the
                                  
    pub fn monotonic_ctr(&self) -> u64 {
        self.monotonic_ctr
    }
}

/// Verify the full cascade AND bind it to BOTH the artifact whose SHA-256 is
/// `artifact_hash` AND the caller's `expected_purpose`. Fail-closed on any
/// mismatch (`ArtifactHashMismatch` / `UnexpectedPurpose`). This is THE verify
/// entry point for the box + the operator preflight.
///
/// `now_unix` is the caller's trusted wall clock (unix seconds). In v1 the
/// delegation window (`not_before..=not_after`) is the SOLE expiry/revocation
                                                                                 
/// trustworthiness of revocation rests entirely on `now_unix` coming from a
/// trusted time source. A caller at an untrusted-clock locus (e.g. an early-boot
                                                                            
pub fn verify_bundle(
    bundle: &Bundle,
    root_pubkey: &[u8; 32],
    now_unix: u64,
    artifact_hash: &[u8; 32],
    expected_purpose: Purpose,
) -> Result<VerifiedArtifact, VerifyError> {
    let (attestation, not_before, not_after, monotonic_ctr) = verify_chain(bundle, root_pubkey)?;
                                                                                 
                                                                          
                                                                         
                                                                                   
                                                                                      
                                                                                    
                            
    if now_unix < not_before {
        return Err(VerifyError::WindowNotYetValid);
    }
    if now_unix > not_after {
        return Err(VerifyError::WindowExpired);
    }
    if &attestation.artifact_hash != artifact_hash {
        return Err(VerifyError::ArtifactHashMismatch);
    }
                                                                                  
                                                                                  
                                                                                
    if attestation.purpose != expected_purpose {
        return Err(VerifyError::UnexpectedPurpose {
            expected: expected_purpose,
            got: attestation.purpose,
        });
    }
    Ok(VerifiedArtifact {
        purpose: attestation.purpose,
        artifact_hash: attestation.artifact_hash,
        not_before,
        not_after,
        monotonic_ctr,
    })
}

/// Convenience for SMALL artifacts: hash the artifact bytes IN MEMORY, then
/// `verify_bundle`. A large artifact (e.g. a multi-GB `.img`) must NOT use this —
/// stream the SHA-256 and call `verify_bundle` with the precomputed hash, else
                                                                     
pub fn verify_bundle_over_bytes(
    bundle: &Bundle,
    root_pubkey: &[u8; 32],
    now_unix: u64,
    artifact: &[u8],
    expected_purpose: Purpose,
) -> Result<VerifiedArtifact, VerifyError> {
    let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();
    verify_bundle(
        bundle,
        root_pubkey,
        now_unix,
        &artifact_hash,
        expected_purpose,
    )
}

/// Proof that a bundle verified AND binds the artifact in hand, but with the
/// delegation's validity window NOT currency-checked (clock-free). Minted ONLY by
/// `verify_bundle_no_window`. Like `VerifiedArtifact` it is SEALED (private fields,
/// no public constructor), so possessing one is type-level proof that the full
/// cascade + the mandatory artifact-hash + expected-purpose binding + the caller's
/// `min_ctr` floor all passed — but it asserts NOTHING about currency: `not_before`/
/// `not_after` are REPORTED for the consumer's information, never enforced here.
///
                                                                                   
/// `From`/`Into`/`as_verified()` in either direction and no shared trait, so a
/// clock-free proof can never be type-swapped for a currency-checked one, and a
/// currency-checked proof can never silently downgrade into this weaker one. The
/// only route to a currency-checked proof is to run the currency check
/// (`verify_bundle`). The compile-time non-convertibility is proven by the trybuild
/// probes (§8 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowUncheckedArtifact {
    purpose: Purpose,
    artifact_hash: [u8; 32],
    not_before: u64,
    not_after: u64,
    monotonic_ctr: u64,
}

impl WindowUncheckedArtifact {
    /// The artifact kind the cascade attested (equals the caller's `expected_purpose`).
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// The SHA-256 the attestation binds (equals the `artifact_hash` the caller passed).
    pub fn artifact_hash(&self) -> &[u8; 32] {
        &self.artifact_hash
    }
    /// The delegation's claimed `not_before` — REPORTED, NOT currency-checked (a
    /// clock-bearing consumer MAY check it itself; this type does not).
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    /// The delegation's claimed `not_after` — REPORTED, NOT currency-checked.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    /// The accepted delegation's `monotonic_ctr` (guaranteed `>= min_ctr`) — so the
                                                                                        
    pub fn monotonic_ctr(&self) -> u64 {
        self.monotonic_ctr
    }
}

/// Verify the full cascade AND bind BOTH the artifact hash AND the caller's
/// `expected_purpose` — exactly like `verify_bundle` — but WITHOUT the currency
/// (time-window) check, for loci with no trustworthy clock (the installer / the
                                                                             
/// caller-supplied `min_ctr` floor: the accepted delegation's `monotonic_ctr` must
/// be `>= min_ctr`, else `CounterRollback`. `min_ctr = 0` is a floor-of-zero = NO
                                                                                  
/// stateless; the caller owns the floor's storage + the read→verify→advance→promote
/// atomicity (the §4 TOCTOU obligation handed to the consumer).
///
/// This re-applies the artifact-hash + `expected_purpose` bindings ITSELF — they are
/// NOT in the shared `verify_chain`; each public entry re-applies them, so NO public
                                                                             
                                                                                       
/// cascade rejects (bad sig / role-collapse / `delegation_id` / in-chain purpose) →
/// `ArtifactHashMismatch` → `UnexpectedPurpose` → `CounterRollback`.
///
/// Returns the distinct sealed `WindowUncheckedArtifact`, NON-convertible to
/// `VerifiedArtifact` (§2c) — so a currency-UNCHECKED proof can never masquerade as a
/// currency-checked one, and an S0 caller that reaches for this by mistake gets a
/// type a `VerifiedArtifact`-typed downstream refuses to compile against.
pub fn verify_bundle_no_window(
    bundle: &Bundle,
    root_pubkey: &[u8; 32],
    artifact_hash: &[u8; 32],
    expected_purpose: Purpose,
    min_ctr: u64,
) -> Result<WindowUncheckedArtifact, VerifyError> {
    let (attestation, not_before, not_after, monotonic_ctr) = verify_chain(bundle, root_pubkey)?;
                                                                                     
                                                  
    if &attestation.artifact_hash != artifact_hash {
        return Err(VerifyError::ArtifactHashMismatch);
    }
    if attestation.purpose != expected_purpose {
        return Err(VerifyError::UnexpectedPurpose {
            expected: expected_purpose,
            got: attestation.purpose,
        });
    }
                                                                                
    if monotonic_ctr < min_ctr {
        return Err(VerifyError::CounterRollback);
    }
    Ok(WindowUncheckedArtifact {
        purpose: attestation.purpose,
        artifact_hash: attestation.artifact_hash,
        not_before,
        not_after,
        monotonic_ctr,
    })
}

#[cfg(test)]
mod tests {
    use super::{verify_single, VerifyError};
    use crate::statement::{Delegation, Purpose};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn good_delegation_signature_verifies() {
        let sk = root_key();
        let d = Delegation {
            worker_pubkey: [0xCD; 32],
            purpose: Purpose::Img,
            not_before: 0,
            not_after: 100,
            monotonic_ctr: 1,
        };
        let msg = d.to_canonical();
        let sig = sk.sign(&msg).to_bytes();
        assert!(verify_single(&sk.verifying_key().to_bytes(), &msg, &sig).is_ok());
    }

    #[test]
    fn delegation_signature_fails_over_attestation_bytes() {
                                                                                    
                                                                                  
                                   
        let sk = root_key();
        let d = Delegation {
            worker_pubkey: [0xCD; 32],
            purpose: Purpose::Img,
            not_before: 0,
            not_after: 100,
            monotonic_ctr: 1,
        };
        let deleg_bytes = d.to_canonical();
        let sig = sk.sign(&deleg_bytes).to_bytes();
        let mut other = deleg_bytes;
        other[0] = 0x02;
        assert!(verify_single(&sk.verifying_key().to_bytes(), &other, &sig).is_err());
    }

    #[test]
    fn decompressable_but_wrong_pubkey_fails_closed_as_bad_signature() {
                                                                               
                                                                           
                                                                        
        let sk = root_key();
        let msg = [0u8; 59];
        let sig = sk.sign(&msg).to_bytes();
        assert_eq!(
            verify_single(&[0xFFu8; 32], &msg, &sig),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn non_decompressable_pubkey_rejects_as_bad_public_key() {
                                                                      
                                                                                 
                                                                                 
                                                                               
                                                                  
        let bad = (0u8..=255)
            .map(|n| {
                let mut k = [0u8; 32];
                k[0] = n;
                k
            })
            .find(|k| VerifyingKey::from_bytes(k).is_err())
            .expect("some single-byte y must be non-decompressable");
        let sk = root_key();
        let msg = [0u8; 59];
        let sig = sk.sign(&msg).to_bytes();
        assert_eq!(
            verify_single(&bad, &msg, &sig),
            Err(VerifyError::BadPublicKey)
        );
    }
}
