                                                                                                     
//! the NO-SKIP LAW and the candidate-key rules, all at load, all fail-closed.
//!
//! Order of enforcement: pin match → the no-skip law (EVERY signature cryptographically verifies
//! in its positional role — one failure of any kind kills the load; SHA-1 anywhere dies as
//! `WeakHash` at the digest constructor, before any crypto) → creation-time sanity everywhere
//! (keys AND signatures ≤ now + skew) → primary revocation (any verified 0x20 = dead) → the 0x30
//! kill rule (a verified certification-revocation kills every self-cert on ITS uid created ≤ the
                                                                                                
//! selection (newest of {0x1F ∪ surviving 0x10–0x13}; equal creation resolved by the TOTAL
//! more-restrictive-wins tiebreaker) → primary validity (key expiry from the governing sig) →
//! the candidate set.
//!
                                                                                                  
//! explicitly include sign (0x02) — `None` is NOT a candidate (no algorithm-implied usage) — plus
//! every valid signing subkey (newest verified binding, sign-flagged, verified 0x19 back-sig
//! present, no 0x28, within its validity window). An empty candidate set is `PolicyViolation`.
//!
//! Tiebreaker note: the spec's "revoked beats valid" axis is realized structurally by the ≤ kill
//! rule (an equal-creation 0x30 removes the cert from the pool before selection), so the ordered
//! comparison implements the remaining axes: shortest key-expiry → fewest capability flags →
//! sign-absent beats sign-present → byte-lexicographically SMALLER full packet (the final,
//! deterministic, admittedly arbitrary total-order leg).
//!
//! Test-architecture note (the no-skip law's structural consequence): negatives that need
//! crypto-VALID-but-policy-bad material can only come from gpg-produced fixtures (key_b/d/e/f/g);
//! every forged shape dies at the no-skip crypto check first, so the remaining policy predicates
//! (tiebreak axes, explicit-flags law, backsig absence, enc-flagged bindings) are unit-tested
//! directly on the candidate functions below the crypto layer. Each test names which kind it is.

use crate::key::{Fingerprint, KeyBlock, SubkeySection, Uid};
use crate::limits::SKEW_SECS;
use crate::sig::{parse_sig, SigPacket};
use crate::verify::{feed_key_block, feed_uid, left16_matches, rsa_verify, SigHash};
use crate::Error;

                                                                                            
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKey {
    Primary,
    Subkey(Fingerprint),
}

/// One candidate signing key of a validated signer: the material `finalize` tries.
#[derive(Debug)]
pub(crate) struct CandidateKey<'a> {
    pub n: &'a [u8],
    pub e: &'a [u8],
    /// The KEY's creation time — `finalize` requires a data signature created ≥ this (§6.3).
    pub created: u32,
    pub id: SigningKey,
}

/// A pinned signer whose block passed the whole §6.3 load policy.
#[derive(Debug)]
pub(crate) struct ValidatedSigner<'a> {
    pub primary_fpr: Fingerprint,
    pub candidates: Vec<CandidateKey<'a>>,
}

/// Validate one parsed block against its pin at `now` (seconds since epoch). See the module docs
/// for the enforcement order; every failure is the FIRST failed predicate's named error.
pub(crate) fn validate_block<'a>(
    block: &'a KeyBlock<'a>,
    pin: &Fingerprint,
    now: u64,
) -> Result<ValidatedSigner<'a>, Error> {
    if block.primary_fpr != *pin {
        return Err(Error::UnknownSigner);
    }

                                                                                                  
                                                                                                  
                                                                                       
    for sig in &block.direct_sigs {
        verify_in_role(sig, block, None, None)?;
    }
    for uid in &block.uids {
        for sig in &uid.sigs {
            verify_in_role(sig, block, Some(uid), None)?;
        }
    }
    for sk in &block.subkeys {
        for sig in &sk.sigs {
            verify_in_role(sig, block, None, Some(sk))?;
        }
    }

                                                                                                    
    let horizon = now.saturating_add(SKEW_SECS);
    let all_sigs = block
        .direct_sigs
        .iter()
        .chain(block.uids.iter().flat_map(|u| u.sigs.iter()))
        .chain(block.subkeys.iter().flat_map(|s| s.sigs.iter()));
    let future_key = u64::from(block.primary.created) > horizon
        || block
            .subkeys
            .iter()
            .any(|s| u64::from(s.key.created) > horizon);
    if future_key || all_sigs.into_iter().any(|s| u64::from(s.created) > horizon) {
        return Err(Error::PolicyViolation("material created in the future"));
    }

                                                                    
    if block.direct_sigs.iter().any(|s| s.sig_type == 0x20) {
        return Err(Error::PolicyViolation("primary key revoked"));
    }

                                                                                                      
                                                                                
    let pool = block
        .direct_sigs
        .iter()
        .filter(|s| s.sig_type == 0x1F)
        .chain(block.uids.iter().flat_map(surviving_certs));
    let governing =
        newest_restrictive(pool).ok_or(Error::PolicyViolation("no surviving self-signature"))?;

                                                                                               
                                                                                                   
                                                                
    if let Some(exp) = governing.key_expiry.filter(|&e| e != 0) {
        let expires = u64::from(block.primary.created).saturating_add(u64::from(exp));
        if now > expires {
            return Err(Error::PolicyViolation("primary key expired"));
        }
    }

                                                                                                
                                                         
    let mut candidates = Vec::new();
    if flags_include_sign(governing.key_flags) {
        candidates.push(CandidateKey {
            n: block.primary.n,
            e: block.primary.e,
            created: block.primary.created,
            id: SigningKey::Primary,
        });
    }
    candidates.extend(
        block
            .subkeys
            .iter()
            .filter_map(|sk| subkey_candidate(sk, now)),
    );
    if candidates.is_empty() {
        return Err(Error::PolicyViolation("no signing-capable key"));
    }

    Ok(ValidatedSigner {
        primary_fpr: block.primary_fpr,
        candidates,
    })
}

/// Verify ONE keyring signature in its positional role — the no-skip law's unit. Role material:
/// the primary block, plus the uid (certification roles) or the subkey (binding roles); the
/// verifying key is the block's PRIMARY. Structural placement rules run BEFORE crypto (a
/// misplaced embedded signature is a grammar violation, not a signature failure); an embedded
/// 0x19 back-signature on a 0x18 binding is then verified against the SUBKEY with its OWN fields
                 
fn verify_in_role(
    sig: &SigPacket<'_>,
    block: &KeyBlock<'_>,
    uid: Option<&Uid<'_>>,
    subkey: Option<&SubkeySection<'_>>,
) -> Result<(), Error> {
    if sig.embedded_sig.is_some() && sig.sig_type != 0x18 {
        return Err(Error::Malformed(
            "embedded signature outside a subkey binding",
        ));
    }

    let mut h = SigHash::for_algo(sig.hash_algo)?;
    feed_key_block(&mut h, block.primary.raw);
    if let Some(u) = uid {
        feed_uid(&mut h, u.raw);
    }
    if let Some(sk) = subkey {
        feed_key_block(&mut h, sk.key.raw);
    }
    let digest = h.finalize_with_sig_fields(sig);
    if !left16_matches(sig, &digest) {
        return Err(Error::BadSignature);
    }
    rsa_verify(
        block.primary.n,
        block.primary.e,
        sig.hash_algo,
        &digest,
        sig.s_mpi,
    )?;

    match (sig.embedded_sig, subkey) {
        (None, _) => Ok(()),
        (Some(embedded), Some(sk)) => {
                                                                                             
                                                                                                   
            let back = parse_sig(embedded)?;
            if back.sig_type != 0x19 {
                return Err(Error::Malformed(
                    "embedded signature is not a back-signature",
                ));
            }
            let mut h = SigHash::for_algo(back.hash_algo)?;
            feed_key_block(&mut h, block.primary.raw);
            feed_key_block(&mut h, sk.key.raw);
            let digest = h.finalize_with_sig_fields(&back);
            if !left16_matches(&back, &digest) {
                return Err(Error::BadSignature);
            }
            rsa_verify(sk.key.n, sk.key.e, back.hash_algo, &digest, back.s_mpi)
        }
                                                                                                  
                                                             
        (Some(_), None) => Err(Error::Malformed(
            "embedded signature outside a subkey binding",
        )),
    }
}

/// The self-certifications on one uid that survive its 0x30 kill rule: a verified 0x30 kills
/// every cert created ≤ the NEWEST revocation's creation (the equal-timestamp boundary revokes,
                                                                   
fn surviving_certs<'a, 'b>(uid: &'b Uid<'a>) -> impl Iterator<Item = &'b SigPacket<'a>> {
    let newest_rev = uid
        .sigs
        .iter()
        .filter(|s| s.sig_type == 0x30)
        .map(|s| s.created)
        .max();
    uid.sigs
        .iter()
        .filter(|s| matches!(s.sig_type, 0x10..=0x13))
        .filter(move |s| newest_rev.is_none_or(|r| s.created > r))
}

/// Select the newest signature; equal creation resolved by the more-restrictive-wins TOTAL order
/// (see the module docs — smaller restrictiveness key wins the tie).
fn newest_restrictive<'a, 'b, I>(pool: I) -> Option<&'b SigPacket<'a>>
where
    I: Iterator<Item = &'b SigPacket<'a>>,
    'a: 'b,
{
    pool.max_by(|a, b| {
        a.created
            .cmp(&b.created)
            .then_with(|| restrictiveness_key(b).cmp(&restrictiveness_key(a)))
    })
}

/// The tiebreak ordering key: SMALLER = more restrictive. Axes in order: shortest key-expiry
/// (None = never = maximally lax), fewest capability flags (None = zero = fewest), sign-absent
/// beats sign-present, byte-lexicographically smaller full packet (final deterministic leg).
fn restrictiveness_key<'a>(sig: &'a SigPacket<'_>) -> (u64, u32, u8, &'a [u8]) {
    let expiry = sig.key_expiry.map_or(u64::MAX, u64::from);
    let flag_count = sig.key_flags.map_or(0, |f| f.count_ones());
    let sign_present = u8::from(flags_include_sign(sig.key_flags));
    (expiry, flag_count, sign_present, sig.raw)
}

/// The explicit-flags law (§6.3): only a PRESENT hashed key-flags subpacket with the sign bit
/// (0x02) grants signing capability — `None` never does (no algorithm-implied usage).
fn flags_include_sign(flags: Option<u8>) -> bool {
    flags.is_some_and(|f| f & 0x02 != 0)
}

/// Evaluate one subkey section as a signing candidate (§6.3). Every signature in it has ALREADY
/// passed the no-skip law (including the embedded 0x19's own verification when present) — this
/// function judges only the policy predicates. `None` = not a candidate (soft, unlike the
/// primary's hard validity failures — a pinned signer may legitimately carry retired subkeys).
fn subkey_candidate<'a>(sk: &'a SubkeySection<'a>, now: u64) -> Option<CandidateKey<'a>> {
                                                                                     
    if sk.sigs.iter().any(|s| s.sig_type == 0x28) {
        return None;
    }
    let binding = newest_restrictive(sk.sigs.iter().filter(|s| s.sig_type == 0x18))?;
    if !flags_include_sign(binding.key_flags) {
        return None;
    }
                                                                                                 
                                                                                
    binding.embedded_sig?;
                                                                                              
                                                                                             
                     
    if let Some(exp) = binding.key_expiry.filter(|&e| e != 0) {
        let created = u64::from(sk.key.created);
        if now < created || now > created.saturating_add(u64::from(exp)) {
            return None;
        }
    }
    Some(CandidateKey {
        n: sk.key.n,
        e: sk.key.e,
        created: sk.key.created,
        id: SigningKey::Subkey(sk.fpr),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{subkey_candidate, validate_block, SigningKey};
    use crate::forge::{creation, mpi, subpacket, uid_packet, KeyForge, SigForge};
    use crate::key::{parse_block, Fingerprint, KeyBlock};
    use crate::sig::parse_sig;
    use crate::{armor, packet, Error};

    /// Stable corpus timestamps (gen.sh stamps everything at the faked GENTIME; MANIFEST.toml
    /// records the same values — stable across regenerations by design).
    const GEN_TIME: u64 = 1_781_000_000;
    /// The single shared evaluation clock (METADATA.toml / MANIFEST.toml `fixture_now`).
    const FIXTURE_NOW: u64 = 1_781_100_000;

    const GREG_PIN: &str = "647F28654894E3BD457199BE38DBBDC86092693E";
    const SASHA_PIN: &str = "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC";

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    /// Decode + walk + parse ONE keyring fixture into an owned packet buffer and its KeyBlock.
    fn block_bytes(rel: &str) -> Vec<u8> {
        let mut blocks = armor::decode_keyring(&fixture(rel)).unwrap();
        assert_eq!(blocks.len(), 1, "{rel}");
        blocks.remove(0)
    }

    fn parse<'a>(bin: &'a [u8]) -> KeyBlock<'a> {
        parse_block(&packet::walk(bin).unwrap()).unwrap()
    }

    /// Validate a generated fixture against its OWN parsed fingerprint (gen pins are per-run; the
    /// real anchors below pin externally from METADATA).
    fn validate_gen(rel: &str, now: u64) -> Result<Vec<SigningKey>, Error> {
        let bin = block_bytes(rel);
        let block = parse(&bin);
        let pin = block.primary_fpr;
        validate_block(&block, &pin, now)
            .map(|v| v.candidates.iter().map(|c| c.id.clone()).collect())
    }

                                                            

    /// Both real blocks validate at fixture_now and the candidate set is EXACTLY {Primary} —
                                                                             
    #[test]
    fn real_blocks_validate_with_exactly_primary_candidates() {
        for (rel, pin_hex, created) in [
            ("real/greg-pruned.asc", GREG_PIN, 1316795861u32),
            ("real/sasha-pruned.asc", SASHA_PIN, 1328804765),
        ] {
            let bin = block_bytes(rel);
            let block = parse(&bin);
            let pin = Fingerprint::from_hex(pin_hex).unwrap();
            let v = validate_block(&block, &pin, FIXTURE_NOW).unwrap();
            assert_eq!(v.primary_fpr, pin, "{rel}");
            assert_eq!(v.candidates.len(), 1, "{rel}");
            assert!(matches!(v.candidates[0].id, SigningKey::Primary), "{rel}");
            assert_eq!(v.candidates[0].created, created, "{rel}");
        }
    }

    /// A wrong pin for a structurally valid block is UnknownSigner (the load-time-only class).
    #[test]
    fn pin_mismatch_is_unknown_signer() {
        let bin = block_bytes("gen/key_a.asc");
        let block = parse(&bin);
        let other = block_bytes("gen/key_c.asc");
        let foreign = parse(&other);
        assert_eq!(
            validate_block(&block, &foreign.primary_fpr, FIXTURE_NOW).unwrap_err(),
            Error::UnknownSigner
        );
    }

                                                                                      

    /// The chain shape (key_b): candidates = {Primary, Subkey(fpr)} — gpg's default primary is
    /// [SC] and the added signing subkey is valid at fixture_now.
    #[test]
    fn chain_shape_yields_primary_and_subkey_candidates() {
        let bin = block_bytes("gen/key_b.asc");
        let block = parse(&bin);
        let ids = validate_gen("gen/key_b.asc", FIXTURE_NOW).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(matches!(ids[0], SigningKey::Primary));
        assert_eq!(ids[1], SigningKey::Subkey(block.subkeys[0].fpr));
    }

    /// key_d's short-expiry subkey is EXPIRED at fixture_now → not a candidate (the primary [SC]
    /// remains, so the load itself succeeds).
    #[test]
    fn expired_subkey_is_not_a_candidate() {
        let ids = validate_gen("gen/key_d.asc", FIXTURE_NOW).unwrap();
        assert!(
            ids.iter().all(|id| matches!(id, SigningKey::Primary)),
            "{ids:?}"
        );
    }

    /// key_e's subkey carries a verified 0x28 → not a candidate.
    #[test]
    fn revoked_subkey_is_not_a_candidate() {
        let ids = validate_gen("gen/key_e.asc", FIXTURE_NOW).unwrap();
        assert!(
            ids.iter().all(|id| matches!(id, SigningKey::Primary)),
            "{ids:?}"
        );
    }

    /// key_f carries a verified 0x20 on the primary → the LOAD fails (hard, not a candidate
    /// filter).
    #[test]
    fn revoked_primary_fails_the_load() {
        assert_eq!(
            validate_gen("gen/key_f.asc", FIXTURE_NOW).unwrap_err(),
            Error::PolicyViolation("primary key revoked")
        );
    }

                                                                                                   
    /// zero surviving self-signatures → the load fails.
    #[test]
    fn equal_timestamp_revocation_kills_the_only_cert() {
        assert_eq!(
            validate_gen("gen/key_g.asc", FIXTURE_NOW).unwrap_err(),
            Error::PolicyViolation("no surviving self-signature")
        );
    }

    /// Creation-time sanity: evaluating the corpus BEFORE its creation time (now ≪ gen_time)
    /// fails closed — nothing in a loadable keyring may be from the future.
    #[test]
    fn future_dated_material_fails_the_load() {
        assert_eq!(
            validate_gen("gen/key_a.asc", GEN_TIME - 200_000).unwrap_err(),
            Error::PolicyViolation("material created in the future")
        );
    }

                                                                                  

    /// Tampering ANY byte of the newest real self-cert — its hashed area (which holds the issuer
    /// hint) or its signature MPI — is a hard load failure, never a fallback to an older
    /// signature.
    #[test]
    fn tampered_real_self_cert_fails_the_load() {
        let bin = block_bytes("real/greg-pruned.asc");
        let block = parse(&bin);
        let pin = Fingerprint::from_hex(GREG_PIN).unwrap();
                                                                                                   
                                                           
        let sig = &block.uids[0].sigs[0];
        let base = bin.as_ptr() as usize;
        let hashed_off = sig.hashed_area.as_ptr() as usize - base;
        let mpi_off = sig.s_mpi.as_ptr() as usize - base;
        for off in [
            hashed_off,
            hashed_off + sig.hashed_area.len() / 2,
            hashed_off + sig.hashed_area.len() - 1,
            mpi_off,
            mpi_off + sig.s_mpi.len() - 1,
        ] {
            let mut tampered = bin.clone();
            tampered[off] ^= 0x01;
            let packets = match packet::walk(&tampered) {
                Err(_) => continue,                                                  
                Ok(p) => p,
            };
            let result = parse_block(&packets)
                .map_err(Ok::<Error, ()>)
                .and_then(|b| {
                    validate_block(&b, &pin, FIXTURE_NOW)
                        .map_err(Ok)
                        .map(|_| ())
                });
            match result {
                Err(Ok(Error::Malformed(_)) | Ok(Error::BadSignature)) => {}
                other => panic!("offset {off}: load did not fail closed: {other:?}"),
            }
        }
    }

    /// A forged (crypto-garbage) direct-key signature appended to a valid block kills the load at
    /// the no-skip check with BadSignature — the crypto-broken class.
    #[test]
    fn forged_appended_direct_sig_fails_the_load() {
        let mut f = SigForge::baseline(GEN_TIME as u32);
        f.sig_type = 0x1F;
        let mut key_a = fixture("gen/key_a.asc");
                                                                                    
        let mut bin = armor::decode_keyring(&key_a).unwrap().remove(0);
                                                                                               
                                         
        let packets = packet::walk(&bin).unwrap();
        let primary_end =
            packets[0].body.as_ptr() as usize + packets[0].body.len() - bin.as_ptr() as usize;
        let mut forged_stream = bin[..primary_end].to_vec();
        forged_stream.extend_from_slice(&f.packet());
        forged_stream.extend_from_slice(&bin[primary_end..]);
        bin = forged_stream;
        key_a.clear();                                  
        let block = parse_block(&packet::walk(&bin).unwrap()).unwrap();
        let pin = block.primary_fpr;
        assert_eq!(
            validate_block(&block, &pin, FIXTURE_NOW).unwrap_err(),
            Error::BadSignature
        );
    }

    /// A SHA-1 binding (and a SHA-1 subkey revocation) die as WeakHash(2) at the digest
    /// constructor — BEFORE any crypto, for every role (§14 E-2).
    #[test]
    fn sha1_keyring_signatures_are_weak_hash() {
        for sig_type in [0x18u8, 0x28] {
            let mut binding = SigForge::baseline(GEN_TIME as u32);
            binding.sig_type = sig_type;
            binding.hash_algo = 2;         
            let subkey_body = KeyForge::baseline(GEN_TIME as u32).body();
            let mut bin = armor::decode_keyring(&fixture("gen/key_a.asc"))
                .unwrap()
                .remove(0);
            bin.extend_from_slice(&crate::forge::frame_new_format(14, &subkey_body));
            bin.extend_from_slice(&binding.packet());
            let block = parse_block(&packet::walk(&bin).unwrap()).unwrap();
            let pin = block.primary_fpr;
            assert_eq!(
                validate_block(&block, &pin, FIXTURE_NOW).unwrap_err(),
                Error::WeakHash(2),
                "sig type {sig_type:#x}"
            );
        }
    }

    /// An embedded-signature subpacket on anything but a 0x18 binding is Malformed — checked
    /// STRUCTURALLY before crypto, so a forged carrier proves the placement rule.
    #[test]
    fn embedded_sig_outside_binding_is_malformed() {
        let mut f = SigForge::baseline(GEN_TIME as u32);
        f.sig_type = 0x1F;
        f.unhashed = subpacket(32, false, b"not-a-real-backsig");
        let mut bin = armor::decode_keyring(&fixture("gen/key_a.asc"))
            .unwrap()
            .remove(0);
        let packets = packet::walk(&bin).unwrap();
        let primary_end =
            packets[0].body.as_ptr() as usize + packets[0].body.len() - bin.as_ptr() as usize;
        let mut stream = bin[..primary_end].to_vec();
        stream.extend_from_slice(&f.packet());
        stream.extend_from_slice(&bin[primary_end..]);
        bin = stream;
        let block = parse_block(&packet::walk(&bin).unwrap()).unwrap();
        let pin = block.primary_fpr;
        assert_eq!(
            validate_block(&block, &pin, FIXTURE_NOW).unwrap_err(),
            Error::Malformed("embedded signature outside a subkey binding")
        );
    }

                                                                                         

    /// Build a parsed, structurally-valid self-cert-shaped SigPacket body for predicate tests.
    fn cert_body(created: u32, key_expiry: Option<u32>, key_flags: Option<u8>) -> Vec<u8> {
        let mut f = SigForge::baseline(created);
        f.sig_type = 0x13;
        if let Some(exp) = key_expiry {
            f.hashed
                .extend_from_slice(&subpacket(9, false, &exp.to_be_bytes()));
        }
        if let Some(flags) = key_flags {
            f.hashed.extend_from_slice(&subpacket(27, false, &[flags]));
        }
        f.body()
    }

    /// The explicit-flags law: a governing self-sig with NO key-flags subpacket (or without the
    /// sign bit) does not make the primary a candidate. Unit-level: crypto-valid material with
    /// these shapes cannot be produced (gpg always emits flags), so the predicate is tested
    /// directly (documented in the module docs).
    #[test]
    fn explicit_flags_law_below_crypto() {
        assert!(!super::flags_include_sign(None));
        assert!(!super::flags_include_sign(Some(0x0C)));                
        assert!(super::flags_include_sign(Some(0x02)));
        assert!(super::flags_include_sign(Some(0x23)));
    }

    /// The more-restrictive-wins total order, axis by axis (equal creation throughout).
    #[test]
    fn governing_tiebreak_axes_below_crypto() {
        let pick = |a: &[u8], b: &[u8]| -> Vec<u8> {
            let pa = parse_sig(a).unwrap();
            let pb = parse_sig(b).unwrap();
            let winner = super::newest_restrictive([&pa, &pb].into_iter()).unwrap();
            winner.raw.to_vec()
        };

                                                                        
        let short = cert_body(100, Some(50), Some(0x02));
        let long = cert_body(100, Some(500), Some(0x02));
        let never = cert_body(100, None, Some(0x02));
        assert_eq!(pick(&short, &never), short);
        assert_eq!(pick(&short, &long), short);

                                           
        let one_flag = cert_body(100, None, Some(0x02));
        let two_flags = cert_body(100, None, Some(0x03));
        assert_eq!(pick(&one_flag, &two_flags), one_flag);

                                                                     
        let sign = cert_body(100, None, Some(0x02));
        let cert_only = cert_body(100, None, Some(0x01));
        assert_eq!(pick(&sign, &cert_only), cert_only);

                                                                              
        let mut fa = SigForge::baseline(100);
        fa.sig_type = 0x13;
        fa.left16 = [0x00, 0x01];
        let mut fb = SigForge::baseline(100);
        fb.sig_type = 0x13;
        fb.left16 = [0xFF, 0x01];
        assert_eq!(pick(&fa.body(), &fb.body()), fa.body());

                                                       
        let newer_lax = cert_body(200, None, Some(0xFF));
        let older_strict = cert_body(100, Some(1), None);
        assert_eq!(pick(&newer_lax, &older_strict), newer_lax);
    }

    /// Subkey-candidate predicates below crypto: no binding / no backsig / enc-flagged / expired
    /// window / revoked — each disqualifies; the full valid shape qualifies.
    #[test]
    fn subkey_candidate_predicates_below_crypto() {
        let subkey_raw = KeyForge::baseline(1000).body();
        let make_section = |sig_bodies: Vec<Vec<u8>>| -> Vec<u8> {
                                                                                                     
            let mut stream = KeyForge::baseline(1000).packet(6);
            stream.extend_from_slice(&uid_packet(b"u"));
            stream.extend_from_slice(&crate::forge::sig_packet_of_type(0x13, 1000));
            stream.extend_from_slice(&crate::forge::frame_new_format(14, &subkey_raw));
            for b in sig_bodies {
                stream.extend_from_slice(&crate::forge::frame_new_format(2, &b));
            }
            stream
        };
        let binding = |expiry: Option<u32>, flags: Option<u8>, backsig: bool| -> Vec<u8> {
            let mut f = SigForge::baseline(1000);
            f.sig_type = 0x18;
            if let Some(exp) = expiry {
                f.hashed
                    .extend_from_slice(&subpacket(9, false, &exp.to_be_bytes()));
            }
            if let Some(fl) = flags {
                f.hashed.extend_from_slice(&subpacket(27, false, &[fl]));
            }
            if backsig {
                f.unhashed = subpacket(32, false, b"raw-backsig-bytes");
            }
            f.body()
        };

        let cases: Vec<(Vec<Vec<u8>>, u64, bool, &str)> = vec![
            (vec![], 2000, false, "no binding at all"),
            (
                vec![binding(None, Some(0x02), false)],
                2000,
                false,
                "no backsig",
            ),
            (
                vec![binding(None, Some(0x0C), true)],
                2000,
                false,
                "enc-flagged",
            ),
            (vec![binding(None, None, true)], 2000, false, "no flags"),
            (
                vec![binding(Some(500), Some(0x02), true)],
                2000,
                false,
                "expired window",
            ),
            (
                vec![
                    binding(None, Some(0x02), true),
                    SigForge {
                        sig_type: 0x28,
                        ..SigForge::baseline(1500)
                    }
                    .body(),
                ],
                2000,
                false,
                "revoked (0x28 present)",
            ),
            (
                vec![binding(Some(5000), Some(0x02), true)],
                2000,
                true,
                "valid within window",
            ),
            (
                vec![binding(None, Some(0x02), true)],
                2000,
                true,
                "valid, never expires",
            ),
        ];
        for (sigs, now, expect_candidate, what) in cases {
            let stream = make_section(sigs);
            let block = parse_block(&packet::walk(&stream).unwrap()).unwrap();
            let got = subkey_candidate(&block.subkeys[0], now).is_some();
            assert_eq!(got, expect_candidate, "{what}");
        }
    }

    /// The ≤ kill rule below crypto: equal-creation 0x30 kills; a strictly newer cert survives.
    #[test]
    fn kill_rule_boundary_below_crypto() {
        let cert = |created: u32| -> Vec<u8> {
            let mut f = SigForge::baseline(created);
            f.sig_type = 0x13;
            f.body()
        };
        let rev = |created: u32| -> Vec<u8> {
            let mut f = SigForge::baseline(created);
            f.sig_type = 0x30;
            f.body()
        };
        let build = |sig_bodies: Vec<Vec<u8>>| -> Vec<u8> {
            let mut stream = KeyForge::baseline(50).packet(6);
            stream.extend_from_slice(&uid_packet(b"u"));
            for b in sig_bodies {
                stream.extend_from_slice(&crate::forge::frame_new_format(2, &b));
            }
            stream
        };
                                                  
        let bin = build(vec![cert(100), rev(100)]);
        let block = parse_block(&packet::walk(&bin).unwrap()).unwrap();
        assert_eq!(super::surviving_certs(&block.uids[0]).count(), 0);
                                         
        let bin = build(vec![cert(101), rev(100)]);
        let block = parse_block(&packet::walk(&bin).unwrap()).unwrap();
        assert_eq!(super::surviving_certs(&block.uids[0]).count(), 1);
    }

    /// forge creation() helper sanity used across this module (guards the subpacket id).
    #[test]
    fn forge_creation_subpacket_is_id_2() {
        assert_eq!(creation(7)[1], 2);
        let _ = mpi(&[1]);                                            
    }
}
