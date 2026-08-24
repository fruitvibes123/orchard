//! Every byte that ever enters a signature digest is built HERE, and all cryptography is
                                
//!
//! [`SigHash`] carries THE one hash whitelist (§5.3/§14 E-2): {8 = SHA-256, 10 = SHA-512}. There
//! is deliberately NO SHA-1 arm and no per-role variant — every signature of every role (the data
//! signature, self-certs, direct-key, bindings, back-sigs, AND revocations) is admitted or refused
//! by [`SigHash::for_algo`]; any algorithm outside the whitelist is `WeakHash(algo)` — one failure
                                                                                                  
//! §5.4 no-skip law, fails the whole keyring load.
//!
//! The v4 trailer construction (§6.2) appends, to the streamed data:
//! `B = 0x04 ‖ sig_type ‖ 0x01 ‖ hash_algo ‖ be16(hashed_len) ‖ hashed_area` — the RAW area bytes
//! exactly as parsed, never re-serialized — then `0x04 ‖ 0xFF ‖ be32(len(B))`. The version and
//! pubkey-algo octets are constants because `parse_sig` enforced them (`== 4`, `== 1`).
//!
//! RSA verification delegates to the in-tree `rsa` crate's encode-then-compare PKCS#1 v1.5 path
//! (the scheme carries the DigestInfo OID via `sha2`'s `oid` feature — never hand-rolled;
                                                                                                
//! MPIs, so ~1/256 of genuine signatures carry a shorter s); `s ≥ n` is `BadSignature` before the
//! call. Fixture law (§6.2): the trailer is verified DIFFERENTIALLY against gpg-produced
//! signatures — real signatures must verify, and every mutation of `B`'s fields must fail.

use crate::sig::SigPacket;
use crate::Error;
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

/// The §5.4 whitelist's upper modulus bound in bits — passed to the rsa constructor so the crate's
/// default 4096-bit cap does not silently narrow OUR whitelist (both real signers are 4096; the
/// spec admits up to 8192).
const RSA_MAX_BITS: usize = 8192;

/// A running signature digest under THE one hash whitelist. No SHA-1 arm exists (§14 E-2).
pub(crate) enum SigHash {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl SigHash {
    /// Admit or refuse a signature's hash algorithm: {8, 10} — for EVERY signature of every role.
                                                                                        
    pub fn for_algo(hash_algo: u8) -> Result<Self, Error> {
        match hash_algo {
            8 => Ok(SigHash::Sha256(Sha256::new())),
            10 => Ok(SigHash::Sha512(Sha512::new())),
            other => Err(Error::WeakHash(other)),
        }
    }

    /// Stream signed bytes into the digest (infallible).
    pub fn update(&mut self, chunk: &[u8]) {
        match self {
            SigHash::Sha256(h) => h.update(chunk),
            SigHash::Sha512(h) => h.update(chunk),
        }
    }

    /// Append `B ‖ trailer` (§6.2) over the already-streamed data and produce H.
    ///
    /// `B = 0x04 ‖ sig_type ‖ 0x01 ‖ hash_algo ‖ be16(hashed_len) ‖ hashed_area(RAW)`; the version
    /// and pubkey-algo octets are constants because `parse_sig` enforced `== 4` / `== 1`. The
    /// hashed area was framed by a be16 length, so `hashed_len ≤ 65535` and the casts are exact;
    /// `len(B) = 6 + hashed_len ≤ 65541`, so the saturating add cannot actually saturate.
    pub fn finalize_with_sig_fields(mut self, sig: &SigPacket<'_>) -> Vec<u8> {
        let hashed_len = sig.hashed_area.len() as u16;
        self.update(&[0x04, sig.sig_type, 0x01, sig.hash_algo]);
        self.update(&hashed_len.to_be_bytes());
        self.update(sig.hashed_area);
        let b_len = u32::from(hashed_len).saturating_add(6);
        self.update(&[0x04, 0xFF]);
        self.update(&b_len.to_be_bytes());
        match self {
            SigHash::Sha256(h) => h.finalize().to_vec(),
            SigHash::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Feed a key block's hash prefix: `0x99 ‖ be16(len) ‖ raw key body` (§6.3 — every keyring
/// signature role hashes the primary this way; subkey roles feed primary then subkey). Bodies come
/// from `parse_key_body` (≤ ~1 KiB under the n/e caps), so the be16 cast is exact.
pub(crate) fn feed_key_block(h: &mut SigHash, raw_key_body: &[u8]) {
    debug_assert!(
        raw_key_body.len() <= usize::from(u16::MAX),
        "key-block hashing is only defined for bodies <= 65535 bytes"
    );
    h.update(&[0x99]);
    h.update(&(raw_key_body.len() as u16).to_be_bytes());
    h.update(raw_key_body);
}

/// Feed a UID's hash prefix: `0xB4 ‖ be32(len) ‖ raw UID bytes` (§6.3, v4 certification hashing).
/// UID bodies are packet-framed (≤ `PACKET_BODY_MAX` = 64 KiB), so the be32 cast is exact.
pub(crate) fn feed_uid(h: &mut SigHash, raw_uid: &[u8]) {
    h.update(&[0xB4]);
    h.update(&(raw_uid.len() as u32).to_be_bytes());
    h.update(raw_uid);
}

/// The left-16 quick-reject (§5.3): a mismatch is `BadSignature`; a MATCH IS NEVER an accept-path
/// input (16 bits is not integrity) — callers proceed to the RSA verify on match.
pub(crate) fn left16_matches(sig: &SigPacket<'_>, digest: &[u8]) -> bool {
    matches!(digest, [a, b, ..] if [*a, *b] == sig.left16)
}

/// Delegated RSA PKCS#1 v1.5 verification (§6.4): encode-then-compare via the in-tree `rsa` crate
                                                                                    
///
/// `s ≥ n` is `BadSignature` before the call; the canonical-MPI `s` is left-padded to the modulus
/// byte length k (gpg emits minimal MPIs). Constructor failures also map to `BadSignature`: the
/// crate is deliberately STRICTER than the §5.4 parse whitelist (n odd, e < n, e < 2^33 vs our
/// e < 2^64) — a key the backend refuses is a key whose signatures cannot verify (fail-closed;
/// under the §5.4 no-skip law a keyring carrying one fails its load).
pub(crate) fn rsa_verify(
    n: &[u8],
    e: &[u8],
    hash_algo: u8,
    digest: &[u8],
    s_mpi: &[u8],
) -> Result<(), Error> {
    let n_int = BigUint::from_bytes_be(n);
    let s_int = BigUint::from_bytes_be(s_mpi);
    if s_int >= n_int {
        return Err(Error::BadSignature);
    }
    let key = RsaPublicKey::new_with_max_size(n_int, BigUint::from_bytes_be(e), RSA_MAX_BITS)
        .map_err(|_| Error::BadSignature)?;
                                                                                                     
                                                       
    let k = key.size();
    let pad = k.checked_sub(s_mpi.len()).ok_or(Error::BadSignature)?;
    let mut s_padded = vec![0u8; pad];
    s_padded.extend_from_slice(s_mpi);
    let result = match hash_algo {
        8 => key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, &s_padded),
        10 => key.verify(Pkcs1v15Sign::new::<Sha512>(), digest, &s_padded),
        other => return Err(Error::WeakHash(other)),
    };
    result.map_err(|_| Error::BadSignature)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{feed_key_block, feed_uid, left16_matches, rsa_verify, SigHash};
    use crate::sig::{parse_sig, SigPacket};
    use crate::{armor, key, packet, Error};

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    /// Armored `.sign` → the single tag-2 packet BODY bytes.
    fn sign_body(rel: &str) -> Vec<u8> {
        let bin = armor::decode_sign(&fixture(rel)).unwrap();
        let packets = packet::walk(&bin).unwrap();
        assert_eq!(packets.len(), 1);
        packets[0].body.to_vec()
    }

    /// (n, e) of the key that SIGNS for a generated keyring: key_a/c/d/e sign with the primary;
    /// key_b signs with its signing SUBKEY (gpg picks the signing-capable subkey when one exists).
    fn signer_n_e(keyring_rel: &str, subkey: bool) -> (Vec<u8>, Vec<u8>) {
        let blocks = armor::decode_keyring(&fixture(keyring_rel)).unwrap();
        let packets = packet::walk(&blocks[0]).unwrap();
        let block = key::parse_block(&packets).unwrap();
        let kb = if subkey {
            &block.subkeys[0].key
        } else {
            &block.primary
        };
        (kb.n.to_vec(), kb.e.to_vec())
    }

    /// The real verification pipeline at this layer: whitelist the algo, stream the payload,
    /// append B + trailer, quick-reject on left16, RSA-verify.
    fn verify_data_sig(sig_body: &[u8], payload: &[u8], n: &[u8], e: &[u8]) -> Result<(), Error> {
        let sig = parse_sig(sig_body)?;
        let mut h = SigHash::for_algo(sig.hash_algo)?;
        h.update(payload);
        let digest = h.finalize_with_sig_fields(&sig);
        if !left16_matches(&sig, &digest) {
            return Err(Error::BadSignature);
        }
        rsa_verify(n, e, sig.hash_algo, &digest, sig.s_mpi)
    }

                                                                                                    
    /// signature verifies through the real pipeline. This is the trailer's differential proof —
    /// gpg built these over the SAME construction §6.2 mandates.
    #[test]
    fn generated_positive_matrix_verifies() {
        let (an, ae) = signer_n_e("gen/key_a.asc", false);
        let (bn, be) = signer_n_e("gen/key_b.asc", true);
        for payload_name in ["empty", "1b", "1kib", "5mib"] {
            let payload = fixture(&format!("gen/payload_{payload_name}.bin"));
            for algo in ["sha256", "sha512"] {
                for (key_tag, n, e) in [("a", &an, &ae), ("b", &bn, &be)] {
                    let body = sign_body(&format!("gen/sig_{key_tag}_{payload_name}_{algo}.asc"));
                    assert_eq!(
                        verify_data_sig(&body, &payload, n, e),
                        Ok(()),
                        "sig_{key_tag}_{payload_name}_{algo}"
                    );
                }
            }
        }
    }

    /// The (b)-shape signatures are made by the SUBKEY: the primary's material must NOT verify
    /// them (also proves candidate keys are not interchangeable).
    #[test]
    fn subkey_signature_rejects_primary_material() {
        let (pn, pe) = signer_n_e("gen/key_b.asc", false);
        let body = sign_body("gen/sig_b_1b_sha256.asc");
        let payload = fixture("gen/payload_1b.bin");
        assert_eq!(
            verify_data_sig(&body, &payload, &pn, &pe),
            Err(Error::BadSignature)
        );
    }

    /// The leading-zero-MPI fixture (§6.4): gpg emitted a signature whose canonical s is SHORTER
    /// than k, so verification only succeeds if s is left-padded back to k.
    #[test]
    fn leading_zero_mpi_signature_verifies_via_padding() {
                                                                
        let bin = fixture("gen/sig_a_1b_sha256_leadingzero.sig");
        let packets = packet::walk(&bin).unwrap();
        assert_eq!(packets.len(), 1);
        let sig = parse_sig(packets[0].body).unwrap();
                                                                                            
        assert!(
            sig.s_mpi.len() < 512,
            "fixture lost its leading-zero property: {} bytes",
            sig.s_mpi.len()
        );
        let (n, e) = signer_n_e("gen/key_a.asc", false);
        let payload = fixture("gen/payload_1b.bin");
        assert_eq!(verify_data_sig(packets[0].body, &payload, &n, &e), Ok(()));
    }

    /// Chunking is semantics-free at the digest layer: one slab, byte-at-a-time, and ragged
    /// splits produce the identical digest and all verify.
    #[test]
    fn chunk_invariance_at_digest_layer() {
        let body = sign_body("gen/sig_a_1kib_sha512.asc");
        let sig = parse_sig(&body).unwrap();
        let payload = fixture("gen/payload_1kib.bin");

        let digest_of = |chunks: &[&[u8]]| {
            let mut h = SigHash::for_algo(sig.hash_algo).unwrap();
            for c in chunks {
                h.update(c);
            }
            h.finalize_with_sig_fields(&sig)
        };

        let slab = digest_of(&[&payload]);
        let bytewise: Vec<&[u8]> = payload.chunks(1).collect();
        assert_eq!(digest_of(&bytewise), slab);
        let mut ragged: Vec<&[u8]> = Vec::new();
        let mut off = 0;
        for step in [1usize, 7, 64, 250, 333, 999] {
            let end = (off + step).min(payload.len());
            ragged.push(&payload[off..end]);
            off = end;
        }
        ragged.push(&payload[off..]);
        assert_eq!(digest_of(&ragged), slab);

        let (n, e) = signer_n_e("gen/key_a.asc", false);
        assert!(left16_matches(&sig, &slab));
        assert_eq!(rsa_verify(&n, &e, sig.hash_algo, &slab, sig.s_mpi), Ok(()));
    }

    /// The §6.2 fixture law, mutation half: flipping ANY field of B — the sig-type octet, the
    /// hash-algo octet (8↔10), or any byte of the raw hashed area — must fail verification.
    /// (Structural hashed-area bytes may already fail the re-parse as Malformed; value bytes reach
    /// the crypto and die at the left16 quick-reject / RSA compare. Never Ok.)
    #[test]
    fn every_b_field_mutation_fails() {
        let body = sign_body("gen/sig_a_1b_sha256.asc");
        let payload = fixture("gen/payload_1b.bin");
        let (n, e) = signer_n_e("gen/key_a.asc", false);
        assert_eq!(verify_data_sig(&body, &payload, &n, &e), Ok(()));

                                    
        let mut m = body.clone();
        m[1] = 0x01;
        assert_eq!(
            verify_data_sig(&m, &payload, &n, &e),
            Err(Error::BadSignature),
            "sig_type flip"
        );

                                                                                        
        let mut m = body.clone();
        assert_eq!(m[3], 8);
        m[3] = 10;
        assert_eq!(
            verify_data_sig(&m, &payload, &n, &e),
            Err(Error::BadSignature),
            "hash_algo swap"
        );

                                                                                                    
                                                    
        let hashed_len = usize::from(u16::from_be_bytes([body[4], body[5]]));
        for i in 6..6 + hashed_len {
            let mut m = body.clone();
            m[i] ^= 0x01;
            let r = verify_data_sig(&m, &payload, &n, &e);
            assert!(
                matches!(r, Err(Error::Malformed(_)) | Err(Error::BadSignature)),
                "hashed-area byte {i}: {r:?}"
            );
        }
    }

    /// left16 is a quick-reject ONLY: a corrupted left16 rejects a signature RSA would accept
    /// (fail-closed), and a wrong payload is rejected before any modexp.
    #[test]
    fn left16_quick_reject_semantics() {
        let body = sign_body("gen/sig_a_1b_sha256.asc");
        let payload = fixture("gen/payload_1b.bin");
        let sig = parse_sig(&body).unwrap();
        let hashed_len = usize::from(u16::from_be_bytes([body[4], body[5]]));
        let unhashed_off = 6 + hashed_len;
        let unhashed_len = usize::from(u16::from_be_bytes([
            body[unhashed_off],
            body[unhashed_off + 1],
        ]));
        let left16_off = unhashed_off + 2 + unhashed_len;

                                                                                               
        let mut m = body.clone();
        m[left16_off] ^= 0xFF;
        let (n, e) = signer_n_e("gen/key_a.asc", false);
        assert_eq!(
            verify_data_sig(&m, &payload, &n, &e),
            Err(Error::BadSignature),
            "corrupted left16 must reject even though RSA would verify"
        );

                                                                                            
        let mut h = SigHash::for_algo(sig.hash_algo).unwrap();
        h.update(b"not the payload");
        let digest = h.finalize_with_sig_fields(&sig);
        assert!(!left16_matches(&sig, &digest));
    }

    /// s ≥ n is BadSignature before any modexp (both s == n and s > n).
    #[test]
    fn s_ge_n_is_bad_signature() {
        let (n, e) = signer_n_e("gen/key_a.asc", false);
        let h = [0u8; 32];
        assert_eq!(
            rsa_verify(&n, &e, 8, &h, &n),
            Err(Error::BadSignature),
            "s == n"
        );
        let mut bigger = n.clone();
        *bigger.last_mut().unwrap() |= 1;
        bigger[0] = 0xFF;
        assert_eq!(
            rsa_verify(&n, &e, 8, &h, &bigger),
            Err(Error::BadSignature),
            "s > n"
        );
    }

    /// THE hash whitelist: everything outside {8, 10} is WeakHash(algo) — including the real
    /// gpg-produced SHA-1 signature fixture (§14 E-2; one failure class per root cause).
    #[test]
    fn non_whitelisted_hash_algos_are_weak_hash() {
        for algo in [1u8, 2, 3, 11, 12, 14] {
            match SigHash::for_algo(algo) {
                Err(Error::WeakHash(a)) => assert_eq!(a, algo),
                Err(other) => panic!("algo {algo}: expected WeakHash, got {other:?}"),
                Ok(_) => panic!("algo {algo}: unexpectedly admitted"),
            }
        }
                                                                              
        let body = sign_body("gen/sig_a_1b_sha1_weak.asc");
        let sig = parse_sig(&body).unwrap();
        assert_eq!(sig.hash_algo, 2);
        assert!(matches!(
            SigHash::for_algo(sig.hash_algo),
            Err(Error::WeakHash(2))
        ));
    }

    /// The rsa crate's validating constructor is STRICTER than the parse whitelist on e
    /// (< 2^33 vs our < 2^64): such a key's signatures fail closed as BadSignature.
    #[test]
    fn oversized_exponent_fails_closed() {
        let (n, _) = signer_n_e("gen/key_a.asc", false);
        let e_2_33_plus_1 = [0x02, 0x00, 0x00, 0x00, 0x01];                              
        let h = [0u8; 32];
        let s = [0x42u8; 32];
        assert_eq!(
            rsa_verify(&n, &e_2_33_plus_1, 8, &h, &s),
            Err(Error::BadSignature)
        );
    }

    /// Early differential proof of the §6.3 feed helpers against REAL gpg bytes: Greg's newest
    /// self-certification (0x13, SHA-512) verifies over
    /// feed_key_block(primary) ‖ feed_uid(uid) ‖ B ‖ trailer with Greg's own key material.
    #[test]
    fn real_self_cert_verifies_through_feed_helpers() {
        let blocks = armor::decode_keyring(&fixture("real/greg-pruned.asc")).unwrap();
        let packets = packet::walk(&blocks[0]).unwrap();
        let block = key::parse_block(&packets).unwrap();
        let uid = &block.uids[0];
        let sig: &SigPacket<'_> = &uid.sigs[0];
        assert!(matches!(sig.sig_type, 0x10..=0x13));

        let mut h = SigHash::for_algo(sig.hash_algo).unwrap();
        feed_key_block(&mut h, block.primary.raw);
        feed_uid(&mut h, uid.raw);
        let digest = h.finalize_with_sig_fields(sig);
        assert!(left16_matches(sig, &digest));
        assert_eq!(
            rsa_verify(
                block.primary.n,
                block.primary.e,
                sig.hash_algo,
                &digest,
                sig.s_mpi
            ),
            Ok(())
        );

                                                                                                  
        let mut h = SigHash::for_algo(sig.hash_algo).unwrap();
        feed_key_block(&mut h, block.primary.raw);
        let mut uid_flipped = uid.raw.to_vec();
        uid_flipped[0] ^= 0x01;
        feed_uid(&mut h, &uid_flipped);
        let digest = h.finalize_with_sig_fields(sig);
        assert!(!left16_matches(sig, &digest));
    }
}
