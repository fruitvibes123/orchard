//! Key/subkey body parse, the v4 fingerprint, and the §5.4 positional block grammar.
//!
//! Key bodies are v4 + RSA only, with sanity bounds: `n` ∈ [2048, 8192] bits (both real signers
//! are rsa4096), `e` odd with 3 ≤ e < 2^64. The block grammar is positional and exact:
//!
//! ```text
//! Primary(6)  [Sig 0x1F|0x20]*  ( UID(13) [Sig 0x10-0x13|0x30]* )+  ( Subkey(14) [Sig 0x18|0x28]* )*
//! ```
//!
//! Tags outside {6, 14, 13, 2} — including User Attributes (17) and Markers (10), which the §5.0
//! vendored-input contract strips — are `Malformed`, never skip paths (the R1-2 reordering hazard:
//! a skipped section is a place to hide a repositioned self-cert). Signature classification is by
//! POSITION ALONE; issuer hints play no role (§5.4). This module only parses and classifies —
//! cryptographic verification of every signature (the no-skip law) is `policy.rs`'s job (§6.3).

use crate::packet::RawPacket;
use crate::reader::Reader;
use crate::sig::{parse_mpi, parse_sig, SigPacket};
use crate::Error;
use sha1::{Digest, Sha1};

/// A v4 key fingerprint: 20 bytes, the pin currency of the whole API (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 20]);

impl Fingerprint {
    /// Parse exactly 40 hex chars (either case). `None` on any other shape — pins are
    /// operator-reviewed constants, so this is a config parse, not a hostile-input path.
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
            let hi = hex_nibble(pair.first().copied()?)?;
            let lo = hex_nibble(pair.get(1).copied()?)?;
                                                                       
            *slot = (hi << 4) | lo;
        }
        Some(Fingerprint(out))
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
                                                                                           
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// A parsed v4 RSA key/subkey body. `n`/`e` are the canonical MPI payloads; `raw` is the full
/// packet body — the fingerprint input and §6.2's `feed_key_block` material.
#[derive(Debug)]
pub(crate) struct KeyBody<'a> {
    pub created: u32,
    pub n: &'a [u8],
    pub e: &'a [u8],
    pub raw: &'a [u8],
}

/// Parse a tag-6/14 body under the §5.4 whitelist: v4 + RSA only, exact consumption, n/e sanity.
pub(crate) fn parse_key_body(body: &[u8]) -> Result<KeyBody<'_>, Error> {
    let mut r = Reader::new(body);
    if r.u8()? != 4 {
        return Err(Error::Unsupported("non-v4 key version"));
    }
    let created = r.u32_be()?;
    if r.u8()? != 1 {
        return Err(Error::Unsupported("non-RSA public-key algorithm"));
    }
    let n = parse_mpi(&mut r)?;
    let e = parse_mpi(&mut r)?;
    if !r.is_empty() {
        return Err(Error::Malformed("trailing bytes after key MPIs"));
    }
                                                                                                  
    let n_bits = mpi_bits(n);
    if !(2048..=8192).contains(&n_bits) {
        return Err(Error::Unsupported("RSA modulus outside 2048..=8192 bits"));
    }
                              
    if e.len() > 8 {
        return Err(Error::Malformed("RSA public exponent too large"));
    }
    let e_val = e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    if e_val < 3 || e_val & 1 == 0 {
        return Err(Error::Malformed("invalid RSA public exponent"));
    }
    Ok(KeyBody {
        created,
        n,
        e,
        raw: body,
    })
}

/// Bit length of a canonical MPI payload. Saturating math: the leading octet of a canonical MPI
/// is nonzero (leading_zeros ≤ 7 < len·8), so nothing actually saturates.
fn mpi_bits(payload: &[u8]) -> usize {
    match payload.first() {
        None => 0,
        Some(&f) => payload
            .len()
            .saturating_mul(8)
            .saturating_sub(f.leading_zeros() as usize),
    }
}

/// The v4 fingerprint: SHA-1(0x99 ‖ be16(body_len) ‖ body) — RFC 4880 §12.2.
///
/// THE one SHA-1 construction site in the whole crate (§3/§6.4/§14 E-2): fingerprint computation
/// is IDENTIFICATION, never signature verification — every signature of every role hashes through
/// `verify.rs`'s {SHA-256, SHA-512}-only `SigHash`. The A2 gate greps for exactly this call site.
///
/// The be16 length is part of the v4 DEFINITION, which only exists for bodies ≤ 65535 bytes; every
/// caller passes a `parse_key_body`-validated body (≤ ~1 KiB under the n/e caps). For any
/// out-of-contract input the truncating cast would merely produce a fingerprint matching no pin —
/// fail-closed at the pin comparison (a deliberate preimage, not a collision, would be required).
pub(crate) fn v4_fingerprint(raw_body: &[u8]) -> Fingerprint {
                                                                                                  
                                                                               
    debug_assert!(
        raw_body.len() <= usize::from(u16::MAX),
        "v4 fingerprint is only defined for bodies <= 65535 bytes"
    );
    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((raw_body.len() as u16).to_be_bytes());
    h.update(raw_body);
    Fingerprint(h.finalize().into())
}

/// A UID section: the raw UID bytes + the signatures positioned after it (0x10–0x13 | 0x30).
#[derive(Debug)]
pub(crate) struct Uid<'a> {
    pub raw: &'a [u8],
    pub sigs: Vec<SigPacket<'a>>,
}

/// A subkey section: the parsed subkey + its fingerprint + the signatures positioned after it
/// (0x18 | 0x28).
#[derive(Debug)]
pub(crate) struct SubkeySection<'a> {
    pub key: KeyBody<'a>,
    pub fpr: Fingerprint,
    pub sigs: Vec<SigPacket<'a>>,
}

/// One armored block's parse result: the §5.4 grammar, positionally classified, nothing skipped.
#[derive(Debug)]
pub(crate) struct KeyBlock<'a> {
    pub primary: KeyBody<'a>,
    pub primary_fpr: Fingerprint,
    pub direct_sigs: Vec<SigPacket<'a>>,
    pub uids: Vec<Uid<'a>>,
    pub subkeys: Vec<SubkeySection<'a>>,
}

/// Which grammar section the walk is in — strictly forward-moving.
#[derive(PartialEq, Eq)]
enum Section {
    Direct,
    Uids,
    Subkeys,
}

/// Parse one block's packet list under the positional grammar (see the module docs). Every
/// signature packet is fully parsed here; cryptographic verification is `policy.rs` (§6.3).
pub(crate) fn parse_block<'a>(packets: &[RawPacket<'a>]) -> Result<KeyBlock<'a>, Error> {
    let mut it = packets.iter();
    let first = it.next().ok_or(Error::Malformed("empty key block"))?;
    if first.tag != 6 {
        return Err(Error::Malformed(
            "key block does not start with a primary key",
        ));
    }
    let primary = parse_key_body(first.body)?;
    let primary_fpr = v4_fingerprint(first.body);

    let mut direct_sigs = Vec::new();
    let mut uids: Vec<Uid<'a>> = Vec::new();
    let mut subkeys: Vec<SubkeySection<'a>> = Vec::new();
    let mut section = Section::Direct;

    for p in it {
        match p.tag {
            6 => return Err(Error::Malformed("second primary key in block")),
            13 => {
                if section == Section::Subkeys {
                    return Err(Error::Malformed("user id after a subkey"));
                }
                section = Section::Uids;
                uids.push(Uid {
                    raw: p.body,
                    sigs: Vec::new(),
                });
            }
            14 => {
                if uids.is_empty() {
                    return Err(Error::Malformed("subkey before the first user id"));
                }
                section = Section::Subkeys;
                subkeys.push(SubkeySection {
                    key: parse_key_body(p.body)?,
                    fpr: v4_fingerprint(p.body),
                    sigs: Vec::new(),
                });
            }
            2 => {
                let sig = parse_sig(p.body)?;
                match section {
                    Section::Direct => {
                        if !matches!(sig.sig_type, 0x1F | 0x20) {
                            return Err(Error::Malformed("signature type outside its position"));
                        }
                        direct_sigs.push(sig);
                    }
                    Section::Uids => {
                        if !matches!(sig.sig_type, 0x10..=0x13 | 0x30) {
                            return Err(Error::Malformed("signature type outside its position"));
                        }
                        uids.last_mut()
                            .ok_or(Error::Malformed("signature without a user id"))?
                            .sigs
                            .push(sig);
                    }
                    Section::Subkeys => {
                        if !matches!(sig.sig_type, 0x18 | 0x28) {
                            return Err(Error::Malformed("signature type outside its position"));
                        }
                        subkeys
                            .last_mut()
                            .ok_or(Error::Malformed("signature without a subkey"))?
                            .sigs
                            .push(sig);
                    }
                }
            }
            _ => return Err(Error::Malformed("packet tag outside keyring whitelist")),
        }
    }
    if uids.is_empty() {
        return Err(Error::Malformed("key block has no user id"));
    }
    Ok(KeyBlock {
        primary,
        primary_fpr,
        direct_sigs,
        uids,
        subkeys,
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
    use super::{parse_block, parse_key_body, Fingerprint};
    use crate::forge::{mpi, sig_packet_of_type, uid_packet, KeyForge, SigForge};
    use crate::{armor, packet, Error};

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

                                                                                
    const GREG_PIN: &str = "647F28654894E3BD457199BE38DBBDC86092693E";
    const SASHA_PIN: &str = "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC";
    const GREG_CREATED: u32 = 1316795861;
    const SASHA_CREATED: u32 = 1328804765;

    /// Armor + walk + parse one real keyring block.
    fn real_block_packets(rel: &str) -> Vec<u8> {
        let mut blocks = armor::decode_keyring(&fixture(rel)).unwrap();
        assert_eq!(blocks.len(), 1);
        blocks.remove(0)
    }

                                                                                           
    /// fingerprints equal the §3 pins exactly (this is the differential proof that the whole
    /// parse + fingerprint stack reproduces gpg's identity for the real material).
    #[test]
    fn real_blocks_parse_and_fingerprints_match_pins() {
        let greg_bin = real_block_packets("real/greg-pruned.asc");
        let greg_packets = packet::walk(&greg_bin).unwrap();
        let greg = parse_block(&greg_packets).unwrap();
        assert_eq!(greg.primary_fpr, Fingerprint::from_hex(GREG_PIN).unwrap());
        assert_eq!(greg.primary.created, GREG_CREATED);
        assert_eq!(greg.uids.len(), 3);
        assert_eq!(greg.subkeys.len(), 0);
        assert_eq!(greg.direct_sigs.len(), 0);

        let sasha_bin = real_block_packets("real/sasha-pruned.asc");
        let sasha_packets = packet::walk(&sasha_bin).unwrap();
        let sasha = parse_block(&sasha_packets).unwrap();
        assert_eq!(sasha.primary_fpr, Fingerprint::from_hex(SASHA_PIN).unwrap());
        assert_eq!(sasha.primary.created, SASHA_CREATED);
        assert_eq!(sasha.uids.len(), 1);
        assert_eq!(sasha.subkeys.len(), 0);
    }

    /// Whitelist-fits-reality evidence: the per-sig hash algos across both real blocks equal
    /// METADATA's `trust_granting_hash_algos` — every real trust-granting signature is already
    /// inside the {8, 10} whitelist, so the §5.0 pruning did its job.
    #[test]
    fn real_self_cert_hash_algos_match_metadata() {
        let greg_bin = real_block_packets("real/greg-pruned.asc");
        let greg_packets = packet::walk(&greg_bin).unwrap();
        let greg = parse_block(&greg_packets).unwrap();
        let greg_algos: Vec<u8> = greg
            .uids
            .iter()
            .flat_map(|u| u.sigs.iter().map(|s| s.hash_algo))
            .collect();
        assert_eq!(greg_algos, vec![10, 8, 8]);
                                                                                              
        for uid in &greg.uids {
            assert_eq!(uid.sigs.len(), 1);
            assert!(matches!(uid.sigs[0].sig_type, 0x10..=0x13));
        }

        let sasha_bin = real_block_packets("real/sasha-pruned.asc");
        let sasha_packets = packet::walk(&sasha_bin).unwrap();
        let sasha = parse_block(&sasha_packets).unwrap();
        let sasha_algos: Vec<u8> = sasha
            .uids
            .iter()
            .flat_map(|u| u.sigs.iter().map(|s| s.hash_algo))
            .collect();
        assert_eq!(sasha_algos, vec![10]);
    }

    #[test]
    fn fingerprint_from_hex_is_exact() {
        let f = Fingerprint::from_hex(GREG_PIN).unwrap();
        assert_eq!(f.0[0], 0x64);
        assert_eq!(f.0[19], 0x3E);
                                                             
        assert_eq!(Fingerprint::from_hex(&GREG_PIN.to_lowercase()).unwrap(), f);
        assert!(Fingerprint::from_hex("647F").is_none());
        assert!(Fingerprint::from_hex(&"G".repeat(40)).is_none());
    }

    /// The forged baseline key body parses; n/e land byte-exact.
    #[test]
    fn forged_key_body_parses() {
        let kf = KeyForge::baseline(1_781_000_000);
        let body = kf.body();
        let kb = parse_key_body(&body).unwrap();
        assert_eq!(kb.created, 1_781_000_000);
        assert_eq!(kb.n, &[0xC3; 256][..]);
        assert_eq!(kb.e, &[0x01, 0x00, 0x01][..]);
        assert_eq!(kb.raw, &body[..]);
    }

    #[test]
    fn non_v4_or_non_rsa_keys_are_unsupported() {
        let mut kf = KeyForge::baseline(1);
        kf.version = 3;
        assert_eq!(
            parse_key_body(&kf.body()).unwrap_err(),
            Error::Unsupported("non-v4 key version")
        );
        let mut kf = KeyForge::baseline(1);
        kf.algo = 22;         
        assert_eq!(
            parse_key_body(&kf.body()).unwrap_err(),
            Error::Unsupported("non-RSA public-key algorithm")
        );
    }

    /// n outside [2048, 8192] bits is Unsupported — both directions.
    #[test]
    fn modulus_size_bounds_are_enforced() {
        let mut kf = KeyForge::baseline(1);
        kf.n = mpi(&[0x80; 128]);             
        assert_eq!(
            parse_key_body(&kf.body()).unwrap_err(),
            Error::Unsupported("RSA modulus outside 2048..=8192 bits")
        );
        let mut kf = KeyForge::baseline(1);
        kf.n = mpi(&[0x80; 1025]);             
        assert_eq!(
            parse_key_body(&kf.body()).unwrap_err(),
            Error::Unsupported("RSA modulus outside 2048..=8192 bits")
        );
                                                 
        let mut kf = KeyForge::baseline(1);
        kf.n = mpi(&[0xFF; 256]);        
        assert!(parse_key_body(&kf.body()).is_ok());
        let mut kf = KeyForge::baseline(1);
        kf.n = mpi(&[0x80; 1024]);        
        assert!(parse_key_body(&kf.body()).is_ok());
    }

    /// e must be odd, 3 ≤ e < 2^64.
    #[test]
    fn exponent_sanity_is_enforced() {
        for bad_e in [&[0x10][..], &[0x01][..]] {
                                 
            let mut kf = KeyForge::baseline(1);
            kf.e = mpi(bad_e);
            assert_eq!(
                parse_key_body(&kf.body()).unwrap_err(),
                Error::Malformed("invalid RSA public exponent"),
                "e payload {bad_e:02X?}"
            );
        }
        let mut kf = KeyForge::baseline(1);
        kf.e = mpi(&[0x01; 9]);            
        assert_eq!(
            parse_key_body(&kf.body()).unwrap_err(),
            Error::Malformed("RSA public exponent too large")
        );
    }

    #[test]
    fn trailing_bytes_after_key_mpis_are_malformed() {
        let mut body = KeyForge::baseline(1).body();
        body.push(0x00);
        assert_eq!(
            parse_key_body(&body).unwrap_err(),
            Error::Malformed("trailing bytes after key MPIs")
        );
    }

                                                                         

    /// A minimal valid block: primary + one UID + one self-cert; sections land where the grammar
    /// says.
    #[test]
    fn forged_minimal_block_parses() {
        let stream = [
            KeyForge::baseline(1).packet(6),
            uid_packet(b"Test User <t@example.org>"),
            sig_packet_of_type(0x13, 2),
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        let block = parse_block(&packets).unwrap();
        assert_eq!(block.uids.len(), 1);
        assert_eq!(block.uids[0].raw, b"Test User <t@example.org>");
        assert_eq!(block.uids[0].sigs.len(), 1);
        assert!(block.direct_sigs.is_empty());
        assert!(block.subkeys.is_empty());
    }

    /// Direct-key sigs before the first UID; a subkey section with binding sigs after UIDs.
    #[test]
    fn forged_full_block_sections_classify_by_position() {
        let stream = [
            KeyForge::baseline(1).packet(6),
            sig_packet_of_type(0x1F, 2),              
            uid_packet(b"u1"),
            sig_packet_of_type(0x13, 3),
            sig_packet_of_type(0x30, 4),                                             
            KeyForge::baseline(5).packet(14),
            sig_packet_of_type(0x18, 6),           
            sig_packet_of_type(0x28, 7),                     
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        let block = parse_block(&packets).unwrap();
        assert_eq!(block.direct_sigs.len(), 1);
        assert_eq!(block.uids.len(), 1);
        assert_eq!(block.uids[0].sigs.len(), 2);
        assert_eq!(block.subkeys.len(), 1);
        assert_eq!(block.subkeys[0].sigs.len(), 2);
    }

    /// Tags outside {6, 14, 13, 2} are Malformed — User Attribute (17) and Marker (10)
    /// explicitly so (§5.2/§5.4: no skip paths).
    #[test]
    fn uat_and_marker_tags_are_malformed() {
        for tag in [17u8, 10, 12, 5] {
            let stream = [
                KeyForge::baseline(1).packet(6),
                uid_packet(b"u"),
                sig_packet_of_type(0x13, 2),
                crate::forge::frame_new_format(tag, b"x"),
            ]
            .concat();
            let packets = packet::walk(&stream).unwrap();
            assert_eq!(
                parse_block(&packets).unwrap_err(),
                Error::Malformed("packet tag outside keyring whitelist"),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn second_primary_in_block_is_malformed() {
        let stream = [
            KeyForge::baseline(1).packet(6),
            uid_packet(b"u"),
            sig_packet_of_type(0x13, 2),
            KeyForge::baseline(3).packet(6),
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Malformed("second primary key in block")
        );
    }

    /// Signature types outside their positional whitelist are Malformed: a binding sig (0x18)
    /// after a UID, a data sig (0x00) after the primary, a self-cert (0x13) after a subkey.
    #[test]
    fn sig_type_outside_position_is_malformed() {
        let cases: Vec<Vec<u8>> = vec![
                                    
            [
                KeyForge::baseline(1).packet(6),
                uid_packet(b"u"),
                sig_packet_of_type(0x18, 2),
            ]
            .concat(),
                                       
            [KeyForge::baseline(1).packet(6), sig_packet_of_type(0x00, 2)].concat(),
                                       
            [
                KeyForge::baseline(1).packet(6),
                uid_packet(b"u"),
                sig_packet_of_type(0x13, 2),
                KeyForge::baseline(3).packet(14),
                sig_packet_of_type(0x13, 4),
            ]
            .concat(),
        ];
        for (i, stream) in cases.iter().enumerate() {
            let packets = packet::walk(stream).unwrap();
            assert_eq!(
                parse_block(&packets).unwrap_err(),
                Error::Malformed("signature type outside its position"),
                "case {i}"
            );
        }
    }

    /// The grammar requires ≥1 UID, and subkeys strictly after all UIDs.
    #[test]
    fn uid_ordering_rules_are_enforced() {
                                 
        let stream = [
            KeyForge::baseline(1).packet(6),
            KeyForge::baseline(2).packet(14),
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Malformed("subkey before the first user id")
        );

                              
        let stream = [
            KeyForge::baseline(1).packet(6),
            uid_packet(b"u"),
            sig_packet_of_type(0x13, 2),
            KeyForge::baseline(3).packet(14),
            uid_packet(b"late"),
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Malformed("user id after a subkey")
        );

                     
        let stream = KeyForge::baseline(1).packet(6);
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Malformed("key block has no user id")
        );

                                       
        let stream = uid_packet(b"u");
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Malformed("key block does not start with a primary key")
        );
    }

    /// A malformed signature packet ANYWHERE in a block fails the block parse (no tolerate-and-
    /// skip at the grammar layer either).
    #[test]
    fn malformed_sig_packet_fails_the_block() {
        let mut bad_sig = SigForge::baseline(2);
        bad_sig.sig_type = 0x13;
        bad_sig.version = 3;
        let stream = [
            KeyForge::baseline(1).packet(6),
            uid_packet(b"u"),
            bad_sig.packet(),
        ]
        .concat();
        let packets = packet::walk(&stream).unwrap();
        assert_eq!(
            parse_block(&packets).unwrap_err(),
            Error::Unsupported("non-v4 signature version")
        );
    }
}
