                                                                                                 
//!
//! Version whitelist {4}; public-key algorithm whitelist {1} (RSA encrypt-or-sign). Both subpacket
//! areas are walked with the same framing and EXACT consumption — every declared length lands
//! in-bounds and the walk consumes each area completely (no unwalked bytes for anything to hide
//! in). Policy-bearing subpackets (creation 2, sig-expiry 3, key-expiry 9, key-flags 27) are
//! consumed from the HASHED area only — the same ids in the unhashed area are attacker-malleable
//! and are ignored wholesale, never merged, never a fallback. Two stated exceptions: embedded
//! signature (32) is accepted from either area because its authority is its own cryptographic
//! verification (§6.3), and issuer fingerprint (33) / issuer key id (16) are read from either area
//! as DIAGNOSTICS only (§6.1 — they never select a key or an error class). Duplicates of any
//! consumed subpacket are `Malformed` (no pick-the-friendly-one games). Unknown subpackets: with
//! the critical bit in a hashed area = `Malformed` (RFC 4880 mandate); otherwise skipped.
//!
//! The hash algorithm octet is RECORDED here, not judged — every signature's hash is admitted or
//! refused by `verify.rs`'s single `{SHA-256, SHA-512}` whitelist (§14 E-2) at use time.
//!
//! MPIs are strict-canonical (§5.3): be16 bit count, exactly ceil(bits/8) payload octets, declared
//! MSB position == actual — non-minimal encodings are `Malformed` (kills length-ambiguity games).
                                                                                                 
//! is accepted and exact-consumed, and the hashed area is hashed RAW so a re-encoding breaks the
//! signature — but downstream code must therefore never byte-COMPARE subpacket encodings.

use crate::limits::SUBPACKETS_MAX;
use crate::reader::Reader;
use crate::Error;

/// A parsed v4 RSA signature packet. `hashed_area` is the RAW area bytes exactly as parsed —
/// §6.2's trailer construction re-emits them verbatim, so tampering anywhere in the area breaks
/// the digest. Policy fields come from the hashed area only; `issuer_fpr_diag` is a diagnostic
/// (never key selection, never an error-class selector — §6.1/§14 E-1).
#[derive(Debug)]
pub(crate) struct SigPacket<'a> {
    pub sig_type: u8,
    pub hash_algo: u8,
    /// The FULL raw packet body this was parsed from — the §6.3 tiebreaker's final
    /// byte-lexicographic axis compares it (a deterministic total order needs the whole packet).
    pub raw: &'a [u8],
    pub hashed_area: &'a [u8],
    pub left16: [u8; 2],
    pub s_mpi: &'a [u8],
    pub created: u32,
    pub sig_expiry: Option<u32>,
    pub key_expiry: Option<u32>,
    pub key_flags: Option<u8>,
    pub embedded_sig: Option<&'a [u8]>,
    /// Deliberately INERT in all control flow (§6.1/§14 E-1 — issuer hints never select a key or
    /// an error class), and `Error` carries no dynamic payloads to decorate (log-injection
    /// hygiene), so production code parses-and-never-reads it; the §7.1 real-issuer consistency
    /// anchor (a test) is its reader. The allow states exactly that.
    #[allow(dead_code)]
    pub issuer_fpr_diag: Option<[u8; 20]>,
}

/// Parse a tag-2 packet body under the §5.3 whitelist. The body must be consumed exactly.
pub(crate) fn parse_sig(body: &[u8]) -> Result<SigPacket<'_>, Error> {
    let mut r = Reader::new(body);
    if r.u8()? != 4 {
        return Err(Error::Unsupported("non-v4 signature version"));
    }
    let sig_type = r.u8()?;
    if r.u8()? != 1 {
        return Err(Error::Unsupported("non-RSA public-key algorithm"));
    }
                                                                                                   
    let hash_algo = r.u8()?;
    let hashed_len = usize::from(r.u16_be()?);
    let hashed_area = r.take(hashed_len)?;
    let unhashed_len = usize::from(r.u16_be()?);
    let unhashed_area = r.take(unhashed_len)?;
    let left16 = match r.take(2)? {
        [a, b] => [*a, *b],
        _ => return Err(Error::Malformed("truncated")),
    };
    let s_mpi = parse_mpi(&mut r)?;
    if !r.is_empty() {
        return Err(Error::Malformed("trailing bytes after signature MPI"));
    }

    let mut f = Fields::default();
    walk_area(hashed_area, true, &mut f)?;
    walk_area(unhashed_area, false, &mut f)?;
    let created = f
        .created
        .ok_or(Error::Malformed("missing creation-time subpacket"))?;

    Ok(SigPacket {
        sig_type,
        hash_algo,
        raw: body,
        hashed_area,
        left16,
        s_mpi,
        created,
        sig_expiry: f.sig_expiry,
        key_expiry: f.key_expiry,
        key_flags: f.key_flags,
        embedded_sig: f.embedded_sig,
        issuer_fpr_diag: f.issuer_fpr_diag,
    })
}

/// Strict-canonical MPI (§5.3): be16 bit count, exactly ceil(bits/8) payload octets, declared MSB
/// position == actual. Returns the payload bytes. Shared with `key.rs` (n, e).
pub(crate) fn parse_mpi<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let bits = r.u16_be()?;
    let nbytes = usize::from(bits).div_ceil(8);
    let payload = r.take(nbytes)?;
    if bits > 0 {
                                                                                
        let first = payload
            .first()
            .copied()
            .ok_or(Error::Malformed("truncated"))?;
                                                                                               
                                                                                            
                                                                            
        let expected_lz = 7u32.wrapping_sub(u32::from(bits.wrapping_sub(1) % 8));
        if first.leading_zeros() != expected_lz {
            return Err(Error::Malformed("non-canonical MPI"));
        }
    }
    Ok(payload)
}

/// Subpacket fields accumulated across BOTH areas (hashed walked first). Duplicate detection for
/// the either-area subpackets (32, 33, 16) therefore spans areas.
#[derive(Default)]
struct Fields<'a> {
    created: Option<u32>,
    sig_expiry: Option<u32>,
    key_expiry: Option<u32>,
    key_flags: Option<u8>,
    embedded_sig: Option<&'a [u8]>,
    issuer_fpr_diag: Option<[u8; 20]>,
    seen_issuer_keyid: bool,
}

                                                                                                 
/// (RFC 4880 §5.2.3.1 — the 2-octet form spans first octets 192..=254; there are no partials
/// here); every declared length lands in-bounds; the loop runs until the area is empty, so the
/// final offset equals the area length by construction.
fn walk_area<'a>(area: &'a [u8], hashed: bool, f: &mut Fields<'a>) -> Result<(), Error> {
    let mut r = Reader::new(area);
    let mut count: usize = 0;
    while !r.is_empty() {
        count = count.saturating_add(1);
        if count > SUBPACKETS_MAX {
            return Err(Error::Malformed("too many subpackets"));
        }
        let b0 = r.u8()?;
        let sp_len = match b0 {
            0..=191 => usize::from(b0),
            192..=254 => {
                                                                                                      
                                                                
                let b1 = r.u8()?;
                usize::from(u16::from_be_bytes([b0.wrapping_sub(192), b1]).wrapping_add(192))
            }
            255 => usize::try_from(r.u32_be()?).map_err(|_| Error::Malformed("truncated"))?,
        };
                                                                              
        if sp_len == 0 {
            return Err(Error::Malformed("zero-length subpacket"));
        }
        let sp = r.take(sp_len)?;
        let mut sr = Reader::new(sp);
        let type_octet = sr.u8()?;
        let body = sr.take(sr.remaining())?;
        handle_subpacket(type_octet & 0x7F, type_octet & 0x80 != 0, body, hashed, f)?;
    }
    Ok(())
}

/// Dispatch one subpacket per the §5.3 consumption rules (see the module docs).
fn handle_subpacket<'a>(
    id: u8,
    critical: bool,
    body: &'a [u8],
    hashed: bool,
    f: &mut Fields<'a>,
) -> Result<(), Error> {
    match id {
                                                                                                  
        2 | 3 | 9 | 27 if !hashed => Ok(()),
        2 => {
            if f.created.is_some() {
                return Err(Error::Malformed("duplicate creation-time subpacket"));
            }
            f.created = Some(u32_body(body)?);
            Ok(())
        }
        3 => {
            if f.sig_expiry.is_some() {
                return Err(Error::Malformed("duplicate signature-expiration subpacket"));
            }
            f.sig_expiry = Some(u32_body(body)?);
            Ok(())
        }
        9 => {
            if f.key_expiry.is_some() {
                return Err(Error::Malformed("duplicate key-expiration subpacket"));
            }
            f.key_expiry = Some(u32_body(body)?);
            Ok(())
        }
        27 => {
            if f.key_flags.is_some() {
                return Err(Error::Malformed("duplicate key-flags subpacket"));
            }
                                                                                        
            f.key_flags = Some(
                body.first()
                    .copied()
                    .ok_or(Error::Malformed("empty key-flags subpacket"))?,
            );
            Ok(())
        }
        32 => {
            if f.embedded_sig.is_some() {
                return Err(Error::Malformed("duplicate embedded-signature subpacket"));
            }
            f.embedded_sig = Some(body);
            Ok(())
        }
        33 => {
            if f.issuer_fpr_diag.is_some() {
                return Err(Error::Malformed("duplicate issuer-fingerprint subpacket"));
            }
                                                                             
            match body {
                [4, fpr @ ..] if fpr.len() == 20 => {
                    let mut a = [0u8; 20];
                    a.copy_from_slice(fpr);
                    f.issuer_fpr_diag = Some(a);
                    Ok(())
                }
                _ => Err(Error::Malformed("malformed issuer-fingerprint subpacket")),
            }
        }
        16 => {
            if f.seen_issuer_keyid {
                return Err(Error::Malformed("duplicate issuer-key-id subpacket"));
            }
            if body.len() != 8 {
                return Err(Error::Malformed("malformed issuer-key-id subpacket"));
            }
                                                                                              
                                                                                      
            f.seen_issuer_keyid = true;
            Ok(())
        }
        _ if critical && hashed => Err(Error::Malformed(
            "unknown critical subpacket in hashed area",
        )),
                                                                                                 
                                          
        _ => Ok(()),
    }
}

/// Exactly-4-octet big-endian time/duration subpacket body.
fn u32_body(body: &[u8]) -> Result<u32, Error> {
    match body {
        [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(Error::Malformed("malformed time subpacket")),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::parse_sig;
    use crate::forge::{creation, mpi_raw, subpacket, subpacket_wide, SigForge};
    use crate::{armor, packet, Error};

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    /// Armor-decode + walk a real `.sign` fixture down to its single tag-2 body.
    fn sign_body(rel: &str) -> Vec<u8> {
        let bin = armor::decode_sign(&fixture(rel)).unwrap();
        let packets = packet::walk(&bin).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].tag, 2);
        packets[0].body.to_vec()
    }

    /// METADATA.toml [greg] pin_fingerprint — the issuer half of the §7.1 consistency anchor.
    const GREG_FPR: [u8; 20] = [
        0x64, 0x7F, 0x28, 0x65, 0x48, 0x94, 0xE3, 0xBD, 0x45, 0x71, 0x99, 0xBE, 0x38, 0xDB, 0xBD,
        0xC8, 0x60, 0x92, 0x69, 0x3E,
    ];

                                                                                                  
    /// METADATA-recorded field values (v4, type 0x00, RSA, SHA-256, created 2024-05-02, issuer
    /// fingerprint == Greg's pin).
    #[test]
    fn real_sign_parses_to_metadata_values() {
        let body = sign_body("real/linux-6.6.30.tar.sign");
        let sig = parse_sig(&body).unwrap();
        assert_eq!(sig.sig_type, 0x00);
        assert_eq!(sig.hash_algo, 8);
        assert_eq!(sig.created, 1714660433);
        assert_eq!(sig.issuer_fpr_diag, Some(GREG_FPR));
        assert!(!sig.hashed_area.is_empty());
        assert!(!sig.s_mpi.is_empty());
                                                                    
        assert_eq!(sig.sig_expiry, None);
        assert_eq!(sig.key_expiry, None);
        assert_eq!(sig.key_flags, None);
        assert_eq!(sig.embedded_sig, None);
    }

    /// A generated SHA-512 detached signature records hash algo 10 (whitelist-fits-reality for the
    /// other admitted hash).
    #[test]
    fn generated_sha512_sign_records_algo_10() {
        let body = sign_body("gen/sig_a_1b_sha512.asc");
        let sig = parse_sig(&body).unwrap();
        assert_eq!(sig.sig_type, 0x00);
        assert_eq!(sig.hash_algo, 10);
    }

    /// The forge baseline round-trips: field capture is exact.
    #[test]
    fn forge_baseline_parses_exactly() {
        let mut f = SigForge::baseline(1_781_000_000);
        f.unhashed = subpacket(16, false, &[0x11; 8]);                                         
        let body = f.body();
        let sig = parse_sig(&body).unwrap();
        assert_eq!(sig.sig_type, 0x00);
        assert_eq!(sig.hash_algo, 8);
        assert_eq!(sig.created, 1_781_000_000);
        assert_eq!(sig.left16, [0xAB, 0xCD]);
        assert_eq!(sig.s_mpi, &[0x5A; 32]);
        assert_eq!(sig.hashed_area, &creation(1_781_000_000)[..]);
    }

    #[test]
    fn non_v4_versions_are_unsupported() {
        for v in [3, 5, 6] {
            let mut f = SigForge::baseline(1);
            f.version = v;
            assert_eq!(
                parse_sig(&f.body()).unwrap_err(),
                Error::Unsupported("non-v4 signature version"),
                "version {v}"
            );
        }
    }

    #[test]
    fn non_rsa_pubkey_algo_is_unsupported() {
                                                                                        
        for algo in [3, 17, 22] {
            let mut f = SigForge::baseline(1);
            f.pubkey_algo = algo;
            assert_eq!(
                parse_sig(&f.body()).unwrap_err(),
                Error::Unsupported("non-RSA public-key algorithm"),
                "algo {algo}"
            );
        }
    }

    /// Unknown subpacket with the critical bit: hashed = Malformed; unhashed = skipped; and
    /// non-critical unknowns are skipped everywhere.
    #[test]
    fn unknown_critical_hashed_only_is_malformed() {
        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(100, true, b"x"));
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("unknown critical subpacket in hashed area")
        );

        let mut f = SigForge::baseline(1);
        f.unhashed = subpacket(100, true, b"x");
        assert!(parse_sig(&f.body()).is_ok(), "critical-unknown UNHASHED");

        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(101, false, b"y"));
        f.unhashed = subpacket(102, false, b"z");
        assert!(parse_sig(&f.body()).is_ok(), "non-critical unknowns");
    }

                                                                                          
    /// straddling declared length — are named Malformed, never skipped or resynced.
    #[test]
    fn hashed_area_trailing_bytes_are_malformed() {
        let mut f = SigForge::baseline(1);
        f.hashed.push(0x00);                                 
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("zero-length subpacket")
        );

        let mut f = SigForge::baseline(1);
        f.hashed.push(0x05);                                                  
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("truncated")
        );
    }

    #[test]
    fn duplicate_creation_is_malformed() {
        let mut f = SigForge::baseline(7);
        f.hashed.extend_from_slice(&creation(7));
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("duplicate creation-time subpacket")
        );
    }

    /// Creation time is REQUIRED in the HASHED area — absent entirely, or present only unhashed
                                                                          
    #[test]
    fn missing_hashed_creation_is_malformed() {
        let mut f = SigForge::baseline(1);
        f.hashed = Vec::new();
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("missing creation-time subpacket")
        );

        let mut f = SigForge::baseline(1);
        f.hashed = Vec::new();
        f.unhashed = creation(1);
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("missing creation-time subpacket")
        );
    }

    /// Policy ids are captured from the hashed area and IGNORED in the unhashed area.
    #[test]
    fn policy_subpackets_are_hashed_only() {
                                         
        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(27, false, &[0x02]));
        assert_eq!(parse_sig(&f.body()).unwrap().key_flags, Some(0x02));

                                                          
        let mut f = SigForge::baseline(1);
        f.unhashed = subpacket(27, false, &[0x02]);
        assert_eq!(parse_sig(&f.body()).unwrap().key_flags, None);

                                                          
        let mut f = SigForge::baseline(1);
        f.hashed
            .extend_from_slice(&subpacket(3, false, &100u32.to_be_bytes()));
        f.hashed
            .extend_from_slice(&subpacket(9, false, &200u32.to_be_bytes()));
        f.unhashed = subpacket(3, false, &999u32.to_be_bytes());
        let sig_body = f.body();
        let sig = parse_sig(&sig_body).unwrap();
        assert_eq!(sig.sig_expiry, Some(100));
        assert_eq!(sig.key_expiry, Some(200));

                                                              
        let mut f = SigForge::baseline(1);
        f.hashed
            .extend_from_slice(&subpacket(9, false, &1u32.to_be_bytes()));
        f.hashed
            .extend_from_slice(&subpacket(9, false, &2u32.to_be_bytes()));
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("duplicate key-expiration subpacket")
        );

                                                                
        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(3, false, &[1, 2, 3]));
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("malformed time subpacket")
        );
    }

    /// Embedded signature (32): accepted from EITHER area (its authority is its own verification,
    /// §6.3); more than one anywhere is Malformed.
    #[test]
    fn embedded_sig_either_area_but_singular() {
        let mut f = SigForge::baseline(1);
        f.unhashed = subpacket(32, false, b"inner-sig-bytes");
        assert_eq!(
            parse_sig(&f.body()).unwrap().embedded_sig,
            Some(&b"inner-sig-bytes"[..])
        );

        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(32, false, b"h"));
        assert_eq!(parse_sig(&f.body()).unwrap().embedded_sig, Some(&b"h"[..]));

        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(32, false, b"h"));
        f.unhashed = subpacket(32, false, b"u");
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("duplicate embedded-signature subpacket")
        );
    }

    /// Issuer subpackets are diagnostics with exact shapes: 33 = 0x04 ‖ 20 fingerprint bytes;
    /// 16 = 8 key-id bytes. Wrong shapes are Malformed (whitelist, not tolerance).
    #[test]
    fn issuer_subpacket_shapes_are_exact() {
        let mut fpr_body = vec![4u8];
        fpr_body.extend_from_slice(&[0x77; 20]);
        let mut f = SigForge::baseline(1);
        f.unhashed = subpacket(33, false, &fpr_body);
        assert_eq!(
            parse_sig(&f.body()).unwrap().issuer_fpr_diag,
            Some([0x77; 20])
        );

        let mut f = SigForge::baseline(1);
        f.hashed.extend_from_slice(&subpacket(33, false, &[4; 5]));
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("malformed issuer-fingerprint subpacket")
        );

        let mut f = SigForge::baseline(1);
        f.unhashed = subpacket(16, false, &[0x11; 7]);
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("malformed issuer-key-id subpacket")
        );
    }

    /// The 5-octet subpacket length form parses (length-form coverage at the subpacket layer).
    #[test]
    fn wide_subpacket_length_form_parses() {
        let mut f = SigForge::baseline(1);
        f.hashed = subpacket_wide(2, false, &9u32.to_be_bytes());
        assert_eq!(parse_sig(&f.body()).unwrap().created, 9);
    }

    /// SUBPACKETS_MAX per area is exact: 256 parses, 257 is Malformed.
    #[test]
    fn subpacket_count_cap_is_exact() {
        let filler = subpacket(100, false, b"");
        let mut f = SigForge::baseline(1);
                                                                                               
        for _ in 0..255 {
            f.hashed.extend_from_slice(&filler);
        }
        assert!(parse_sig(&f.body()).is_ok());
        f.hashed.extend_from_slice(&filler);         
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("too many subpackets")
        );
    }

    /// Strict-canonical MPI: leading zero octet, or a declared bit count whose MSB position does
    /// not match the actual leading octet, is Malformed.
    #[test]
    fn non_minimal_mpi_is_malformed() {
                                                                                 
        let mut f = SigForge::baseline(1);
        f.mpi = mpi_raw(16, &[0x00, 0xFF]);
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("non-canonical MPI")
        );
                                                                                                
        let mut f = SigForge::baseline(1);
        f.mpi = mpi_raw(16, &[0x01, 0x00]);
        assert_eq!(
            parse_sig(&f.body()).unwrap_err(),
            Error::Malformed("non-canonical MPI")
        );
    }

    /// The signature body must end exactly at the MPI — trailing bytes are Malformed.
    #[test]
    fn trailing_bytes_after_mpi_are_malformed() {
        let mut body = SigForge::baseline(1).body();
        body.push(0x00);
        assert_eq!(
            parse_sig(&body).unwrap_err(),
            Error::Malformed("trailing bytes after signature MPI")
        );
    }

    /// Truncated bodies are the reader's named error, never a panic.
    #[test]
    fn truncated_bodies_are_malformed() {
        assert_eq!(parse_sig(b"").unwrap_err(), Error::Malformed("truncated"));
        let body = SigForge::baseline(1).body();
        assert_eq!(
            parse_sig(&body[..body.len() - 1]).unwrap_err(),
            Error::Malformed("truncated")
        );
    }
}
