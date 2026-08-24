                                                                                     
//!
//! Both RFC 4880 header formats are accepted: old-format (1/2/4-octet lengths) and new-format
//! (1/2/5-octet lengths). Deliberately rejected as `Unsupported`: old-format indeterminate length
//! (length type 0b11) and new-format partial body lengths (first length octet 224..=254) — both are
//! streaming-legacy forms never emitted for keys or signatures. Declared lengths are bounds-checked
//! through `reader.rs`; a body over `PACKET_BODY_MAX` or a stream over `PACKETS_MAX` packets is
//! `Malformed`. Framing carries NO semantics — tag meaning and position are the grammar layers' job
//! (`sig.rs` / `key.rs`).

use crate::limits::{PACKETS_MAX, PACKET_BODY_MAX};
use crate::reader::Reader;
use crate::Error;

/// One framed packet: its tag and raw body bytes (a zero-copy subslice of the input).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RawPacket<'a> {
    pub tag: u8,
    pub body: &'a [u8],
}

/// Walk a complete binary packet stream into its framed packets. The whole input must be consumed
/// by whole packets; zero-length input is malformed (a decoded armor body is never legitimately
/// empty).
pub(crate) fn walk(bytes: &[u8]) -> Result<Vec<RawPacket<'_>>, Error> {
    if bytes.is_empty() {
        return Err(Error::Malformed("empty packet stream"));
    }
    let mut r = Reader::new(bytes);
    let mut packets: Vec<RawPacket<'_>> = Vec::new();
    while !r.is_empty() {
        if packets.len() >= PACKETS_MAX {
            return Err(Error::Malformed("too many packets"));
        }
        let header = r.u8()?;
        if header & 0x80 == 0 {
            return Err(Error::Malformed("invalid packet header octet"));
        }
        let (tag, declared_len) = if header & 0x40 == 0 {
                                                                      
            let tag = (header >> 2) & 0x0F;
            let len = match header & 0x03 {
                0 => u32::from(r.u8()?),
                1 => u32::from(r.u16_be()?),
                2 => r.u32_be()?,
                                                                                           
                _ => return Err(Error::Unsupported("old-format indeterminate packet length")),
            };
            (tag, len)
        } else {
                                                                                     
            let tag = header & 0x3F;
            let b0 = r.u8()?;
            let len = match b0 {
                0..=191 => u32::from(b0),
                192..=223 => {
                                                                                                    
                                                                                    
                    let b1 = r.u8()?;
                    u32::from(u16::from_be_bytes([b0.wrapping_sub(192), b1]).wrapping_add(192))
                }
                224..=254 => return Err(Error::Unsupported("new-format partial body length")),
                255 => r.u32_be()?,
            };
            (tag, len)
        };
                                                                                                
                                                       
        let len = usize::try_from(declared_len)
            .map_err(|_| Error::Malformed("packet body exceeds size cap"))?;
        if len > PACKET_BODY_MAX {
            return Err(Error::Malformed("packet body exceeds size cap"));
        }
        let body = r.take(len)?;
        packets.push(RawPacket { tag, body });
    }
    Ok(packets)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{walk, RawPacket};
    use crate::armor;
    use crate::limits::PACKETS_MAX;
    use crate::Error;

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    fn tags(packets: &[RawPacket<'_>]) -> Vec<u8> {
        packets.iter().map(|p| p.tag).collect()
    }

    /// The real `.sign` is exactly ONE old-format tag-2 packet (first byte 0x89 = old-format,
    /// tag 2, 2-octet length): 3 header bytes + 563 body bytes == the 566-byte armor-decoded
    /// ground truth.
    #[test]
    fn real_sign_walks_to_exactly_one_tag2_packet() {
        let bin = armor::decode_sign(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
        let packets = walk(&bin).unwrap();
        assert_eq!(tags(&packets), vec![2]);
        assert_eq!(packets[0].body.len(), 563);
    }

    /// The real pruned keyrings walk to the exact tag sequences recorded in METADATA.toml —
    /// Public-Key, then per-UID [UID, self-cert] pairs: the §5.4 grammar's raw material.
    #[test]
    fn real_keyrings_walk_to_expected_tag_sequences() {
        let greg = armor::decode_keyring(&fixture("real/greg-pruned.asc")).unwrap();
        assert_eq!(tags(&walk(&greg[0]).unwrap()), vec![6, 13, 2, 13, 2, 13, 2]);
        let sasha = armor::decode_keyring(&fixture("real/sasha-pruned.asc")).unwrap();
        assert_eq!(tags(&walk(&sasha[0]).unwrap()), vec![6, 13, 2]);
    }

    /// Every old-format length form (1-, 2-, 4-octet) frames the same body identically.
    #[test]
    fn old_format_length_forms() {
                                                                            
        let one: &[u8] = &[0x88, 3, b'a', b'b', b'c'];
        let two: &[u8] = &[0x89, 0, 3, b'a', b'b', b'c'];
        let four: &[u8] = &[0x8A, 0, 0, 0, 3, b'a', b'b', b'c'];
        for input in [one, two, four] {
            let packets = walk(input).unwrap();
            assert_eq!(tags(&packets), vec![2]);
            assert_eq!(packets[0].body, b"abc");
        }
    }

    /// New-format 1-octet (< 192), 2-octet (both ends of 192..=8383), and 5-octet length forms —
    /// the 2-octet arithmetic pinned at its boundaries.
    #[test]
    fn new_format_length_forms() {
                                   
        let mut one = vec![0xC2, 3];
        one.extend_from_slice(b"abc");
        assert_eq!(walk(&one).unwrap()[0].body, b"abc");

                                                                   
        let mut two_lo = vec![0xC2, 192, 0];
        two_lo.extend_from_slice(&[0xAB; 192]);
        assert_eq!(walk(&two_lo).unwrap()[0].body.len(), 192);

                                                                      
        let mut two_hi = vec![0xC2, 223, 255];
        two_hi.extend_from_slice(&[0xCD; 8383]);
        assert_eq!(walk(&two_hi).unwrap()[0].body.len(), 8383);

                                        
        let mut five = vec![0xC2, 255, 0, 0, 1, 44];
        five.extend_from_slice(&[0xEF; 300]);
        assert_eq!(walk(&five).unwrap()[0].body.len(), 300);
    }

    /// New-format tag extraction (tag = header & 0x3F) and a multi-packet stream mixing header
    /// formats — framing is decided per packet, not per stream.
    #[test]
    fn mixed_format_multi_packet_stream() {
        let input = [
            &[0xC6, 1, 0xAA][..],                    
            &[0x88, 1, 0xBB][..],                    
            &[0xCD, 0][..],                                             
            &[0xCE, 2, 1, 2][..],                     
        ]
        .concat();
        let packets = walk(&input).unwrap();
        assert_eq!(tags(&packets), vec![6, 2, 13, 14]);
        assert_eq!(packets[2].body, b"");
    }

                                                                            

    #[test]
    fn old_format_indeterminate_length_is_unsupported() {
                                                                     
        assert_eq!(
            walk(&[0x8B, 0xAA]),
            Err(Error::Unsupported("old-format indeterminate packet length"))
        );
    }

    #[test]
    fn new_format_partial_body_length_is_unsupported() {
                                                                                      
        assert_eq!(
            walk(&[0xC2, 224, 0xAA]),
            Err(Error::Unsupported("new-format partial body length"))
        );
        assert_eq!(
            walk(&[0xC2, 254]),
            Err(Error::Unsupported("new-format partial body length"))
        );
    }

    /// The body cap fires on the DECLARED length, before any body read — for both 4-byte length
    /// forms, including lengths that would also run past the input.
    #[test]
    fn over_cap_declared_body_is_malformed() {
                                                                         
        assert_eq!(
            walk(&[0xC2, 255, 0x00, 0x01, 0x00, 0x01]),
            Err(Error::Malformed("packet body exceeds size cap"))
        );
                                                                               
        assert_eq!(
            walk(&[0x8A, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(Error::Malformed("packet body exceeds size cap"))
        );
    }

    /// PACKETS_MAX is exact: at-cap parses, one more is malformed.
    #[test]
    fn packet_count_cap_is_exact() {
                                                                                
        let at_cap: Vec<u8> = [0xCD, 0].repeat(PACKETS_MAX);
        assert_eq!(walk(&at_cap).unwrap().len(), PACKETS_MAX);
        let over_cap: Vec<u8> = [0xCD, 0].repeat(PACKETS_MAX + 1);
        assert_eq!(walk(&over_cap), Err(Error::Malformed("too many packets")));
    }

    /// Declared lengths beyond the remaining input — and length octets themselves cut off — are
    /// the reader's named truncation error.
    #[test]
    fn declared_length_beyond_input_is_malformed() {
        assert_eq!(
            walk(&[0xC2, 16, b'a', b'b', b'c']),
            Err(Error::Malformed("truncated"))
        );
        assert_eq!(walk(&[0xC2]), Err(Error::Malformed("truncated")));
        assert_eq!(walk(&[0xC2, 255, 0, 0]), Err(Error::Malformed("truncated")));
        assert_eq!(walk(&[0x89, 0]), Err(Error::Malformed("truncated")));
    }

    #[test]
    fn zero_length_input_is_malformed() {
        assert_eq!(walk(b""), Err(Error::Malformed("empty packet stream")));
    }

    /// An octet without bit 7 set is not a packet header — rejected at the stream start AND
    /// between packets (no resync, no skip).
    #[test]
    fn non_header_octet_is_malformed() {
        assert_eq!(
            walk(&[0x00]),
            Err(Error::Malformed("invalid packet header octet"))
        );
        assert_eq!(
            walk(&[0x7F, 0xAA]),
            Err(Error::Malformed("invalid packet header octet"))
        );
        let mut stream = vec![0xC2, 1, 0xAA];                       
        stream.push(0x41);                              
        assert_eq!(
            walk(&stream),
            Err(Error::Malformed("invalid packet header octet"))
        );
    }

    /// Framing-truncation sweep over the real binaries: EVERY strict prefix either errors or
    /// yields strictly fewer packets — never panics, never fabricates a full walk.
    #[test]
    fn truncation_sweep_over_real_binaries_never_panics() {
        let sign = armor::decode_sign(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
        let greg = armor::decode_keyring(&fixture("real/greg-pruned.asc"))
            .unwrap()
            .remove(0);
        for bin in [sign, greg] {
            let full = walk(&bin).unwrap().len();
            for i in 0..bin.len() {
                match walk(&bin[..i]) {
                    Err(_) => {}
                    Ok(packets) => assert!(
                        packets.len() < full,
                        "prefix {i} fabricated a full {full}-packet walk"
                    ),
                }
            }
        }
    }
}
