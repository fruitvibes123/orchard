//! Test-only OpenPGP packet FORGE: pure byte construction, no cashew imports, no cryptography.
//!
//! Builds structurally VALID packets that tests then mutate field-by-field, so every negative
                                                                                                  
//! tests (through `cashew::forge` declared in lib.rs) and directly by integration tests — keep it
//! dependency-free.
//!
//! This is deliberately a SECOND implementation of the byte formats (a writer), independent of the
//! parser under test — a shared encoder would let one bug cancel its mirror image.

#![allow(
    dead_code,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

/// Encode one subpacket in the 1-octet length form (`len < 192`): length ‖ type-octet ‖ body,
/// where the length covers type + body.
pub fn subpacket(id: u8, critical: bool, body: &[u8]) -> Vec<u8> {
    let len = body.len() + 1;
    assert!(len < 192, "1-octet subpacket form only");
    let mut v = vec![len as u8, id | if critical { 0x80 } else { 0 }];
    v.extend_from_slice(body);
    v
}

/// The same subpacket forced into the 5-octet length form (0xFF ‖ be32(len)).
pub fn subpacket_wide(id: u8, critical: bool, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF];
    v.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
    v.push(id | if critical { 0x80 } else { 0 });
    v.extend_from_slice(body);
    v
}

/// A hashed-area creation-time subpacket (id 2, u32 seconds).
pub fn creation(t: u32) -> Vec<u8> {
    subpacket(2, false, &t.to_be_bytes())
}

/// Canonical MPI encoding of `payload`: leading zero octets stripped, bit count derived from the
/// actual MSB (the §5.3 strict form).
pub fn mpi(payload: &[u8]) -> Vec<u8> {
    let start = payload
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(payload.len());
    let p = &payload[start..];
    let bits = if p.is_empty() {
        0
    } else {
        p.len() * 8 - p[0].leading_zeros() as usize
    };
    let mut v = (bits as u16).to_be_bytes().to_vec();
    v.extend_from_slice(p);
    v
}

/// A VERBATIM (possibly non-canonical) MPI: the declared bit count and payload are emitted as
/// given — the non-minimal-encoding forgery hook.
pub fn mpi_raw(bits: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = bits.to_be_bytes().to_vec();
    v.extend_from_slice(payload);
    v
}

/// Frame a packet body as ONE new-format packet with the smallest sufficient length form.
pub fn frame_new_format(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0 | tag];
    let n = body.len();
    if n < 192 {
        v.push(n as u8);
    } else if n <= 8383 {
        let x = n - 192;
        v.push((x >> 8) as u8 + 192);
        v.push((x & 0xFF) as u8);
    } else {
        v.push(255);
        v.extend_from_slice(&(n as u32).to_be_bytes());
    }
    v.extend_from_slice(body);
    v
}

/// A v4 RSA signature packet, field-by-field overridable. `hashed`/`unhashed` are RAW subpacket
/// areas (concatenated subpackets); `mpi` is the full encoded MPI (bit count ‖ payload).
pub struct SigForge {
    pub version: u8,
    pub sig_type: u8,
    pub pubkey_algo: u8,
    pub hash_algo: u8,
    pub hashed: Vec<u8>,
    pub unhashed: Vec<u8>,
    pub left16: [u8; 2],
    pub mpi: Vec<u8>,
}

impl SigForge {
    /// Structurally valid baseline: v4, binary-document type, RSA, SHA-256, one hashed
    /// creation-time subpacket, an arbitrary canonical MPI.
    pub fn baseline(created: u32) -> Self {
        SigForge {
            version: 4,
            sig_type: 0x00,
            pubkey_algo: 1,
            hash_algo: 8,
            hashed: creation(created),
            unhashed: Vec::new(),
            left16: [0xAB, 0xCD],
            mpi: mpi(&[0x5A; 32]),
        }
    }

    /// Assemble the signature packet BODY (the `parse_sig` input).
    pub fn body(&self) -> Vec<u8> {
        let mut v = vec![
            self.version,
            self.sig_type,
            self.pubkey_algo,
            self.hash_algo,
        ];
        v.extend_from_slice(&(self.hashed.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.hashed);
        v.extend_from_slice(&(self.unhashed.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.unhashed);
        v.extend_from_slice(&self.left16);
        v.extend_from_slice(&self.mpi);
        v
    }

    /// The body framed as a new-format tag-2 packet.
    pub fn packet(&self) -> Vec<u8> {
        frame_new_format(2, &self.body())
    }
}

/// A v4 RSA public-key packet (tag 6 primary / tag 14 subkey), field-by-field overridable.
/// `n`/`e` are full encoded MPIs.
pub struct KeyForge {
    pub version: u8,
    pub created: u32,
    pub algo: u8,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl KeyForge {
    /// Structurally valid baseline: v4, RSA, a fake 2048-bit modulus (0xC3 fill — MSB set, so the
    /// canonical bit count is exactly 2048), e = 65537.
    pub fn baseline(created: u32) -> Self {
        KeyForge {
            version: 4,
            created,
            algo: 1,
            n: mpi(&[0xC3; 256]),
            e: mpi(&[0x01, 0x00, 0x01]),
        }
    }

    /// Assemble the key packet BODY (the `parse_key_body` input).
    pub fn body(&self) -> Vec<u8> {
        let mut v = vec![self.version];
        v.extend_from_slice(&self.created.to_be_bytes());
        v.push(self.algo);
        v.extend_from_slice(&self.n);
        v.extend_from_slice(&self.e);
        v
    }

    /// The body framed as tag 6 (primary) or tag 14 (subkey).
    pub fn packet(&self, tag: u8) -> Vec<u8> {
        frame_new_format(tag, &self.body())
    }
}

/// A UID packet (tag 13) around arbitrary text bytes.
pub fn uid_packet(text: &[u8]) -> Vec<u8> {
    frame_new_format(13, text)
}

/// A minimal parse-valid signature packet of the given type (crypto-invalid — grammar tests only).
pub fn sig_packet_of_type(sig_type: u8, created: u32) -> Vec<u8> {
    let mut f = SigForge::baseline(created);
    f.sig_type = sig_type;
    f.packet()
}

/// Hand-rolled base64 (STANDARD alphabet, padded, 64-char lines) — an INDEPENDENT encoder for
/// armoring forged packets in tests; never shares code with the decoder under test.
pub fn base64_lines(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, &x) in idx.iter().enumerate() {
            if i <= chunk.len() {
                raw.push(ALPHABET[x as usize] as char);
            } else {
                raw.push('=');
            }
        }
    }
    raw.as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrap binary packet bytes as ONE armored block of the given type (no CRC line — optional by
/// the §5.1 grammar).
pub fn armor_block(block_type: &str, payload: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN PGP {block_type}-----\n\n{}\n-----END PGP {block_type}-----\n",
        base64_lines(payload)
    )
    .into_bytes()
}
