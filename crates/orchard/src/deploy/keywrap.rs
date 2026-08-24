//! The shared at-rest passphrase-wrap for artifact-signing seeds — the docker
                                                                    
//!
//! Argon2id (host-grade floor) over the operator passphrase → XChaCha20-Poly1305
//! seal of the 32-byte seed, emitted as a self-describing `WrappedBlob`
//! (`version ‖ salt ‖ nonce ‖ kdf-params ‖ ct+tag`). Load-bearing properties:
//!
                                                                             
//!   version byte `!= WRAP_VERSION_V1` — never a `>=` floor (dragonfruit's
//!   `BadVersion` precedent). Anti-rollback for a future v2 = re-wrap every v1
//!   blob before bumping.
                                                                             
//!   params are whitelisted below a DoS cap before ever reaching the KDF — a
//!   hostile blob cannot demand a 2 GiB derivation.
                                                                             
//!   CSPRNG salt+nonce generation — no caller can reproduce a prior pair.
                                                                          
//!   Task 3): `{version, salt, nonce, kdf-params, key-role}` are associated
//!   data; the role is supplied by the caller's intent, never blob-carried.
//!
//! Pure (no I/O, no docker) — extraction-ready
                                                                                
//! The software rung stays the plaintext floor; only the docker rung wraps.
//!
//! **Memory hygiene (verified against pinned `argon2` 0.5.3 /
//! `chacha20poly1305` 0.10.1 / `poly1305` 0.8.0 source — asserted from the crates'
//! own code, not release notes):** the sensitive final material — seed, derived
//! AEAD key, decrypted plaintext — is `Zeroizing`, and the cipher's own key copy is
//! wiped by chacha20poly1305's unconditional `ZeroizeOnDrop`. `derive_key`
//! additionally owns Argon2id's 19-64 MiB memory-hard matrix as a
//! `Zeroizing<Vec<Block>>` and wipes it on every exit path — argon2's own `zeroize`
//! feature wipes ONLY its small finalize/initial-hash temporaries, NEVER that
//! matrix, whose tail re-derives this very key via one public hash at `p=1`. The
//! chacha20poly1305 one-time-MAC `State` (r/h/pad) is ALSO wiped: orchard's
//! Cargo.toml requests poly1305's `zeroize` feature — which chacha20poly1305 0.10.1
//! enables on chacha20 but NOT on poly1305 — so poly1305's `impl Drop for State`
                                                                              
//! inherent residual has NO caller-side fix: argon2's `fill_blocks` keeps a few
//! SHORT-LIVED STACK `Block`s (the per-iteration `result`) that the crate never
//! zeroizes and no public API lets us own. It is NOT key-rederivable at our enforced
//! `t>=2` floor — the final write into each key-contributing block is an XOR, so the
//! stack copy is only an XOR-operand, never the standalone key — and it is a
                                                                               

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand::RngCore;
use zeroize::Zeroizing;

/// The current (and only) wrapped-blob format version. Decode is STRICT
/// equality against this — see the module docs on anti-rollback.
pub const WRAP_VERSION_V1: u8 = 1;

                                                                          
/// t=2, p=1`. Set for the HOST — deliberately NOT anchored to the hardware
/// 1B custody's Pico-SRAM-sized number, which is far below any host floor.
pub const HOST_FLOOR: KdfParams = KdfParams {
    m_kib: 19_456,
    t: 2,
    p: 1,
};

/// The project-target Argon2id params for new wraps: `m=64 MiB, t=3, p=1`.
pub const HOST_TARGET: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

                                                                         
/// generous headroom above [`HOST_TARGET`]-class settings, but bounded so a
/// hostile blob cannot demand a multi-GiB / hour-long derivation.
/// `MAX_M_KIB` = 1 GiB of Argon2 memory; `MAX_T` = 64 passes; `MAX_P` = 16 lanes
/// (mirrors the `MAX_WINDOW_DAYS` whitelist-the-sane-range pattern).
pub const MAX_M_KIB: u32 = 1_048_576;
pub const MAX_T: u32 = 64;
pub const MAX_P: u32 = 16;

/// Salt length bounds accepted at decode: v1 wraps always WRITE 16 bytes
                                                                                
/// below the 128-bit floor.
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;

/// The salt length v1 `wrap_seed` writes (the ≥128-bit spec floor).
const SALT_LEN: usize = 16;

/// The only payload v1 seals: a 32-byte ed25519 seed.
const SEED_LEN: usize = 32;

/// XChaCha20-Poly1305's extended nonce is exactly 24 bytes.
const NONCE_LEN: usize = 24;

/// Ciphertext cap: a v1 blob seals a 32-byte seed + 16-byte Poly1305 tag = 48
/// bytes; the cap leaves format slack while staying DoS-bounded.
const MAX_CT_LEN: usize = 1024;

/// The Argon2id cost parameters carried in (and bounded by) the blob header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iteration count (passes).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

/// Which seed a caller intends to load. Bound into the AAD by the LOAD CONTEXT
                                                                                 
/// context fails at unwrap on the AAD mismatch, not downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Root,
    Worker,
}

impl KeyRole {
    /// The stable AAD token for this role.
    pub fn slug(self) -> &'static str {
        match self {
            KeyRole::Root => "root",
            KeyRole::Worker => "worker",
        }
    }
}

/// The decoded self-describing wrap header + ciphertext. Carries NO secret
/// material: everything here is public at-rest bytes (the seed is inside `ct`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedBlob {
    pub version: u8,
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub kdf: KdfParams,
    /// AEAD ciphertext ‖ 16-byte Poly1305 tag.
    pub ct: Vec<u8>,
}

/// Keywrap failures. Fail-closed: every arm is a refusal — there is no
/// "best-effort" decode. Displays carry NO secret material by construction
/// (paths/params only).
#[derive(Debug, thiserror::Error)]
pub enum WrapError {
    #[error(
        "wrapped-blob version {0} != v{WRAP_VERSION_V1} (STRICT equality — a future v2 \
         re-wraps every v1 blob before bumping; there is no >= floor)"
    )]
    BadVersion(u8),
    #[error(
        "wrapped-blob KDF params out of range: m={m_kib} KiB, t={t}, p={p} \
         (caps: m<={MAX_M_KIB} KiB, t<={MAX_T}, p<={MAX_P} — DoS bound, F-8)"
    )]
    KdfParamsOutOfRange { m_kib: u32, t: u32, p: u32 },
    #[error("wrapped-blob truncated/malformed: {0}")]
    Truncated(&'static str),
    #[error("wrapped-blob carries {0} trailing byte(s) past the encoded length — refused")]
    TrailingBytes(usize),
    #[error(
        "wrapped-blob salt length {0} outside {MIN_SALT_LEN}..={MAX_SALT_LEN} \
         (v1 writes 16; the floor is 128-bit)"
    )]
    SaltLenOutOfRange(usize),
    #[error("wrapped-blob ciphertext length {0} exceeds the {MAX_CT_LEN}-byte cap")]
    CtLenOutOfRange(usize),
    #[error(
        "Argon2id params below the OWASP host floor (m>={floor_m} KiB, t>={floor_t}, \
         p>={floor_p}): got m={m_kib} KiB, t={t}, p={p} — refusing a weakened wrap/blob \
         (F-2/F-16; the floor is host-grade, never the Pico-SRAM number)",
        floor_m = HOST_FLOOR.m_kib,
        floor_t = HOST_FLOOR.t,
        floor_p = HOST_FLOOR.p
    )]
    KdfParamsBelowFloor { m_kib: u32, t: u32, p: u32 },
    #[error("Argon2id derivation refused: {0}")]
    Kdf(String),
    #[error(
        "AEAD open failed — wrong passphrase, a tampered header/ciphertext, or a \
         role-swapped blob (the tag covers the AAD-bound header + load-context role)"
    )]
    Aead,
    #[error("unwrapped payload is {0} bytes, expected the {SEED_LEN}-byte seed")]
    PlaintextLen(usize),
}

                                                                           
/// header, and the LOAD-CONTEXT `role` — which is deliberately a parameter,
/// never a blob field (a blob-carried role would match any swapped blob and
                                                                          
/// variable-length field is length-prefixed (salt by a `u16`, role by a `u8`)
/// and every other field is fixed-width — so injectivity holds regardless of
/// field order and survives appending a field, not merely because `role` is
/// currently terminal.
fn aad(
    version: u8,
    salt: &[u8],
    nonce: &[u8; NONCE_LEN],
    kdf: KdfParams,
    role: KeyRole,
) -> Vec<u8> {
    let mut a = Vec::with_capacity(32 + salt.len() + NONCE_LEN + 12 + 8);
    a.extend_from_slice(b"orchard-keywrap-v1-aad");
    a.push(version);
    a.extend_from_slice(&(salt.len() as u16).to_le_bytes());
    a.extend_from_slice(salt);
    a.extend_from_slice(nonce);
    a.extend_from_slice(&kdf.m_kib.to_le_bytes());
    a.extend_from_slice(&kdf.t.to_le_bytes());
    a.extend_from_slice(&kdf.p.to_le_bytes());
                                                                                  
                                                                                   
                                                                  
    let role_slug = role.slug().as_bytes();
    a.push(role_slug.len() as u8);
    a.extend_from_slice(role_slug);
    a
}

/// Argon2id(passphrase, salt; params) → a 32-byte AEAD key, zeroized on drop.
/// The caller owns the passphrase buffer's lifecycle (the CLI read sites hold
/// it in `Zeroizing` — F-9); this fn never copies it beyond argon2's internals.
///
                                                                             
/// `zeroize` feature wipes only its small finalize/initial-hash temporaries — it
/// does NOT wipe the 19-64 MiB memory-hard matrix, which the convenience
/// `hash_password_into` would drop un-zeroized. Since that matrix's tail
/// re-derives THIS key via one public hash at `p=1`, we own it ourselves as a
/// `Zeroizing<Vec<Block>>` and pass it to `hash_password_into_with_memory`, so it
/// is wiped (incl. spare capacity) on every exit path.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, WrapError> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
        .map_err(|e| WrapError::Kdf(e.to_string()))?;
                                                                            
                                                                             
                                                             
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
                                                                          
                                                                                  
                                                                            
                                                                                     
    let mut matrix = Zeroizing::new(vec![argon2::Block::default(); block_count]);
    argon
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *matrix)
        .map_err(|e| WrapError::Kdf(e.to_string()))?;
    Ok(key)
}

/// The fail-closed Argon2id param floor (F-2/F-16): reject anything below the
/// OWASP host minimum ([`HOST_FLOOR`]). Enforced at BOTH ends — `wrap_seed`
/// (never mint a weak blob) and `unwrap_seed` (never honor one: a blob edited
/// down to trivial params must not quietly become a fast-guessable wrap).
/// Reaches `make verify` through its always-on `cargo test --workspace` leg —
/// the tests are plain `#[test]`s, never `#[ignore]`d.
pub fn enforce_param_floor(p: KdfParams) -> Result<(), WrapError> {
    if p.m_kib < HOST_FLOOR.m_kib || p.t < HOST_FLOOR.t || p.p < HOST_FLOOR.p {
        return Err(WrapError::KdfParamsBelowFloor {
            m_kib: p.m_kib,
            t: p.t,
            p: p.p,
        });
    }
    Ok(())
}

/// Wrap a 32-byte seed under `passphrase` for the load-context `role`,
/// returning the encoded v1 blob. Params are floor-enforced (F-2) AND
/// cap-enforced (symmetric with decode — never mint a blob our own decode
/// would refuse).
///
                                                                          
/// nonce are generated INTERNALLY from the OS CSPRNG on every call — there is
/// no caller-supplied-salt/nonce path, so no call site (rotation and
/// re-delegation included) can reproduce a prior pair; each wrap derives a
/// unique Argon2id key that seals exactly one blob.
pub fn wrap_seed(
    seed: &[u8; SEED_LEN],
    passphrase: &[u8],
    role: KeyRole,
    params: KdfParams,
) -> Result<Vec<u8>, WrapError> {
    enforce_param_floor(params)?;
    if params.m_kib > MAX_M_KIB || params.t > MAX_T || params.p > MAX_P {
        return Err(WrapError::KdfParamsOutOfRange {
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
        });
    }
    wrap_seed_inner(seed, passphrase, role, params)
}

/// The unguarded wrap body. Private on purpose: production enters via
/// [`wrap_seed`]'s floor+cap guards; tests reach this directly to mint
/// below-floor blobs and prove [`unwrap_seed`] refuses them.
fn wrap_seed_inner(
    seed: &[u8; SEED_LEN],
    passphrase: &[u8],
    role: KeyRole,
    params: KdfParams,
) -> Result<Vec<u8>, WrapError> {
    let mut salt = vec![0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: seed,
                aad: &aad(WRAP_VERSION_V1, &salt, &nonce, params, role),
            },
        )
        .map_err(|_| WrapError::Aead)?;

    Ok(encode_blob(&WrappedBlob {
        version: WRAP_VERSION_V1,
        salt,
        nonce,
        kdf: params,
        ct,
    }))
}

/// Unwrap a v1 blob under `passphrase` in the load-context `role`. Strict
/// decode (version equality + param bounds) → Argon2id re-derivation from the
/// blob's salt → AEAD open with the AAD rebuilt from the header + the CONTEXT
/// role. The derived key and the plaintext are `Zeroizing`; any failure is a
/// typed refusal, never a partial seed.
pub fn unwrap_seed(
    blob_bytes: &[u8],
    passphrase: &[u8],
    role: KeyRole,
) -> Result<Zeroizing<[u8; SEED_LEN]>, WrapError> {
    let blob = decode_blob(blob_bytes)?;
                                                                            
                                                                              
                                                  
    enforce_param_floor(blob.kdf)?;
    let key = derive_key(passphrase, &blob.salt, blob.kdf)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                (&blob.nonce).into(),
                Payload {
                    msg: &blob.ct,
                    aad: &aad(blob.version, &blob.salt, &blob.nonce, blob.kdf, role),
                },
            )
            .map_err(|_| WrapError::Aead)?,
    );
    if pt.len() != SEED_LEN {
        return Err(WrapError::PlaintextLen(pt.len()));
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&pt);
    Ok(seed)
}

/// Encode a blob to the v1 wire form (little-endian, length-prefixed):
/// `version:u8 ‖ salt_len:u16 ‖ salt ‖ nonce:24 ‖ m_kib:u32 ‖ t:u32 ‖ p:u32 ‖
/// ct_len:u32 ‖ ct`.
///
/// Deliberately performs NO validation — `decode_blob` is the single guard
/// (tests must be able to construct hostile blobs through this encoder).
pub fn encode_blob(blob: &WrappedBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + blob.salt.len() + NONCE_LEN + 12 + 4 + blob.ct.len());
    out.push(blob.version);
                                                                                  
                                                                                        
                                                                                          
    out.extend_from_slice(&(blob.salt.len() as u16).to_le_bytes());
    out.extend_from_slice(&blob.salt);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.kdf.m_kib.to_le_bytes());
    out.extend_from_slice(&blob.kdf.t.to_le_bytes());
    out.extend_from_slice(&blob.kdf.p.to_le_bytes());
    out.extend_from_slice(&(blob.ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob.ct);
    out
}

/// Bounds-checked little-endian cursor. Every read is explicit `Result` — a
/// short buffer is a typed refusal, never a panic or a silent zero-fill.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], WrapError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(WrapError::Truncated("length overflow"))?;
        if end > self.buf.len() {
            return Err(WrapError::Truncated(what));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, WrapError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, WrapError> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, WrapError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Decode + validate a v1 wrapped blob. Order is load-bearing:
/// 1. **version, STRICT equality** (before touching anything else — F-13);
/// 2. bounds-checked field reads (salt-len / nonce / params / ct-len);
/// 3. **param upper-bounds** (the DoS cap — before any caller feeds them to
///    Argon2id);
/// 4. exact-length consumption (trailing bytes are refused, not ignored).
pub fn decode_blob(bytes: &[u8]) -> Result<WrappedBlob, WrapError> {
    let mut c = Cursor { buf: bytes, pos: 0 };

    let version = c.u8("version byte")?;
    if version != WRAP_VERSION_V1 {
        return Err(WrapError::BadVersion(version));
    }

    let salt_len = c.u16("salt length")? as usize;
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
        return Err(WrapError::SaltLenOutOfRange(salt_len));
    }
    let salt = c.take(salt_len, "salt")?.to_vec();

    let nonce: [u8; NONCE_LEN] = c
        .take(NONCE_LEN, "nonce")?
        .try_into()
        .expect("take(NONCE_LEN) returns exactly NONCE_LEN bytes");

    let kdf = KdfParams {
        m_kib: c.u32("kdf m_kib")?,
        t: c.u32("kdf t")?,
        p: c.u32("kdf p")?,
    };
    if kdf.m_kib > MAX_M_KIB || kdf.t > MAX_T || kdf.p > MAX_P {
        return Err(WrapError::KdfParamsOutOfRange {
            m_kib: kdf.m_kib,
            t: kdf.t,
            p: kdf.p,
        });
    }

    let ct_len = c.u32("ct length")? as usize;
    if ct_len > MAX_CT_LEN {
        return Err(WrapError::CtLenOutOfRange(ct_len));
    }
    let ct = c.take(ct_len, "ciphertext")?.to_vec();

    if c.pos != bytes.len() {
        return Err(WrapError::TrailingBytes(bytes.len() - c.pos));
    }

    Ok(WrappedBlob {
        version,
        salt,
        nonce,
        kdf,
        ct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_blob() -> WrappedBlob {
        WrappedBlob {
            version: WRAP_VERSION_V1,
            salt: vec![0x11; 16],
            nonce: [0x22; 24],
            kdf: KdfParams {
                m_kib: 65536,
                t: 3,
                p: 1,
            },
            ct: vec![0x33; 48],
        }
    }

    /// The version field is byte 0 of the encoding.
    fn set_version_byte(encoded: &mut [u8], v: u8) {
        encoded[0] = v;
    }

    #[test]
    fn decode_rejects_a_wrong_version_byte_strict_equality() {
        let mut b = encode_blob(&sample_blob());                             
                                                   
        set_version_byte(&mut b, 2);
        assert!(matches!(decode_blob(&b), Err(WrapError::BadVersion(2))));
                                                                  
        set_version_byte(&mut b, 9);
        assert!(matches!(decode_blob(&b), Err(WrapError::BadVersion(9))));
                                                      
        set_version_byte(&mut b, 0);
        assert!(matches!(decode_blob(&b), Err(WrapError::BadVersion(0))));
    }

    #[test]
    fn decode_rejects_kdf_params_above_the_cap() {
        let mut blob = sample_blob();
        blob.kdf.m_kib = 2_000_000;                                                
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::KdfParamsOutOfRange { .. })
        ));
                                   
        let mut blob = sample_blob();
        blob.kdf.t = 10_000;
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::KdfParamsOutOfRange { .. })
        ));
        let mut blob = sample_blob();
        blob.kdf.p = 1_000;
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::KdfParamsOutOfRange { .. })
        ));
                                                                    
        let mut blob = sample_blob();
        blob.kdf = KdfParams {
            m_kib: MAX_M_KIB,
            t: MAX_T,
            p: MAX_P,
        };
        assert!(decode_blob(&encode_blob(&blob)).is_ok());
    }

    #[test]
    fn decode_rejects_truncated_and_foreign_blobs() {
        let b = encode_blob(&sample_blob());
        assert!(decode_blob(&b[..b.len() - 5]).is_err());             
        assert!(decode_blob(b"not a wrapped blob at all").is_err());           
        assert!(decode_blob(&[]).is_err());         
                                                                         
                                                     
        assert!(decode_blob(&[7u8; 32]).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut b = encode_blob(&sample_blob());
        b.push(0x00);
        assert!(matches!(decode_blob(&b), Err(WrapError::TrailingBytes(1))));
    }

    #[test]
    fn decode_rejects_out_of_range_salt_len() {
                                  
        let mut blob = sample_blob();
        blob.salt = vec![0x11; 8];
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::SaltLenOutOfRange(8))
        ));
                              
        let mut blob = sample_blob();
        blob.salt = vec![0x11; 65];
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::SaltLenOutOfRange(65))
        ));
    }

    #[test]
    fn decode_rejects_oversized_ct() {
        let mut blob = sample_blob();
        blob.ct = vec![0x33; MAX_CT_LEN + 1];
        assert!(matches!(
            decode_blob(&encode_blob(&blob)),
            Err(WrapError::CtLenOutOfRange(_))
        ));
    }

    #[test]
    fn encode_decode_round_trips_the_header() {
        let blob = sample_blob();
        let got = decode_blob(&encode_blob(&blob)).unwrap();
        assert_eq!(got.version, blob.version);
        assert_eq!(got.salt, blob.salt);
        assert_eq!(got.nonce, blob.nonce);
        assert_eq!(got.kdf, blob.kdf);
        assert_eq!(got.ct, blob.ct);
    }

                                          
      
                                                                              
                                                                                 
                                                                            
                                                    
    const TEST_PARAMS: KdfParams = HOST_FLOOR;

    /// Flip one SALT byte inside an ENCODED blob (salt starts at offset 3:
    /// version u8 ‖ salt_len u16).
    fn flip_a_salt_byte(encoded: &mut [u8]) {
        encoded[3] ^= 0x01;
    }

    #[test]
    fn wrap_unwrap_round_trips_the_seed() {
        let seed = [7u8; 32];
        let blob = wrap_seed(&seed, b"correct horse", KeyRole::Worker, TEST_PARAMS).unwrap();
        let got = unwrap_seed(&blob, b"correct horse", KeyRole::Worker).unwrap();
        assert_eq!(&*got, &seed);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let blob = wrap_seed(&[7u8; 32], b"right", KeyRole::Worker, TEST_PARAMS).unwrap();
        assert!(matches!(
            unwrap_seed(&blob, b"wrong", KeyRole::Worker),
            Err(WrapError::Aead)
        ));
    }

    #[test]
    fn salt_tampering_fails_closed_kdf_and_aad() {
        let mut blob = wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, TEST_PARAMS).unwrap();
                                                                                   
                                                                                       
                                                                                     
                                                                                
                                                                                  
        flip_a_salt_byte(&mut blob);
        assert!(matches!(
            unwrap_seed(&blob, b"pw", KeyRole::Worker),
            Err(WrapError::Aead)
        ));
    }

    #[test]
    fn role_swap_fails_at_unwrap_not_downstream() {
                                                                                    
                                                                                       
                                                                                 
                                                                        
                                                                               
                                                                       
        let blob = wrap_seed(&[7u8; 32], b"pw", KeyRole::Root, TEST_PARAMS).unwrap();
        assert!(matches!(
            unwrap_seed(&blob, b"pw", KeyRole::Worker),
            Err(WrapError::Aead)
        ));
                          
        let blob = wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, TEST_PARAMS).unwrap();
        assert!(matches!(
            unwrap_seed(&blob, b"pw", KeyRole::Root),
            Err(WrapError::Aead)
        ));
    }

    #[test]
    fn two_wraps_of_same_seed_and_passphrase_differ_in_salt_nonce_ct() {
        let a = decode_blob(&wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, TEST_PARAMS).unwrap())
            .unwrap();
        let b = decode_blob(&wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, TEST_PARAMS).unwrap())
            .unwrap();
        assert_ne!(a.salt, b.salt, "internal per-call salt");
        assert_ne!(a.nonce, b.nonce, "internal per-call nonce");
        assert_ne!(a.ct, b.ct, "different derived key ⇒ different ciphertext");
    }

    #[test]
    fn wrapped_blob_never_contains_the_plaintext_seed() {
        let seed = [0xABu8; 32];
        let blob = wrap_seed(&seed, b"pw", KeyRole::Worker, TEST_PARAMS).unwrap();
        assert!(
            !blob.windows(32).any(|w| w == seed),
            "plaintext seed leaked into the blob"
        );
    }

                                                           

    /// The expected Argon2id-v0x13 derivation for
    /// (passphrase=b"password", salt=b"keywrapKATsalt00", m=19456 KiB, t=2, p=1,
    /// 32-byte output). CROSS-IMPLEMENTATION provenance: minted 2026-07-10 with
    /// the libargon2 reference CLI (an independent C implementation):
    ///   echo -n "password" | argon2 "keywrapKATsalt00" -id -t 2 -k 19456 -p 1 -l 32 -r
    /// RustCrypto `argon2` reproducing it guards against a silent KDF change
    /// (algorithm, version, param interpretation, or endianness drift).
    const EXPECTED_ARGON2ID_KEY_HEX: &str =
        "d3c75fae200d8db490c088237df0576ab6a800979ab0584678cdb816209fc138";

    #[test]
    fn argon2id_kat_matches_the_libargon2_reference_vector() {
        let key = derive_key(b"password", b"keywrapKATsalt00", HOST_FLOOR).unwrap();
        assert_eq!(hex::encode(key.as_ref()), EXPECTED_ARGON2ID_KEY_HEX);
    }

    #[test]
    fn param_floor_rejects_below_owasp_minimum() {
                         
        assert!(matches!(
            enforce_param_floor(KdfParams {
                m_kib: 8192,
                t: 2,
                p: 1
            }),
            Err(WrapError::KdfParamsBelowFloor { .. })
        ));
                    
        assert!(matches!(
            enforce_param_floor(KdfParams {
                m_kib: 65536,
                t: 1,
                p: 1
            }),
            Err(WrapError::KdfParamsBelowFloor { .. })
        ));
                    
        assert!(matches!(
            enforce_param_floor(KdfParams {
                m_kib: 65536,
                t: 3,
                p: 0
            }),
            Err(WrapError::KdfParamsBelowFloor { .. })
        ));
                                                     
        assert!(enforce_param_floor(HOST_FLOOR).is_ok());
        assert!(enforce_param_floor(HOST_TARGET).is_ok());
    }

    #[test]
    fn wrap_seed_refuses_below_floor_and_above_cap_params() {
        let below = KdfParams {
            m_kib: 8192,
            t: 2,
            p: 1,
        };
        assert!(matches!(
            wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, below),
            Err(WrapError::KdfParamsBelowFloor { .. })
        ));
        let above = KdfParams {
            m_kib: MAX_M_KIB + 1,
            t: 3,
            p: 1,
        };
        assert!(matches!(
            wrap_seed(&[7u8; 32], b"pw", KeyRole::Worker, above),
            Err(WrapError::KdfParamsOutOfRange { .. })
        ));
    }

    #[test]
    fn unwrap_enforces_the_floor_on_the_blob_params() {
                                                                                 
                                                                               
                                                                             
        let below = KdfParams {
            m_kib: 8192,
            t: 2,
            p: 1,
        };
        let blob = wrap_seed_inner(&[7u8; 32], b"pw", KeyRole::Worker, below).unwrap();
        assert!(matches!(
            unwrap_seed(&blob, b"pw", KeyRole::Worker),
            Err(WrapError::KdfParamsBelowFloor { .. })
        ));
    }
}
