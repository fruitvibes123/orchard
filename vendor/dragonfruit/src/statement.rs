                                                                   
//! No variable-length fields, no alloc — the device's one parse surface.
//!
//! Type separation (delegation vs attestation) is enforced by the FIXED LENGTH
//! first (59 vs 67), then the type tag: `from_canonical` checks `len` before the
//! tag, so a cross-type blob rejects with `WrongLength`. The tag is the
//! belt-and-suspenders discriminator for any future same-length type — do NOT
//! weaken or reorder the length check assuming the tag alone separates types
               
//!
//! `no_std` reuse (C3 firmware): the parse/serialize logic here is alloc-free and
                                                                                
//! closed) — `StatementError`'s derive is `thiserror`-2 (no_std, `core::error::Error`),
//! so the C3 RP2350 firmware reuses THIS exact parser, not a copy. `make verify`
//! builds the crate for `thumbv8m.main-none-eabihf` (where that target is
//! installed) to catch a std dep creeping back, and runs the trimmed-config golden
//! KAT (the `dragonfruit-nostd-gate` crate) to catch a behaviour divergence.

use crate::{TAG_ATTESTATION, TAG_DELEGATION, VERSION_V1};
use thiserror::Error;

/// Errors from parsing/validating a canonical statement.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StatementError {
    #[error("wrong length: expected {expected}, got {got}")]
    WrongLength { expected: usize, got: usize },
    #[error("bad type tag: 0x{0:02x}")]
    BadTag(u8),
    #[error("unsupported version: {0}")]
    BadVersion(u8),
    #[error("unknown purpose enum value: {0}")]
    UnknownPurpose(u8),
}

                                                                              
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Img = 0,
    KexecVmlinuz = 1,
    KexecInitramfs = 2,
    Backup = 3,
                                                                                   
    UpdateImage = 4,
                                                                                        
    RootHash = 5,
    /// Model-weights manifest — the hotswappable-model data volume (additive,
                                                                              
    /// for a Backup/UpdateImage/RootHash artifact or vice-versa).
    Weights = 6,
}

impl Purpose {
    pub(crate) fn to_u8(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_u8(b: u8) -> Result<Self, StatementError> {
        match b {
            0 => Ok(Purpose::Img),
            1 => Ok(Purpose::KexecVmlinuz),
            2 => Ok(Purpose::KexecInitramfs),
            3 => Ok(Purpose::Backup),
            4 => Ok(Purpose::UpdateImage),
            5 => Ok(Purpose::RootHash),
            6 => Ok(Purpose::Weights),
            other => Err(StatementError::UnknownPurpose(other)),
        }
    }
}

                                                                             
/// Layout: `tag(1) ‖ version(1) ‖ worker_pubkey[32] ‖ purpose(1) ‖
/// not_before(u64 BE) ‖ not_after(u64 BE) ‖ monotonic_ctr(u64 BE)` = 59 bytes.
pub const DELEGATION_LEN: usize = 1 + 1 + 32 + 1 + 8 + 8 + 8;      

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    pub worker_pubkey: [u8; 32],
    pub purpose: Purpose,
    pub not_before: u64,
    pub not_after: u64,
    pub monotonic_ctr: u64,
}

impl Delegation {
    /// Serialize to the canonical fixed-width bytes (the signed message).
    pub fn to_canonical(&self) -> [u8; DELEGATION_LEN] {
        let mut out = [0u8; DELEGATION_LEN];
        out[0] = TAG_DELEGATION;
        out[1] = VERSION_V1;
        out[2..34].copy_from_slice(&self.worker_pubkey);
        out[34] = self.purpose.to_u8();
        out[35..43].copy_from_slice(&self.not_before.to_be_bytes());
        out[43..51].copy_from_slice(&self.not_after.to_be_bytes());
        out[51..59].copy_from_slice(&self.monotonic_ctr.to_be_bytes());
        out
    }

    /// Parse + validate the fixed fields (reject unknown enum / wrong length /
    /// bad tag / bad version). No alloc, constant-offset slicing only.
    pub fn from_canonical(b: &[u8]) -> Result<Self, StatementError> {
        if b.len() != DELEGATION_LEN {
            return Err(StatementError::WrongLength {
                expected: DELEGATION_LEN,
                got: b.len(),
            });
        }
        if b[0] != TAG_DELEGATION {
            return Err(StatementError::BadTag(b[0]));
        }
        if b[1] != VERSION_V1 {
            return Err(StatementError::BadVersion(b[1]));
        }
        let mut worker_pubkey = [0u8; 32];
        worker_pubkey.copy_from_slice(&b[2..34]);
        let purpose = Purpose::from_u8(b[34])?;
        Ok(Delegation {
            worker_pubkey,
            purpose,
            not_before: be_u64(&b[35..43]),
            not_after: be_u64(&b[43..51]),
            monotonic_ctr: be_u64(&b[51..59]),
        })
    }
}

/// Read a big-endian u64 from an 8-byte slice. Caller guarantees `s.len() == 8`
/// (constant offsets after a verified total length); copy_from_slice keeps this
/// panic-free without `unwrap`.
fn be_u64(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(s);
    u64::from_be_bytes(buf)
}

                                                                                        
/// Layout: `tag(1) ‖ version(1) ‖ artifact_hash[32] ‖ purpose(1) ‖ delegation_id[32]` = 67 bytes.
pub const ATTESTATION_LEN: usize = 1 + 1 + 32 + 1 + 32;      

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub artifact_hash: [u8; 32],
    pub purpose: Purpose,
    /// SHA-256 of the canonical delegation authorizing this worker (binds the chain).
    pub delegation_id: [u8; 32],
}

impl Attestation {
    pub fn to_canonical(&self) -> [u8; ATTESTATION_LEN] {
        let mut out = [0u8; ATTESTATION_LEN];
        out[0] = TAG_ATTESTATION;
        out[1] = VERSION_V1;
        out[2..34].copy_from_slice(&self.artifact_hash);
        out[34] = self.purpose.to_u8();
        out[35..67].copy_from_slice(&self.delegation_id);
        out
    }

    pub fn from_canonical(b: &[u8]) -> Result<Self, StatementError> {
        if b.len() != ATTESTATION_LEN {
            return Err(StatementError::WrongLength {
                expected: ATTESTATION_LEN,
                got: b.len(),
            });
        }
        if b[0] != TAG_ATTESTATION {
            return Err(StatementError::BadTag(b[0]));
        }
        if b[1] != VERSION_V1 {
            return Err(StatementError::BadVersion(b[1]));
        }
        let mut artifact_hash = [0u8; 32];
        artifact_hash.copy_from_slice(&b[2..34]);
        let purpose = Purpose::from_u8(b[34])?;
        let mut delegation_id = [0u8; 32];
        delegation_id.copy_from_slice(&b[35..67]);
        Ok(Attestation {
            artifact_hash,
            purpose,
            delegation_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_roundtrips_all_variants() {
        for (b, p) in [
            (0u8, Purpose::Img),
            (1, Purpose::KexecVmlinuz),
            (2, Purpose::KexecInitramfs),
            (3, Purpose::Backup),
            (4, Purpose::UpdateImage),
            (5, Purpose::RootHash),
            (6, Purpose::Weights),
        ] {
            assert_eq!(p.to_u8(), b);
            assert_eq!(Purpose::from_u8(b), Ok(p));
        }
    }

    #[test]
    fn purpose_rejects_unknown() {
                                                                                
                                                                                  
        assert_eq!(Purpose::from_u8(7), Err(StatementError::UnknownPurpose(7)));
        assert_eq!(
            Purpose::from_u8(255),
            Err(StatementError::UnknownPurpose(255))
        );
    }

    fn sample_delegation() -> Delegation {
        Delegation {
            worker_pubkey: [0xAB; 32],
            purpose: Purpose::Img,
            not_before: 1_000,
            not_after: 2_000,
            monotonic_ctr: 7,
        }
    }

    #[test]
    fn delegation_roundtrip_and_length() {
        let d = sample_delegation();
        let bytes = d.to_canonical();
        assert_eq!(bytes.len(), DELEGATION_LEN);
        assert_eq!(bytes.len(), 59);
        assert_eq!(bytes[0], crate::TAG_DELEGATION);
        assert_eq!(bytes[1], crate::VERSION_V1);
        assert_eq!(Delegation::from_canonical(&bytes), Ok(d));
    }

    #[test]
    fn delegation_rejects_malformed() {
        let mut bytes = sample_delegation().to_canonical();
                       
        assert_eq!(
            Delegation::from_canonical(&bytes[..58]),
            Err(StatementError::WrongLength {
                expected: 59,
                got: 58
            })
        );
                  
        let mut bad_tag = bytes;
        bad_tag[0] = 0xFF;
        assert_eq!(
            Delegation::from_canonical(&bad_tag),
            Err(StatementError::BadTag(0xFF))
        );
                      
        bytes[1] = 0x02;
        assert_eq!(
            Delegation::from_canonical(&bytes),
            Err(StatementError::BadVersion(0x02))
        );
                                      
        let mut bad_purpose = sample_delegation().to_canonical();
        bad_purpose[34] = 9;
        assert_eq!(
            Delegation::from_canonical(&bad_purpose),
            Err(StatementError::UnknownPurpose(9))
        );
    }

    fn sample_attestation() -> Attestation {
        Attestation {
            artifact_hash: [0x11; 32],
            purpose: Purpose::Backup,
            delegation_id: [0x22; 32],
        }
    }

    #[test]
    fn attestation_roundtrip_and_length() {
        let a = sample_attestation();
        let bytes = a.to_canonical();
        assert_eq!(bytes.len(), ATTESTATION_LEN);
        assert_eq!(bytes.len(), 67);
        assert_eq!(bytes[0], crate::TAG_ATTESTATION);
        assert_eq!(bytes[1], crate::VERSION_V1);
        assert_eq!(Attestation::from_canonical(&bytes), Ok(a));
    }

    #[test]
    fn attestation_rejects_malformed() {
        let mut bytes = sample_attestation().to_canonical();
        assert_eq!(
            Attestation::from_canonical(&bytes[..66]),
            Err(StatementError::WrongLength {
                expected: 67,
                got: 66
            })
        );
        let mut bad_tag = bytes;
        bad_tag[0] = crate::TAG_DELEGATION;                                                  
        assert_eq!(
            Attestation::from_canonical(&bad_tag),
            Err(StatementError::BadTag(crate::TAG_DELEGATION))
        );
        bytes[1] = 0x09;
        assert_eq!(
            Attestation::from_canonical(&bytes),
            Err(StatementError::BadVersion(0x09))
        );
        let mut bad_purpose = sample_attestation().to_canonical();
        bad_purpose[34] = 200;                        
        assert_eq!(
            Attestation::from_canonical(&bad_purpose),
            Err(StatementError::UnknownPurpose(200))
        );
    }
}
