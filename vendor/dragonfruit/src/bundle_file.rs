                                                                       
//! Fixed 254 bytes, verify-walk order:
//! `delegation[59] ‖ root_sig[64] ‖ attestation[67] ‖ worker_sig[64]`.
//! Parsing is a length-equality check + constant-offset slicing — the same
//! near-zero parse surface discipline as the statements themselves (no
//! variable-length field, no alloc beyond the owned arrays).

use crate::statement::{ATTESTATION_LEN, DELEGATION_LEN};
use crate::verify::Bundle;
use thiserror::Error;

const SIG_LEN: usize = 64;

/// The fixed on-disk `.sig` length: 59 + 64 + 67 + 64.
pub const BUNDLE_FILE_LEN: usize = DELEGATION_LEN + SIG_LEN + ATTESTATION_LEN + SIG_LEN;

                                                                                
                                                                            
                                                   
const DELEG_END: usize = DELEGATION_LEN;      
const ROOT_SIG_END: usize = DELEG_END + SIG_LEN;       
const ATTEST_END: usize = ROOT_SIG_END + ATTESTATION_LEN;       
const WORKER_SIG_END: usize = ATTEST_END + SIG_LEN;       
const _: () = assert!(WORKER_SIG_END == BUNDLE_FILE_LEN);

/// Why a `.sig` file failed to parse. Wrong length is the ONLY failure mode —
/// the fields are fixed-width, so a correct-length buffer always slices cleanly
/// (the signature/statement *contents* are validated by the verifier, not here).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleFileError {
    #[error("wrong bundle file length: expected {expected}, got {got}")]
    WrongLength { expected: usize, got: usize },
}

/// A parsed-by-position `.sig` bundle. Owns fixed arrays so it can outlive the
/// input buffer; [`as_bundle`](BundleFile::as_bundle) borrows it into the
/// verifier's [`Bundle`] tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub delegation_bytes: [u8; DELEGATION_LEN],
    pub root_sig: [u8; SIG_LEN],
    pub attestation_bytes: [u8; ATTESTATION_LEN],
    pub worker_sig: [u8; SIG_LEN],
}

impl BundleFile {
    /// Parse the fixed 254-byte file. Length-equality check + constant-offset
    /// slicing; `copy_from_slice` over verified-length ranges is panic-free.
    pub fn from_bytes(b: &[u8]) -> Result<Self, BundleFileError> {
        if b.len() != BUNDLE_FILE_LEN {
            return Err(BundleFileError::WrongLength {
                expected: BUNDLE_FILE_LEN,
                got: b.len(),
            });
        }
        let mut delegation_bytes = [0u8; DELEGATION_LEN];
        let mut root_sig = [0u8; SIG_LEN];
        let mut attestation_bytes = [0u8; ATTESTATION_LEN];
        let mut worker_sig = [0u8; SIG_LEN];
        delegation_bytes.copy_from_slice(&b[0..DELEG_END]);
        root_sig.copy_from_slice(&b[DELEG_END..ROOT_SIG_END]);
        attestation_bytes.copy_from_slice(&b[ROOT_SIG_END..ATTEST_END]);
        worker_sig.copy_from_slice(&b[ATTEST_END..WORKER_SIG_END]);
        Ok(BundleFile {
            delegation_bytes,
            root_sig,
            attestation_bytes,
            worker_sig,
        })
    }

    /// Serialize back to the canonical fixed-width bytes (round-trips `from_bytes`).
    pub fn to_bytes(&self) -> [u8; BUNDLE_FILE_LEN] {
        let mut out = [0u8; BUNDLE_FILE_LEN];
        out[0..DELEG_END].copy_from_slice(&self.delegation_bytes);
        out[DELEG_END..ROOT_SIG_END].copy_from_slice(&self.root_sig);
        out[ROOT_SIG_END..ATTEST_END].copy_from_slice(&self.attestation_bytes);
        out[ATTEST_END..WORKER_SIG_END].copy_from_slice(&self.worker_sig);
        out
    }

    /// Borrow as the verifier tuple — feed straight into `verify_bundle`.
    pub fn as_bundle(&self) -> Bundle<'_> {
        Bundle {
            delegation_bytes: &self.delegation_bytes,
            root_sig: &self.root_sig,
            attestation_bytes: &self.attestation_bytes,
            worker_sig: &self.worker_sig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_is_the_sum_of_components() {
        assert_eq!(BUNDLE_FILE_LEN, 254);
        assert_eq!(BUNDLE_FILE_LEN, 59 + 64 + 67 + 64);
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let bf = BundleFile {
            delegation_bytes: [0x11; DELEGATION_LEN],
            root_sig: [0x22; SIG_LEN],
            attestation_bytes: [0x33; ATTESTATION_LEN],
            worker_sig: [0x44; SIG_LEN],
        };
        assert_eq!(BundleFile::from_bytes(&bf.to_bytes()), Ok(bf));
    }

    #[test]
    fn wrong_length_rejects_both_directions() {
        let ok = [0u8; BUNDLE_FILE_LEN];
        assert!(BundleFile::from_bytes(&ok).is_ok());
        assert_eq!(
            BundleFile::from_bytes(&ok[..BUNDLE_FILE_LEN - 1]),
            Err(BundleFileError::WrongLength {
                expected: 254,
                got: 253
            })
        );
        let mut long = ok.to_vec();
        long.push(0);
        assert_eq!(
            BundleFile::from_bytes(&long),
            Err(BundleFileError::WrongLength {
                expected: 254,
                got: 255
            })
        );
    }
}
