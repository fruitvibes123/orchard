//! dragonfruit — the operator-sovereign artifact-signing verify/sign core.
//!
                                                                           
//! `DELEGATION`/`ATTESTATION` statement format, the bundle verify (explicit
//! chain + the mandatory artifact-hash binding), and a feature-gated software
//! signer. Verify-only by default; `--features sign` adds software signing.
//!
                                                                                   
//! RP2350 firmware reuses the EXACT same verify+statement core as the host (one
//! audited parser/verifier, not two). The host calls it from `std` code unchanged.
#![no_std]
#![forbid(unsafe_code)]

                                                                                
#[cfg(test)]
extern crate std;

mod bundle_file;
#[cfg(feature = "sign")]
mod sign;
mod statement;
mod verify;

pub use bundle_file::{BundleFile, BundleFileError, BUNDLE_FILE_LEN};
#[cfg(feature = "sign")]
pub use sign::{sign_attestation, sign_delegation};
pub use statement::{
    Attestation, Delegation, Purpose, StatementError, ATTESTATION_LEN, DELEGATION_LEN,
};
pub use verify::{
    verify_bundle, verify_bundle_no_window, verify_bundle_over_bytes, Bundle, VerifiedArtifact,
    VerifyError, WindowUncheckedArtifact,
};

                                                                                         
pub(crate) const TAG_DELEGATION: u8 = 0x01;
pub(crate) const TAG_ATTESTATION: u8 = 0x02;
                                                                                         
                                                                                   
                                                                                   
                                                                                          
pub(crate) const VERSION_V1: u8 = 0x01;
