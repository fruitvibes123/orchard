//! Software-key signing for the `just create keys` / `docker` menu rungs
                                                                                
//! module is gated behind `--features sign` and never compiled into the
//! verify-only box/preflight build.

                                                                                                     
                                                                                                          
                                                                                                   
                                                                                                     
                                                                                                           
                                                                                                           
                                                                                                         
                                                                                                           
                                                                                                  
#[cfg(not(feature = "sanctioned-signer"))]
compile_error!(
    "dragonfruit's software signer (sign_delegation/sign_attestation) compiles ONLY in a SANCTIONED \
     off-box signing context: enable `sanctioned-signer` ALONGSIDE `sign`. The box VERIFIES, never \
     signs (box-never-signs CRUX). If you are seeing this from a box/preflight graph, drop `sign` — \
     do NOT add `sanctioned-signer`."
);

use crate::statement::{Attestation, Delegation};
use ed25519_dalek::{Signer, SigningKey};

/// Sign a delegation's canonical bytes with the ROOT software key.
pub fn sign_delegation(root: &SigningKey, delegation: &Delegation) -> [u8; 64] {
    root.sign(&delegation.to_canonical()).to_bytes()
}

/// Sign an attestation's canonical bytes with the WORKER software key.
pub fn sign_attestation(worker: &SigningKey, attestation: &Attestation) -> [u8; 64] {
    worker.sign(&attestation.to_canonical()).to_bytes()
}
