//! With `--features sign`, dragonfruit's own software signer produces bundles that
//! dragonfruit's verifier accepts (the software / docker key-menu rungs).
#![cfg(feature = "sign")]
use dragonfruit::{
    sign_attestation, sign_delegation, verify_bundle, Attestation, Bundle, Delegation, Purpose,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

#[test]
fn software_signed_bundle_verifies() {
    let root = SigningKey::from_bytes(&[3u8; 32]);
    let worker = SigningKey::from_bytes(&[4u8; 32]);
    let artifact = b"img bytes";
    let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();

    let d = Delegation {
        worker_pubkey: worker.verifying_key().to_bytes(),
        purpose: Purpose::Img,
        not_before: 0,
        not_after: 100,
        monotonic_ctr: 1,
    };
    let deleg_bytes = d.to_canonical();
    let root_sig = sign_delegation(&root, &d);
    let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();

    let a = Attestation {
        artifact_hash,
        purpose: Purpose::Img,
        delegation_id,
    };
    let attest_bytes = a.to_canonical();
    let worker_sig = sign_attestation(&worker, &a);

    let bundle = Bundle {
        delegation_bytes: &deleg_bytes,
        root_sig: &root_sig,
        attestation_bytes: &attest_bytes,
        worker_sig: &worker_sig,
    };
    assert!(verify_bundle(
        &bundle,
        &root.verifying_key().to_bytes(),
        50,
        &artifact_hash,
        Purpose::Img
    )
    .is_ok());
}
