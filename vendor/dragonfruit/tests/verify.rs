//! Chain + domain-separation + window + substitution-attack reject (1A AC#5/#6,
                                                                               
//! verify surface is exercised without the `sign` feature.
use dragonfruit::{
    verify_bundle, verify_bundle_over_bytes, Attestation, Bundle, Delegation, Purpose, VerifyError,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

                                 

struct Cascade {
    root: SigningKey,
    worker: SigningKey,
    deleg_bytes: Vec<u8>,
    root_sig: [u8; 64],
    attest_bytes: Vec<u8>,
    worker_sig: [u8; 64],
    artifact_hash: [u8; 32],
}

/// Build a fully valid root→worker cascade over a given artifact, window [nb,na].
fn build_cascade(purpose: Purpose, nb: u64, na: u64, ctr: u64) -> Cascade {
    let root = SigningKey::from_bytes(&[1u8; 32]);
    let worker = SigningKey::from_bytes(&[2u8; 32]);
    let artifact = b"the artifact bytes";
    let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();

    let d = Delegation {
        worker_pubkey: worker.verifying_key().to_bytes(),
        purpose,
        not_before: nb,
        not_after: na,
        monotonic_ctr: ctr,
    };
    let deleg_bytes = d.to_canonical().to_vec();
    let root_sig = root.sign(&deleg_bytes).to_bytes();
    let delegation_id: [u8; 32] = Sha256::digest(&deleg_bytes).into();

    let a = Attestation {
        artifact_hash,
        purpose,
        delegation_id,
    };
    let attest_bytes = a.to_canonical().to_vec();
    let worker_sig = worker.sign(&attest_bytes).to_bytes();

    Cascade {
        root,
        worker,
        deleg_bytes,
        root_sig,
        attest_bytes,
        worker_sig,
        artifact_hash,
    }
}

fn bundle(c: &Cascade) -> Bundle<'_> {
    Bundle {
        delegation_bytes: &c.deleg_bytes,
        root_sig: &c.root_sig,
        attestation_bytes: &c.attest_bytes,
        worker_sig: &c.worker_sig,
    }
}

#[test]
fn full_cascade_verifies_and_each_tamper_rejects() {
    let c = build_cascade(Purpose::Img, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();

           
    let v = verify_bundle(&bundle(&c), &root_pk, 50, &c.artifact_hash, Purpose::Img);
    assert!(v.is_ok(), "good cascade should verify: {v:?}");

                                                                                     
                                                       
    let wrong_root_pk = SigningKey::from_bytes(&[9u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        verify_bundle(
            &bundle(&c),
            &wrong_root_pk,
            50,
            &c.artifact_hash,
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::BadSignature
    );

                                                               
    let mut bad = c.deleg_bytes.clone();
    bad[5] ^= 0xFF;
    let b = Bundle {
        delegation_bytes: &bad,
        root_sig: &c.root_sig,
        attestation_bytes: &c.attest_bytes,
        worker_sig: &c.worker_sig,
    };
    assert_eq!(
        verify_bundle(&b, &root_pk, 50, &c.artifact_hash, Purpose::Img).unwrap_err(),
        VerifyError::BadSignature
    );

                                                                  
    let mut bad_att = c.attest_bytes.clone();
    bad_att[40] ^= 0xFF;
    let b = Bundle {
        delegation_bytes: &c.deleg_bytes,
        root_sig: &c.root_sig,
        attestation_bytes: &bad_att,
        worker_sig: &c.worker_sig,
    };
    assert_eq!(
        verify_bundle(&b, &root_pk, 50, &c.artifact_hash, Purpose::Img).unwrap_err(),
        VerifyError::BadSignature
    );
}

#[test]
fn window_not_yet_valid_and_expired() {
    let early = build_cascade(Purpose::Img, 10, 100, 1);
    let root_pk = early.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle(
            &bundle(&early),
            &root_pk,
            5,
            &early.artifact_hash,
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::WindowNotYetValid
    );
    assert_eq!(
        verify_bundle(
            &bundle(&early),
            &root_pk,
            200,
            &early.artifact_hash,
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::WindowExpired
    );
}

#[test]
fn clocked_verify_exposes_delegation_monotonic_ctr() {
                                                                                
                                                                          
                                                                                 
                                                                                  
                                                                               
    let c = build_cascade(Purpose::Img, 0, 100, 42);
    let root_pk = c.root.verifying_key().to_bytes();
    let v = verify_bundle(&bundle(&c), &root_pk, 50, &c.artifact_hash, Purpose::Img)
        .expect("good cascade verifies");
    assert_eq!(v.monotonic_ctr(), 42);
}

#[test]
fn purpose_mismatch_rejects() {
    let c = build_cascade(Purpose::Img, 0, 100, 1);
    let delegation_id: [u8; 32] = Sha256::digest(&c.deleg_bytes).into();
                                                                       
    let att = Attestation {
        artifact_hash: c.artifact_hash,
        purpose: Purpose::Backup,
        delegation_id,
    };
    let att_bytes = att.to_canonical();
    let worker_sig = c.worker.sign(&att_bytes).to_bytes();
    let b = Bundle {
        delegation_bytes: &c.deleg_bytes,
        root_sig: &c.root_sig,
        attestation_bytes: &att_bytes,
        worker_sig: &worker_sig,
    };
    assert_eq!(
        verify_bundle(
            &b,
            &c.root.verifying_key().to_bytes(),
            50,
            &c.artifact_hash,
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::PurposeMismatch
    );
}

#[test]
fn delegation_id_mismatch_rejects() {
    let c = build_cascade(Purpose::Img, 0, 100, 1);
                                                              
    let att = Attestation {
        artifact_hash: c.artifact_hash,
        purpose: Purpose::Img,
        delegation_id: [0u8; 32],
    };
    let att_bytes = att.to_canonical();
    let worker_sig = c.worker.sign(&att_bytes).to_bytes();
    let b = Bundle {
        delegation_bytes: &c.deleg_bytes,
        root_sig: &c.root_sig,
        attestation_bytes: &att_bytes,
        worker_sig: &worker_sig,
    };
    assert_eq!(
        verify_bundle(
            &b,
            &c.root.verifying_key().to_bytes(),
            50,
            &c.artifact_hash,
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::DelegationIdMismatch
    );
}

#[test]
fn chain_valid_but_wrong_artifact_is_rejected() {
                                                                                
                                                                                      
    let c = build_cascade(Purpose::Img, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    let wrong_hash = [0x99u8; 32];
    assert_eq!(
        verify_bundle(&bundle(&c), &root_pk, 50, &wrong_hash, Purpose::Img).unwrap_err(),
        VerifyError::ArtifactHashMismatch
    );
}

#[test]
fn verify_over_bytes_hashes_internally() {
    let c = build_cascade(Purpose::Img, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
                                                    
    let v = verify_bundle_over_bytes(
        &bundle(&c),
        &root_pk,
        50,
        b"the artifact bytes",
        Purpose::Img,
    );
    assert!(v.is_ok());
    let bad = verify_bundle_over_bytes(&bundle(&c), &root_pk, 50, b"different bytes", Purpose::Img);
    assert_eq!(bad.unwrap_err(), VerifyError::ArtifactHashMismatch);
}

#[test]
fn worker_equal_root_is_rejected() {
                                                                                
                                                                                
                                                       
    let root = SigningKey::from_bytes(&[1u8; 32]);
    let root_pk = root.verifying_key().to_bytes();
    let artifact_hash: [u8; 32] = Sha256::digest(b"x").into();

    let d = Delegation {
        worker_pubkey: root_pk,                  
        purpose: Purpose::Img,
        not_before: 0,
        not_after: 100,
        monotonic_ctr: 1,
    };
    let d_bytes = d.to_canonical();
    let root_sig = root.sign(&d_bytes).to_bytes();
    let delegation_id: [u8; 32] = Sha256::digest(d_bytes).into();

    let a = Attestation {
        artifact_hash,
        purpose: Purpose::Img,
        delegation_id,
    };
    let a_bytes = a.to_canonical();
    let worker_sig = root.sign(&a_bytes).to_bytes();                              

    let b = Bundle {
        delegation_bytes: &d_bytes,
        root_sig: &root_sig,
        attestation_bytes: &a_bytes,
        worker_sig: &worker_sig,
    };
    assert_eq!(
        verify_bundle(&b, &root_pk, 50, &artifact_hash, Purpose::Img).unwrap_err(),
        VerifyError::RootWorkerKeyReuse
    );
}

#[test]
fn cross_purpose_is_rejected_by_expected_purpose_binding() {
                                                                                 
                                                                                
                                                                                  
                                                                                  
                                                                                  
                                                                                  
    let c = build_cascade(Purpose::Backup, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();

                                                           
    assert!(verify_bundle(&bundle(&c), &root_pk, 50, &c.artifact_hash, Purpose::Backup).is_ok());

                                                                                     
                                                            
    let err = verify_bundle(&bundle(&c), &root_pk, 50, &c.artifact_hash, Purpose::Img).unwrap_err();
    assert_eq!(
        err,
        VerifyError::UnexpectedPurpose {
            expected: Purpose::Img,
            got: Purpose::Backup,
        }
    );
    let msg = err.to_string();
    assert!(msg.contains("Img"), "error names expected purpose: {msg}");
    assert!(msg.contains("Backup"), "error names actual purpose: {msg}");

                                                                                      
    assert_eq!(
        verify_bundle_over_bytes(
            &bundle(&c),
            &root_pk,
            50,
            b"the artifact bytes",
            Purpose::Img
        )
        .unwrap_err(),
        VerifyError::UnexpectedPurpose {
            expected: Purpose::Img,
            got: Purpose::Backup,
        }
    );
}

#[test]
fn weights_purpose_is_confusion_bound_both_directions() {
                                                                                     
                                                                                 
                                                                 
    let w = build_cascade(Purpose::Weights, 0, 100, 1);
    let w_pk = w.root.verifying_key().to_bytes();

                                 
    assert!(verify_bundle(&bundle(&w), &w_pk, 50, &w.artifact_hash, Purpose::Weights).is_ok());

                                                                      
    for expected in [Purpose::Backup, Purpose::UpdateImage] {
        assert_eq!(
            verify_bundle(&bundle(&w), &w_pk, 50, &w.artifact_hash, expected).unwrap_err(),
            VerifyError::UnexpectedPurpose {
                expected,
                got: Purpose::Weights,
            }
        );
    }

                                                                    
    let b = build_cascade(Purpose::Backup, 0, 100, 1);
    let b_pk = b.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle(&bundle(&b), &b_pk, 50, &b.artifact_hash, Purpose::Weights).unwrap_err(),
        VerifyError::UnexpectedPurpose {
            expected: Purpose::Weights,
            got: Purpose::Backup,
        }
    );
}
