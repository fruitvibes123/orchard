//! The clock-free sibling: `verify_bundle_no_window` + the sealed, non-convertible
                                                                                  
//! ONLY check dropped vs `verify_bundle`, that BOTH mandatory bindings (artifact
//! hash + expected purpose) are re-applied by the windowless path itself
                                                                                  
//! reject order pinned in §2a. The compile-time non-convertibility of the sealed
//! type (AC3) is proven separately by the trybuild probes (Task 5).
use dragonfruit::{
    verify_bundle, verify_bundle_no_window, Attestation, Bundle, Delegation, Purpose, VerifyError,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

                                                                                  
                                                              
struct Cascade {
    root: SigningKey,
    deleg_bytes: Vec<u8>,
    root_sig: [u8; 64],
    attest_bytes: Vec<u8>,
    worker_sig: [u8; 64],
    artifact_hash: [u8; 32],
}

/// A fully valid root→worker cascade over a fixed artifact, window [nb,na], counter ctr.
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
fn expired_bundle_rejected_by_clocked_is_accepted_windowless() {
                                                                                  
                                                                                     
                                                                    
    let c = build_cascade(Purpose::UpdateImage, 1_000, 2_000, 1);
    let root_pk = c.root.verifying_key().to_bytes();

    assert_eq!(
        verify_bundle(
            &bundle(&c),
            &root_pk,
            3_000,
            &c.artifact_hash,
            Purpose::UpdateImage
        )
        .unwrap_err(),
        VerifyError::WindowExpired
    );

    let wua = verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::UpdateImage,
        0,
    )
    .expect("windowless accepts an expired-but-otherwise-valid bundle");
    assert_eq!(wua.purpose(), Purpose::UpdateImage);
    assert_eq!(wua.artifact_hash(), &c.artifact_hash);
    assert_eq!(wua.not_before(), 1_000);                                  
    assert_eq!(wua.not_after(), 2_000);
    assert_eq!(wua.monotonic_ctr(), 1);
}

#[test]
fn not_yet_valid_bundle_accepted_windowless() {
                                                                                       
                                   
    let c = build_cascade(Purpose::UpdateImage, 1_000, 2_000, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle(
            &bundle(&c),
            &root_pk,
            500,
            &c.artifact_hash,
            Purpose::UpdateImage
        )
        .unwrap_err(),
        VerifyError::WindowNotYetValid
    );
    assert!(verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::UpdateImage,
        0
    )
    .is_ok());
}

                                                                                     

#[test]
fn windowless_rejects_wrong_root_key() {
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 1);
    let wrong_root = SigningKey::from_bytes(&[9u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &wrong_root,
            &c.artifact_hash,
            Purpose::UpdateImage,
            0
        )
        .unwrap_err(),
        VerifyError::BadSignature
    );
}

#[test]
fn windowless_rejects_tampered_delegation_and_attestation() {
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();

    let mut bad = c.deleg_bytes.clone();
    bad[5] ^= 0xFF;
    let b = Bundle {
        delegation_bytes: &bad,
        root_sig: &c.root_sig,
        attestation_bytes: &c.attest_bytes,
        worker_sig: &c.worker_sig,
    };
    assert_eq!(
        verify_bundle_no_window(&b, &root_pk, &c.artifact_hash, Purpose::UpdateImage, 0)
            .unwrap_err(),
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
        verify_bundle_no_window(&b, &root_pk, &c.artifact_hash, Purpose::UpdateImage, 0)
            .unwrap_err(),
        VerifyError::BadSignature
    );
}

#[test]
fn windowless_rejects_role_collapse() {
                                                                                  
                                                                        
    let root = SigningKey::from_bytes(&[1u8; 32]);
    let root_pk = root.verifying_key().to_bytes();
    let artifact_hash: [u8; 32] = Sha256::digest(b"x").into();

    let d = Delegation {
        worker_pubkey: root_pk,
        purpose: Purpose::UpdateImage,
        not_before: 0,
        not_after: 100,
        monotonic_ctr: 1,
    };
    let d_bytes = d.to_canonical();
    let root_sig = root.sign(&d_bytes).to_bytes();
    let delegation_id: [u8; 32] = Sha256::digest(d_bytes).into();
    let a = Attestation {
        artifact_hash,
        purpose: Purpose::UpdateImage,
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
        verify_bundle_no_window(&b, &root_pk, &artifact_hash, Purpose::UpdateImage, 0).unwrap_err(),
        VerifyError::RootWorkerKeyReuse
    );
}

#[test]
fn windowless_rejects_malformed_window() {
                                                                                       
                                                                                         
    let c = build_cascade(Purpose::UpdateImage, 100, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &c.artifact_hash,
            Purpose::UpdateImage,
            0
        )
        .unwrap_err(),
        VerifyError::WindowInvalid
    );
}

                                                                                      

#[test]
fn windowless_rejects_wrong_artifact_hash() {
                                                                                    
                                                                               
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &[0x99u8; 32],
            Purpose::UpdateImage,
            0
        )
        .unwrap_err(),
        VerifyError::ArtifactHashMismatch
    );
}

#[test]
fn windowless_rejects_wrong_expected_purpose() {
                                                                            
                                                                                    
                                                               
    let c = build_cascade(Purpose::Backup, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &c.artifact_hash,
            Purpose::UpdateImage,
            0
        )
        .unwrap_err(),
        VerifyError::UnexpectedPurpose {
            expected: Purpose::UpdateImage,
            got: Purpose::Backup,
        }
    );
}

#[test]
fn windowless_weights_purpose_is_confusion_bound_both_directions() {
                                                                                    
                                                                                 
    let w = build_cascade(Purpose::Weights, 0, 100, 1);
    let w_pk = w.root.verifying_key().to_bytes();

    assert!(
        verify_bundle_no_window(&bundle(&w), &w_pk, &w.artifact_hash, Purpose::Weights, 0).is_ok()
    );

    for expected in [Purpose::Backup, Purpose::UpdateImage] {
        assert_eq!(
            verify_bundle_no_window(&bundle(&w), &w_pk, &w.artifact_hash, expected, 0).unwrap_err(),
            VerifyError::UnexpectedPurpose {
                expected,
                got: Purpose::Weights,
            }
        );
    }

    let b = build_cascade(Purpose::Backup, 0, 100, 1);
    let b_pk = b.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(&bundle(&b), &b_pk, &b.artifact_hash, Purpose::Weights, 0)
            .unwrap_err(),
        VerifyError::UnexpectedPurpose {
            expected: Purpose::Weights,
            got: Purpose::Backup,
        }
    );
}

                                                                                   

#[test]
fn min_ctr_floor_accepts_at_or_above_rejects_below() {
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 5);                      
    let root_pk = c.root.verifying_key().to_bytes();
                                  
    assert!(verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::UpdateImage,
        5
    )
    .is_ok());
                                     
    assert!(verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::UpdateImage,
        4
    )
    .is_ok());
                                                         
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &c.artifact_hash,
            Purpose::UpdateImage,
            6
        )
        .unwrap_err(),
        VerifyError::CounterRollback
    );
}

#[test]
fn min_ctr_zero_floors_nothing() {
                                                                                         
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 0);
    let root_pk = c.root.verifying_key().to_bytes();
    assert!(verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::UpdateImage,
        0
    )
    .is_ok());
}

                                                                                    
                                                                                           

#[test]
fn reject_order_window_invalid_beats_counter_low() {
                                                                                       
    let c = build_cascade(Purpose::UpdateImage, 100, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &c.artifact_hash,
            Purpose::UpdateImage,
            999
        )
        .unwrap_err(),
        VerifyError::WindowInvalid
    );
}

#[test]
fn reject_order_hash_mismatch_beats_counter_low() {
                                                                                            
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &[0x99u8; 32],
            Purpose::UpdateImage,
            999
        )
        .unwrap_err(),
        VerifyError::ArtifactHashMismatch
    );
}

#[test]
fn reject_order_purpose_mismatch_beats_counter_low() {
                                                                                            
    let c = build_cascade(Purpose::Backup, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &c.artifact_hash,
            Purpose::UpdateImage,
            999
        )
        .unwrap_err(),
        VerifyError::UnexpectedPurpose {
            expected: Purpose::UpdateImage,
            got: Purpose::Backup,
        }
    );
}

#[test]
fn reject_order_hash_beats_purpose() {
                                                                                          
    let c = build_cascade(Purpose::Backup, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();
    assert_eq!(
        verify_bundle_no_window(
            &bundle(&c),
            &root_pk,
            &[0x99u8; 32],
            Purpose::UpdateImage,
            0
        )
        .unwrap_err(),
        VerifyError::ArtifactHashMismatch
    );
}

                                                                                   

#[test]
fn reject_order_cascade_beats_binding() {
                                                                                          
                                                                                             
                                                                         
                                                                      
                                                                                     
                                                                                         
                                                                                               
    let c = build_cascade(Purpose::UpdateImage, 0, 100, 1);
    let root_pk = c.root.verifying_key().to_bytes();

    let mut bad_att = c.attest_bytes.clone();
    bad_att[40] ^= 0xFF;                                              
    let b = Bundle {
        delegation_bytes: &c.deleg_bytes,
        root_sig: &c.root_sig,
        attestation_bytes: &bad_att,
        worker_sig: &c.worker_sig,
    };
    assert_eq!(
        verify_bundle_no_window(&b, &root_pk, &[0x99u8; 32], Purpose::UpdateImage, 0).unwrap_err(),
        VerifyError::BadSignature
    );
}

                                                                                  

#[test]
fn windowless_accepts_valid_and_reports_facts() {
    let c = build_cascade(Purpose::RootHash, 1_000, 2_000, 7);
    let root_pk = c.root.verifying_key().to_bytes();
    let wua = verify_bundle_no_window(
        &bundle(&c),
        &root_pk,
        &c.artifact_hash,
        Purpose::RootHash,
        7,
    )
    .expect("valid windowless verify");
    assert_eq!(wua.purpose(), Purpose::RootHash);
    assert_eq!(wua.artifact_hash(), &c.artifact_hash);
    assert_eq!(wua.not_before(), 1_000);
    assert_eq!(wua.not_after(), 2_000);
    assert_eq!(wua.monotonic_ctr(), 7);
}
