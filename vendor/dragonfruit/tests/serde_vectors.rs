//! Known-answer vectors pinning the canonical statement bytes. If these change,
//! the C3 firmware wire format changed too — that is a deliberate, reviewed act.
use dragonfruit::{verify_bundle, Attestation, Bundle, Delegation, Purpose};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

#[test]
fn delegation_canonical_bytes_are_pinned() {
    let d = Delegation {
        worker_pubkey: [0xAB; 32],
        purpose: Purpose::Img,
        not_before: 1_000,
        not_after: 2_000,
        monotonic_ctr: 7,
    };
                                                                                                 
    let expected = "0101\
abababababababababababababababababababababababababababababababab\
00\
00000000000003e8\
00000000000007d0\
0000000000000007";
    assert_eq!(hex::encode(d.to_canonical()), expected);
    assert_eq!(d.to_canonical().len(), 59);
}

#[test]
fn attestation_canonical_bytes_are_pinned() {
    let a = Attestation {
        artifact_hash: [0x11; 32],
        purpose: Purpose::Backup,
        delegation_id: [0x22; 32],
    };
                                                 
    let expected = "0201\
1111111111111111111111111111111111111111111111111111111111111111\
03\
2222222222222222222222222222222222222222222222222222222222222222";
    assert_eq!(hex::encode(a.to_canonical()), expected);
    assert_eq!(a.to_canonical().len(), 67);
}

#[test]
fn signed_bundle_golden_vector() {
                                                                                   
                                                                             
                                                                          
                                                                              
    let root = SigningKey::from_bytes(&[1u8; 32]);
    let worker = SigningKey::from_bytes(&[2u8; 32]);
    let artifact = b"dragonfruit golden artifact";
    let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();

    let d = Delegation {
        worker_pubkey: worker.verifying_key().to_bytes(),
        purpose: Purpose::Img,
        not_before: 1_000,
        not_after: 2_000,
        monotonic_ctr: 1,
    };
    let deleg_bytes = d.to_canonical();
    let root_sig = root.sign(&deleg_bytes).to_bytes();
    let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
    let a = Attestation {
        artifact_hash,
        purpose: Purpose::Img,
        delegation_id,
    };
    let attest_bytes = a.to_canonical();
    let worker_sig = worker.sign(&attest_bytes).to_bytes();

    assert_eq!(
        hex::encode(root.verifying_key().to_bytes()),
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
    );
    assert_eq!(
        hex::encode(deleg_bytes),
        "01018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394\
         0000000000000003e800000000000007d00000000000000001"
    );
    assert_eq!(
        hex::encode(root_sig),
        "329a99b0ccd7c0dd6154af0e70c6423f8fd3963fa8ce67f374738aa25eea270e\
         823eb457d24e6fb3e8dcf0a8ea5820a807fd0c913128222d1f7f15c4b52b7b0c"
    );
    assert_eq!(
        hex::encode(attest_bytes),
        "0201f8fa05fd8b8b48df05cc3a5a0a9d0d40f96a4e4849f0c43a031f00dabe10bea1\
         001884134ef96db8ca7a1710349a29be345c576d1d477f5d42abcb42412d8bdddb"
    );
    assert_eq!(
        hex::encode(worker_sig),
        "68d20066cdede9a2b4ac0822d77b32a634ada11ae279f0d2c39a92157efbad21\
         ff2f9523530dc43882ab5ef90864a2c6fb108683fd467fffce1301e62f1cd10c"
    );

                                                                             
    let bundle = Bundle {
        delegation_bytes: &deleg_bytes,
        root_sig: &root_sig,
        attestation_bytes: &attest_bytes,
        worker_sig: &worker_sig,
    };
    assert!(verify_bundle(
        &bundle,
        &root.verifying_key().to_bytes(),
        1_500,
        &artifact_hash,
        Purpose::Img
    )
    .is_ok());
}

#[test]
fn bundle_file_golden_vector_roundtrips() {
                                                                             
                                                                                     
                                                                                 
    let deleg = "01018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394\
                 0000000000000003e800000000000007d00000000000000001";
    let root_sig = "329a99b0ccd7c0dd6154af0e70c6423f8fd3963fa8ce67f374738aa25eea270e\
                    823eb457d24e6fb3e8dcf0a8ea5820a807fd0c913128222d1f7f15c4b52b7b0c";
    let attest = "0201f8fa05fd8b8b48df05cc3a5a0a9d0d40f96a4e4849f0c43a031f00dabe10bea1\
                  001884134ef96db8ca7a1710349a29be345c576d1d477f5d42abcb42412d8bdddb";
    let worker_sig = "68d20066cdede9a2b4ac0822d77b32a634ada11ae279f0d2c39a92157efbad21\
                      ff2f9523530dc43882ab5ef90864a2c6fb108683fd467fffce1301e62f1cd10c";
    let file_hex = format!("{deleg}{root_sig}{attest}{worker_sig}");
    let bytes = hex::decode(&file_hex).expect("golden hex decodes");
    assert_eq!(bytes.len(), dragonfruit::BUNDLE_FILE_LEN);
    assert_eq!(dragonfruit::BUNDLE_FILE_LEN, 254);

                                                                      
    let parsed = dragonfruit::BundleFile::from_bytes(&bytes).expect("254 bytes parse");
    assert_eq!(hex::encode(parsed.delegation_bytes), deleg);
    assert_eq!(hex::encode(parsed.root_sig), root_sig);
    assert_eq!(hex::encode(parsed.attestation_bytes), attest);
    assert_eq!(hex::encode(parsed.worker_sig), worker_sig);
    assert_eq!(parsed.to_bytes().to_vec(), bytes);

                                                                           
    let artifact_hash: [u8; 32] = Sha256::digest(b"dragonfruit golden artifact").into();
    let root_pub =
        hex::decode("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c").unwrap();
    let root_pub: [u8; 32] = root_pub.try_into().unwrap();
    assert!(verify_bundle(
        &parsed.as_bundle(),
        &root_pub,
        1_500,
        &artifact_hash,
        Purpose::Img
    )
    .is_ok());

                                                                                  
    assert!(dragonfruit::BundleFile::from_bytes(&bytes[..253]).is_err());
    let mut long = bytes.clone();
    long.push(0);
    assert!(dragonfruit::BundleFile::from_bytes(&long).is_err());
}

#[test]
fn delegation_update_image_canonical_bytes_are_pinned() {
                                                                                 
                                                                                 
    let d = Delegation {
        worker_pubkey: [0xCD; 32],
        purpose: Purpose::UpdateImage,
        not_before: 1_000,
        not_after: 2_000,
        monotonic_ctr: 7,
    };
                                                                                   
    let expected = "0101\
cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
04\
00000000000003e8\
00000000000007d0\
0000000000000007";
    assert_eq!(hex::encode(d.to_canonical()), expected);
    assert_eq!(d.to_canonical().len(), 59);
}

#[test]
fn attestation_root_hash_canonical_bytes_are_pinned() {
                                                                              
                                    
    let a = Attestation {
        artifact_hash: [0x33; 32],
        purpose: Purpose::RootHash,
        delegation_id: [0x44; 32],
    };
                                                 
    let expected = "0201\
3333333333333333333333333333333333333333333333333333333333333333\
05\
4444444444444444444444444444444444444444444444444444444444444444";
    assert_eq!(hex::encode(a.to_canonical()), expected);
    assert_eq!(a.to_canonical().len(), 67);
}

#[test]
fn signed_update_image_bundle_golden_vector() {
                                                                              
                                                                                      
                                                                                
                                                                               
                                                                         
    let root = SigningKey::from_bytes(&[3u8; 32]);
    let worker = SigningKey::from_bytes(&[4u8; 32]);
    let artifact = b"dragonfruit update-image golden";
    let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();

    let d = Delegation {
        worker_pubkey: worker.verifying_key().to_bytes(),
        purpose: Purpose::UpdateImage,
        not_before: 1_000,
        not_after: 2_000,
        monotonic_ctr: 1,
    };
    let deleg_bytes = d.to_canonical();
    let root_sig = root.sign(&deleg_bytes).to_bytes();
    let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
    let a = Attestation {
        artifact_hash,
        purpose: Purpose::UpdateImage,
        delegation_id,
    };
    let attest_bytes = a.to_canonical();
    let worker_sig = worker.sign(&attest_bytes).to_bytes();

    assert_eq!(
        hex::encode(root.verifying_key().to_bytes()),
        "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
    );
    assert_eq!(
        hex::encode(deleg_bytes),
        "0101ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c\
         0400000000000003e800000000000007d00000000000000001"
    );
    assert_eq!(
        hex::encode(root_sig),
        "7ea0a83be1f7ae7df2703c3c8d49241e387b57eff58d6dc5efad319856c5c6c3\
         2978672f0b25f6ca171e3d47ecf82ef23bf4e62f322e8f766a02b7205257720e"
    );
    assert_eq!(
        hex::encode(attest_bytes),
        "0201bbb74458f8cd44ef8c8b85744e6aa227655c9b0f99b270c66ff0e3d27e6586\
         0304d8903de6a0a847bdc9667b142091751a523174b31d979ba903c70b9eb8475795"
    );
    assert_eq!(
        hex::encode(worker_sig),
        "76a0add0b54a94ff13c8b4f1600af67a73f79fabd7a509d5d9c059cce2382d8cb\
         c670a6cf6e766c5ddfd8e79df8b145d3177befc35950afe21d14fb1c9809201"
    );

                                                                                  
                                                                   
    let bundle = Bundle {
        delegation_bytes: &deleg_bytes,
        root_sig: &root_sig,
        attestation_bytes: &attest_bytes,
        worker_sig: &worker_sig,
    };
    assert!(verify_bundle(
        &bundle,
        &root.verifying_key().to_bytes(),
        1_500,
        &artifact_hash,
        Purpose::UpdateImage
    )
    .is_ok());
}
