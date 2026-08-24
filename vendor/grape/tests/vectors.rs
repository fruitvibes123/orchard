//! Reference-vector + determinism + wire-format tests for the rescue host-key
//! derivation (plan Task 1.1). The HKDF salts/info + IKM assembly are re-encoded
//! independently here (NOT imported from the crate) so a drift in the library's
//! construction is caught rather than masked; RFC 5869 anchors the HKDF-SHA256
//! primitive itself.

use hkdf::Hkdf;
use sha2::Sha256;

use grape::{
    derive_host_key, derive_seed, ed25519_public_from_seed, host_key_from_seed, seed_from_inputs,
    DeriveError, PublicInputs,
};

                                    

#[test]
fn public_inputs_accepts_valid() {
    assert!(PublicInputs::new("a".repeat(40), "3.21.0", "b".repeat(64)).is_ok());
}

#[test]
fn public_inputs_rejects_bad_input() {
                       
    assert!(PublicInputs::new("a".repeat(39), "3.21.0", "b".repeat(64)).is_err());
    assert!(PublicInputs::new("a".repeat(40), "3.21.0", "b".repeat(63)).is_err());
                        
    assert!(PublicInputs::new("g".repeat(40), "3.21.0", "b".repeat(64)).is_err());
                           
    assert!(PublicInputs::new("a".repeat(40), "", "b".repeat(64)).is_err());
                                                
    assert!(PublicInputs::new("a".repeat(40), "3.21|evil", "b".repeat(64)).is_err());
}

                                                                    

#[test]
fn hkdf_sha256_matches_rfc5869_tc1() {
    let ikm = [0x0bu8; 22];
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, expected);
}

                                       

#[test]
fn seed_is_deterministic_and_matches_documented_construction() {
    let master_key = [0x42u8; 32];
    let git = "a".repeat(40);
    let alpine = "3.21.0";
    let crt = "b".repeat(64);
    let pi = PublicInputs::new(&git, alpine, &crt).unwrap();

    let seed = seed_from_inputs(&master_key, &pi).unwrap();

                               
    assert_eq!(seed, seed_from_inputs(&master_key, &pi).unwrap());

                                                                                
    let mut ikm = format!("{git}|{alpine}|{crt}").into_bytes();
    ikm.extend_from_slice(&master_key);
    let hk = Hkdf::<Sha256>::new(Some(b"rescue-host-key-seed-derivation-v1"), &ikm);
    let mut expected = [0u8; 32];
    hk.expand(b"rescue-host-key-seed", &mut expected).unwrap();
    assert_eq!(seed, expected);
}

                                                               

#[test]
fn host_key_wire_format_and_determinism() {
    let seed = [0x11u8; 32];
    let nonce = [0x22u8; 32];                                  

    let key = host_key_from_seed(&seed, &nonce).unwrap();
    let b = key.as_ref();

                                                                                 
                                                                       
    assert_eq!(b.len(), 83);
    assert_eq!(&b[0..4], &[0, 0, 0, 11]);
    assert_eq!(&b[4..15], b"ssh-ed25519");
    assert_eq!(&b[15..19], &[0, 0, 0, 64]);

                                                                                      
    let hk = Hkdf::<Sha256>::new(Some(b"rescue-host-key-derivation-v1"), &seed);
    let mut expected_ed_seed = [0u8; 32];
    hk.expand(&nonce, &mut expected_ed_seed).unwrap();
    assert_eq!(&b[19..51], &expected_ed_seed);

                                                                                    
    let embedded_seed: [u8; 32] = b[19..51].try_into().unwrap();
    let embedded_pub: [u8; 32] = b[51..83].try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&embedded_seed);
    assert_eq!(sk.verifying_key().to_bytes(), embedded_pub);

                               
    assert_eq!(b, host_key_from_seed(&seed, &nonce).unwrap().as_ref());
}

#[test]
fn ed25519_public_matches_the_dropbear_embedded_public() {
    let seed = [0x33u8; 32];
    let nonce = [0x44u8; 32];
                                                                                      
                                                                                            
    let dropbear = host_key_from_seed(&seed, &nonce).unwrap();
    let embedded_pub: [u8; 32] = dropbear.as_ref()[51..83].try_into().unwrap();
    assert_eq!(
        ed25519_public_from_seed(&seed, &nonce).unwrap(),
        embedded_pub
    );
                               
    assert_eq!(
        ed25519_public_from_seed(&seed, &nonce).unwrap(),
        ed25519_public_from_seed(&seed, &nonce).unwrap()
    );
}

                                                        

#[test]
fn path_api_reads_files_and_matches_cores() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("rhkd-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let master_key = [0x42u8; 32];
    let mk_path = dir.join("master.key");
    std::fs::File::create(&mk_path)
        .unwrap()
        .write_all(&master_key)
        .unwrap();
    let pi = PublicInputs::new("a".repeat(40), "3.21.0", "b".repeat(64)).unwrap();
    let seed_via_path = derive_seed(&mk_path, &pi).unwrap();
    assert_eq!(seed_via_path, seed_from_inputs(&master_key, &pi).unwrap());

    let seed_path = dir.join("seed");
    std::fs::File::create(&seed_path)
        .unwrap()
        .write_all(&seed_via_path)
        .unwrap();
    let nonce = [0x22u8; 32];
    let key_via_path = derive_host_key(&seed_path, &nonce).unwrap();
    assert_eq!(
        key_via_path.as_ref(),
        host_key_from_seed(&seed_via_path, &nonce).unwrap().as_ref()
    );

                                             
    let bad = dir.join("bad");
    std::fs::File::create(&bad)
        .unwrap()
        .write_all(&[0u8; 16])
        .unwrap();
    assert!(matches!(
        derive_seed(&bad, &pi),
        Err(DeriveError::FileRead(_))
    ));

    std::fs::remove_dir_all(&dir).ok();
}

                                                  

#[test]
fn kernel_frandom_seed_is_deterministic_hex_and_git_bound() {
    use grape::kernel_frandom_seed_hex;
    let master = [7u8; 32];
    let s1 = kernel_frandom_seed_hex(&master, "abc123").unwrap();
    assert_eq!(
        s1,
        kernel_frandom_seed_hex(&master, "abc123").unwrap(),
        "deterministic"
    );
    assert_eq!(s1.len(), 64, "32-byte seed as lowercase hex");
    assert!(s1.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(
        s1,
        kernel_frandom_seed_hex(&master, "def456").unwrap(),
        "git_sha-bound"
    );
}

#[test]
fn kernel_frandom_seed_matches_independent_hkdf_and_is_domain_separated() {
    use grape::kernel_frandom_seed_hex;
                                                                                         
    let master = [9u8; 32];
    let git = "feedface".repeat(5);          
    let mut info = b"kernel-frandom-seed".to_vec();
    info.push(b':');
    info.extend_from_slice(git.as_bytes());
    let hk = Hkdf::<Sha256>::new(
        Some(&b"recipes-kernel-frandom-seed-derivation-v1"[..]),
        &master,
    );
    let mut expect = [0u8; 32];
    hk.expand(&info, &mut expect).unwrap();
    let expect_hex: String = expect.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        kernel_frandom_seed_hex(&master, &git).unwrap(),
        expect_hex,
        "library matches an independent re-encoding of the kernel HKDF"
    );
                                                                                               
    let pi = PublicInputs::new(git.clone(), "3.23", "cd".repeat(32)).unwrap();
    let rescue: String = seed_from_inputs(&master, &pi)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_ne!(
        expect_hex, rescue,
        "kernel seed is domain-separated from the rescue seed"
    );
}
