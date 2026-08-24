//! Unit tests for the sibling `keys.rs`, extracted via `#[path]` to keep the
//! production file focused. Still a child module of `keys` (so `use super::*`
//! reaches its private items); a pure relocation of the former inline `mod tests`.

use super::*;
use x509_parser::prelude::FromDer;

fn opts(dir: &Path, mode: GenMode) -> GenerateKeysOpts {
    GenerateKeysOpts {
        output_dir: dir.join("keys"),
        subject_ou: Some("op-laptop".into()),
        force: false,
        mode,
        regenerate_master_key: false,
        fingerprints_path: dir.join("pinned-cert-fingerprints.toml"),
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

/// A self-signed CA cert that expired in the past (for the validity-window test).
fn expired_ca_der() -> Vec<u8> {
    let kp = ecdsa_keypair().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, "expired-ca");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let two_years = Duration::from_secs(TEN_YEARS_SECS / 5);
    let expired_at = SystemTime::now() - two_years;
    p.not_before = (expired_at - two_years).into();
    p.not_after = expired_at.into();                        
    p.self_signed(&kp).unwrap().der().to_vec()
}

#[test]
fn f_keys_r1_1_curve_oid_gate_accepts_only_prime256v1() {
                                                                             
                                                                              
                                                                  
                                                                                  
    assert_eq!(PRIME256V1_OID, "1.2.840.10045.3.1.7");
    for other in [
        "1.3.132.0.10",
        "1.3.36.3.3.2.8.1.1.7",
        "1.2.156.10197.1.301",
    ] {
        assert_ne!(PRIME256V1_OID, other, "{other} must not match P-256");
    }
}

#[test]
fn f_keys_r1_4_import_rejects_expired_cert() {
    assert!(
        matches!(
            validate_ca_cert(&expired_ca_der()),
            Err(DeployKeyError::Import(_))
        ),
        "an expired CA must be rejected on import"
    );
}

#[test]
fn f_keys_r1_7_force_preserves_existing_master_key() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
    let master_before = read(&o.output_dir.join(MASTER_KEY_FILE));
    let ca_key_before = read(&o.output_dir.join("signing-ca.key"));

    let mut o2 = opts(tmp.path(), GenMode::Generate);
    o2.force = true;
    generate_keys(&o2).unwrap();

    assert_eq!(
        read(&o.output_dir.join(MASTER_KEY_FILE)),
        master_before,
        "force re-bootstrap PRESERVES the master.key (rescue-key continuity)"
    );
    assert_ne!(
        read(&o.output_dir.join("signing-ca.key")),
        ca_key_before,
        "force DOES re-issue the signing keys"
    );
}

#[test]
fn f_keys_r2_2_rotation_path_rejects_expired_cert() {
                                                                         
                                                                                   
    let kp = ecdsa_keypair().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name
        .push(DnType::CommonName, "expired-leaf");
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let two_years = Duration::from_secs(TEN_YEARS_SECS / 5);
    let expired_at = SystemTime::now() - two_years;
    p.not_before = (expired_at - two_years).into();
    p.not_after = expired_at.into();
    let pem = p.self_signed(&kp).unwrap().pem();
    assert!(
        matches!(
            fingerprint_entry_from_cert_pem(&pem),
            Err(DeployKeyError::Import(_))
        ),
        "rotation must refuse to pin an expired cert"
    );
}

#[test]
fn f_keys_r3_1_rcgen_keypair_is_zeroize() {
                                                                                
                                                                                     
                                                                                 
                                                                       
    fn assert_zeroize<T: zeroize::Zeroize>() {}
    assert_zeroize::<rcgen::KeyPair>();
}

#[test]
fn generate_writes_seven_files_with_correct_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();

    for name in SIGNING_FILES
        .iter()
        .chain(std::iter::once(&MASTER_KEY_FILE))
    {
        assert!(o.output_dir.join(name).exists(), "{name} missing");
    }
    assert!(o.fingerprints_path.exists(), "fingerprints toml missing");
                              
    let leftovers: Vec<_> = std::fs::read_dir(&o.output_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files leaked into keys dir");
    assert_eq!(read(&o.output_dir.join(MASTER_KEY_FILE)).len(), 32);
}

#[cfg(unix)]
#[test]
fn modes_are_0600_keys_0644_certs_in_0700_dir() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(o.output_dir.clone()), 0o700);
    for k in [
        "image-signing.key",
        "signing-ca.key",
        "ima.key",
        MASTER_KEY_FILE,
    ] {
        assert_eq!(mode(o.output_dir.join(k)), 0o600, "{k} not 0600");
    }
    for c in ["image-signing.crt", "signing-ca.crt", "ima.crt"] {
        assert_eq!(mode(o.output_dir.join(c)), 0o644, "{c} not 0644");
    }
}

#[test]
fn ima_leaf_chains_to_ca_and_is_digitalsignature_only() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();

    let ca_der =
        pem_cert_to_der(&String::from_utf8(read(&o.output_dir.join("signing-ca.crt"))).unwrap())
            .unwrap();
    let ima_der =
        pem_cert_to_der(&String::from_utf8(read(&o.output_dir.join("ima.crt"))).unwrap()).unwrap();

                                                                            
                                                                    
    validate_leaf_cert(&ima_der, Some(&ca_der), "ima").expect("ima leaf must validate");
                                      
    validate_ca_cert(&ca_der).expect("signing-ca must validate");

                                                              
    let (_, ima) = x509_parser::certificate::X509Certificate::from_der(&ima_der).unwrap();
    let ku = ima.key_usage().unwrap().unwrap();
    assert!(ku.value.digital_signature(), "ima leaf is digitalSignature");
    assert!(
        !ku.value.key_cert_sign(),
        "ima leaf must NOT be keyCertSign"
    );

                                                                                               
                                                                                          
                                                                                                  
                                                                                              
                                                                                         
    assert!(
        ima.basic_constraints().unwrap().is_none(),
        "ima leaf must have NO basicConstraints (canonical CA:FALSE; kernel rejects explicit FALSE)"
    );
    let ext_oids: Vec<String> = ima
        .extensions()
        .iter()
        .map(|e| e.oid.to_id_string())
        .collect();
    assert!(
        ext_oids.iter().any(|o| o == "2.5.29.35"),
        "ima leaf must carry AuthorityKeyIdentifier (2.5.29.35)"
    );
    assert!(
        ext_oids.iter().any(|o| o == "2.5.29.14"),
        "ima leaf must carry SubjectKeyIdentifier (2.5.29.14)"
    );

                                                              
    let (_, ca) = x509_parser::certificate::X509Certificate::from_der(&ca_der).unwrap();
    assert!(ca.key_usage().unwrap().unwrap().value.key_cert_sign());
    assert!(ca.basic_constraints().unwrap().unwrap().value.ca);
}

#[test]
fn image_signing_is_self_signed_leaf() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
    let der =
        pem_cert_to_der(&String::from_utf8(read(&o.output_dir.join("image-signing.crt"))).unwrap())
            .unwrap();
                                                                       
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
    cert.verify_signature(Some(cert.public_key()))
        .expect("image-signing self-signed");
    validate_leaf_cert(&der, None, "image-signing").unwrap();
}

#[test]
fn fingerprints_toml_has_all_three_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
    let toml = String::from_utf8(read(&o.fingerprints_path)).unwrap();
    assert!(toml.contains("[image_signing]"));
    assert!(toml.contains("[signing_ca]"));
    assert!(toml.contains("[ima]"));
    assert_eq!(toml.matches("fingerprint = \"sha256:").count(), 3);
                                                       
    let is_der =
        pem_cert_to_der(&String::from_utf8(read(&o.output_dir.join("image-signing.crt"))).unwrap())
            .unwrap();
    assert!(toml.contains(&format!("sha256:{}", sha256_hex(&is_der))));
}

#[test]
fn refuses_when_files_exist_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
                                                                       
    let before = read(&o.output_dir.join("signing-ca.key"));
    let o2 = opts(tmp.path(), GenMode::Generate);
    let err = generate_keys(&o2).unwrap_err();
    assert!(matches!(err, DeployKeyError::Exists(..)));
    assert_eq!(
        read(&o.output_dir.join("signing-ca.key")),
        before,
        "existing key untouched"
    );
}

#[test]
fn force_overwrites_existing() {
    let tmp = tempfile::tempdir().unwrap();
    generate_keys(&opts(tmp.path(), GenMode::Generate)).unwrap();
    let mut o2 = opts(tmp.path(), GenMode::Generate);
    o2.force = true;
    generate_keys(&o2).expect("force overwrites");
}

#[test]
fn regenerate_master_key_touches_only_master() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Generate);
    generate_keys(&o).unwrap();
    let ca_key_before = read(&o.output_dir.join("signing-ca.key"));
    let ima_crt_before = read(&o.output_dir.join("ima.crt"));
    let master_before = read(&o.output_dir.join(MASTER_KEY_FILE));

    let mut o2 = opts(tmp.path(), GenMode::Generate);
    o2.regenerate_master_key = true;
    o2.force = true;
    generate_keys(&o2).unwrap();

    assert_ne!(
        read(&o.output_dir.join(MASTER_KEY_FILE)),
        master_before,
        "master rotated"
    );
    assert_eq!(
        read(&o.output_dir.join("signing-ca.key")),
        ca_key_before,
        "ca key untouched"
    );
    assert_eq!(
        read(&o.output_dir.join("ima.crt")),
        ima_crt_before,
        "ima cert untouched"
    );
}

#[test]
fn regenerate_master_key_refuses_without_force_when_present() {
    let tmp = tempfile::tempdir().unwrap();
    generate_keys(&opts(tmp.path(), GenMode::Generate)).unwrap();
    let mut o2 = opts(tmp.path(), GenMode::Generate);
    o2.regenerate_master_key = true;                        
    assert!(matches!(
        generate_keys(&o2).unwrap_err(),
        DeployKeyError::Exists(..)
    ));
}

#[test]
fn token_mode_is_unsupported() {
    let tmp = tempfile::tempdir().unwrap();
    let o = opts(tmp.path(), GenMode::Token { slot: "9c".into() });
    assert!(matches!(
        generate_keys(&o).unwrap_err(),
        DeployKeyError::TokenUnsupported
    ));
    assert!(!o.output_dir.exists(), "token mode writes nothing");
}

#[test]
fn import_copies_six_and_autogenerates_master() {
                                                           
    let src = tempfile::tempdir().unwrap();
    generate_keys(&opts(src.path(), GenMode::Generate)).unwrap();
    let k = |n: &str| src.path().join("keys").join(n);

    let dst = tempfile::tempdir().unwrap();
    let import = GenMode::Import(ImportPaths {
        image_signing_key: k("image-signing.key"),
        image_signing_cert: k("image-signing.crt"),
        signing_ca_key: k("signing-ca.key"),
        signing_ca_cert: k("signing-ca.crt"),
        ima_key: k("ima.key"),
        ima_cert: k("ima.crt"),
    });
    let o = opts(dst.path(), import);
    generate_keys(&o).unwrap();

                                                                            
    assert_eq!(read(&o.output_dir.join("ima.crt")), read(&k("ima.crt")));
    assert_eq!(read(&o.output_dir.join(MASTER_KEY_FILE)).len(), 32);
    assert_ne!(
        read(&o.output_dir.join(MASTER_KEY_FILE)),
        read(&src.path().join("keys").join(MASTER_KEY_FILE)),
        "import auto-generates a DISTINCT master.key"
    );
}

#[test]
fn import_rejects_a_leaf_used_as_ca() {
                                                                               
                                                    
    let src = tempfile::tempdir().unwrap();
    generate_keys(&opts(src.path(), GenMode::Generate)).unwrap();
    let k = |n: &str| src.path().join("keys").join(n);
    let dst = tempfile::tempdir().unwrap();
    let import = GenMode::Import(ImportPaths {
        image_signing_key: k("image-signing.key"),
        image_signing_cert: k("image-signing.crt"),
        signing_ca_key: k("signing-ca.key"),
        signing_ca_cert: k("signing-ca.crt"),
        ima_key: k("signing-ca.key"),                                       
        ima_cert: k("signing-ca.crt"),
    });
    let err = generate_keys(&opts(dst.path(), import)).unwrap_err();
    assert!(
        matches!(err, DeployKeyError::Import(_)),
        "CA-as-leaf must be rejected, got {err:?}"
    );
}
