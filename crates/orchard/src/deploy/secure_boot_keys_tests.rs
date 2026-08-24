//! Host units for the SB key family ceremony + the sign-sb preflights (SB-loader plan
//! Tasks 4.1/4.2). RSA-2048 here for test speed (the bits parameter is exercised; the
//! 3072 default is a CLI-level constant); `[profile.dev.package.num-bigint-dig]`
//! opt-level keeps keygen in seconds. The container-side halves (sbsign, the splice)
//! are proven by the #[ignore] container seam test + the §9.2 OVMF gate.

use super::*;
use x509_parser::prelude::{FromDer, X509Certificate};

fn gen_opts(dir: &Path) -> SecureBootKeysOpts {
    SecureBootKeysOpts {
        keys_dir: dir.join("keys"),
        db_fingerprint_path: dir.join("pinned-secure-boot-db.toml"),
        rung: SecureBootRung::Software,
        bits: SbRsaBits::Rsa2048,
        force: false,
        subject_ou: Some("test-op".into()),
    }
}

fn pem_to_der(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes).unwrap();
    pem.contents
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn software_rung_mints_the_pk_kek_db_chain_with_strict_modes_and_pins_db() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = gen_opts(tmp.path());
    generate_secure_boot_keys(&opts).expect("software rung mints the family");

    let sb = opts.keys_dir.join("secure-boot");
    assert_eq!(mode_of(&sb), 0o700, "secure-boot dir mode");
    for name in SECURE_BOOT_FILES {
        let p = sb.join(name);
        assert!(p.is_file(), "{name} written");
        let want = if name.ends_with(".key") { 0o600 } else { 0o644 };
        assert_eq!(mode_of(&p), want, "{name} mode");
    }

                                                                                
    let pk_der = pem_to_der(&sb.join("PK.crt"));
    let kek_der = pem_to_der(&sb.join("KEK.crt"));
    let db_der = pem_to_der(&sb.join("db.crt"));
    let (_, pk) = X509Certificate::from_der(&pk_der).unwrap();
    let (_, kek) = X509Certificate::from_der(&kek_der).unwrap();
    let (_, db) = X509Certificate::from_der(&db_der).unwrap();
    assert_eq!(pk.issuer(), pk.subject(), "PK is self-signed (the root)");
    assert_eq!(kek.issuer(), pk.subject(), "KEK is PK-signed");
    assert_eq!(db.issuer(), kek.subject(), "db is KEK-signed");
    assert!(pk.is_ca() && kek.is_ca(), "PK/KEK are CAs");
    assert!(!db.is_ca(), "db is a leaf");
    let db_ku = db.key_usage().unwrap().expect("db has KeyUsage");
    assert!(db_ku.value.digital_signature(), "db has digitalSignature");
                                                                  
    assert_eq!(
        db.public_key().parsed().unwrap().key_size(),
        2048,
        "db key size follows --sb-rsa"
    );
                                                                                      
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let twenty_nine_years = 60 * 60 * 24 * 365 * 29;
    assert!(
        db.validity().not_after.timestamp() > now_epoch + twenty_nine_years,
        "db validity is far-future"
    );

                                                                 
    let pin = std::fs::read_to_string(&opts.db_fingerprint_path).unwrap();
    let expected = format!("{:x}", sha2::Sha256::digest(&db_der));
    assert!(
        pin.contains(&format!("fingerprint = \"sha256:{expected}\"")),
        "pinned-secure-boot-db.toml carries the db DER sha256: {pin}"
    );
}

#[test]
fn rerun_refuses_without_force_and_force_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let mut opts = gen_opts(tmp.path());
    generate_secure_boot_keys(&opts).unwrap();
    let first_db = std::fs::read(opts.keys_dir.join("secure-boot/db.crt")).unwrap();

    let err = generate_secure_boot_keys(&opts).expect_err("re-run without --force refuses");
    assert!(matches!(err, SecureBootKeyError::Exists(..)), "got {err:?}");
    let unchanged = std::fs::read(opts.keys_dir.join("secure-boot/db.crt")).unwrap();
    assert_eq!(first_db, unchanged, "refusal left the family untouched");

    opts.force = true;
    generate_secure_boot_keys(&opts).expect("--force re-mints");
    let second_db = std::fs::read(opts.keys_dir.join("secure-boot/db.crt")).unwrap();
    assert_ne!(first_db, second_db, "--force minted a fresh family");
}

#[test]
fn hardware_rungs_route_to_not_yet_available_and_write_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    for rung in [SecureBootRung::OneSigner, SecureBootRung::TwoSigners] {
        let mut opts = gen_opts(tmp.path());
        opts.rung = rung;
        let err = generate_secure_boot_keys(&opts).expect_err("hardware rung routes");
        assert!(
            matches!(err, SecureBootKeyError::HardwareRungNotYetAvailable(_)),
            "got {err:?}"
        );
        assert!(
            !opts.keys_dir.join("secure-boot").exists(),
            "no partial family written"
        );
    }
}

#[test]
fn rung_and_bits_parse_the_cli_menu() {
    assert_eq!(
        SecureBootRung::parse("software"),
        Some(SecureBootRung::Software)
    );
    assert_eq!(
        SecureBootRung::parse("one-signer"),
        Some(SecureBootRung::OneSigner)
    );
    assert_eq!(
        SecureBootRung::parse("two-signers"),
        Some(SecureBootRung::TwoSigners)
    );
    assert_eq!(SecureBootRung::parse("hsm"), None);
    assert_eq!(SbRsaBits::parse("3072"), Some(SbRsaBits::Rsa3072));
    assert_eq!(SbRsaBits::parse("2048"), Some(SbRsaBits::Rsa2048));
    assert_eq!(SbRsaBits::parse("1024"), None, "no undocumented downgrade");
}

mod sign_sb_preflights {
    use super::super::super::sign_sb::{SignManifest, SignSbError, SignSbOpts, sign_sb};
    use super::*;

    fn sign_opts(dir: &Path, img: &Path) -> SignSbOpts {
        SignSbOpts {
            img: img.to_path_buf(),
            keys_dir: dir.join("keys"),
            rung: SecureBootRung::Software,
            container_image: "recipes-imgbuild:dev".into(),
            db_fingerprint_path: dir.join("pinned-secure-boot-db.toml"),
        }
    }

    #[test]
    fn hardware_rungs_route_before_touching_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let mut opts = sign_opts(tmp.path(), &tmp.path().join("x.img"));
        opts.rung = SecureBootRung::OneSigner;
        let err = sign_sb(&opts).expect_err("hardware rung routes");
        assert!(
            matches!(err, SignSbError::HardwareRungNotYetAvailable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn db_fingerprint_mismatch_fails_closed_before_signing() {
        let tmp = tempfile::tempdir().unwrap();
        let genk = gen_opts(tmp.path());
        generate_secure_boot_keys(&genk).unwrap();
                                                                            
        std::fs::write(
            &genk.db_fingerprint_path,
            format!("[db]\nfingerprint = \"sha256:{}\"\n", "0".repeat(64)),
        )
        .unwrap();
        let opts = sign_opts(tmp.path(), &tmp.path().join("x.img"));
        let err = sign_sb(&opts).expect_err("mismatched pin refuses");
        assert!(
            matches!(err, SignSbError::DbFingerprintMismatch { .. }),
            "got {err:?}"
        );
    }

    /// Normalize a PE to its Authenticode-COVERED bytes: zero the OptionalHeader CheckSum field, zero
    /// the Certificate Table (Security) data-directory entry, and drop the appended certificate table —
    /// the three regions the Authenticode PE hash excludes by construction. Two PEs with equal
    /// normalized bytes have the same Authenticode digest (would verify against the same signature).
    /// PE32+ only (x86_64-unknown-uefi); panics on a malformed/short PE (the test inputs are real PEs).
    fn authenticode_covered_bytes(pe: &[u8]) -> Vec<u8> {
        let u32le =
            |b: &[u8], off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;
        let pe_off = u32le(pe, 0x3c);                                      
        assert_eq!(&pe[pe_off..pe_off + 4], b"PE\0\0", "PE signature");
        let opt = pe_off + 24;                                                    
        assert_eq!(
            u16::from_le_bytes(pe[opt..opt + 2].try_into().unwrap()),
            0x20b,
            "PE32+ (x86_64-unknown-uefi)"
        );
        let checksum = opt + 64;                                                        
        let security_dir = opt + 144;                                                                     
        let cert_off = u32le(pe, security_dir);
        let cert_size = u32le(pe, security_dir + 4);
                                                                                                
        let end = if cert_size > 0 { cert_off } else { pe.len() };
        let mut out = pe[..end].to_vec();
        out[checksum..checksum + 4].fill(0);
        out[security_dir..security_dir + 8].fill(0);
        out
    }

                                                                                                       
    /// `signingTime` auth attribute, so two signings are NOT byte-identical and signed-PE byte-determinism
    /// does NOT hold. Reproducibility is Authenticode-DIGEST equivalence instead — `signingTime` + the
    /// cert table + the checksum all live in hash-EXCLUDED regions. This asserts the REAL property:
    /// (1) two signings agree on every Authenticode-covered byte (so the signature is over stable content),
    /// and (2) the signed PE's covered bytes reproduce the UNSIGNED build (the §9.4-part-2 transparency
    /// property: anyone can rebuild the unsigned loader and confirm the signed boot PE wraps exactly it).
    #[test]
    #[ignore = "needs docker + the container (sbsign + a loader build); run via make boot-gate-uefi"]
    fn signed_pe_authenticode_bytes_reproduce_the_unsigned_build() {
        let tmp = tempfile::tempdir().unwrap();
        let genk = gen_opts(tmp.path());
        generate_secure_boot_keys(&genk).unwrap();
        let sb_dir = genk.keys_dir.join("secure-boot");
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")                                                           
            .canonicalize()
            .unwrap();
        let work = tempfile::tempdir().unwrap();
                                                                                                
                                                                                                          
                                                                                                            
                                                            
        let script = "set -e; \
             cd /repo/vendor/rambutan && \
             RECIPES_LOADER_DEV=1 CARGO_TARGET_DIR=/work/target CARGO_HOME=/work/cargo \
               cargo build --release --locked --target x86_64-unknown-uefi >/dev/null && \
             cp /work/target/x86_64-unknown-uefi/release/rambutan.efi /work/pe && \
             sbsign --key /sb/db.key --cert /sb/db.crt --output /work/signed1 /work/pe && \
             sbsign --key /sb/db.key --cert /sb/db.crt --output /work/signed2 /work/pe && \
             chmod -R a+r /work";
        let out = std::process::Command::new("docker")
            .args(["run", "--rm"])
            .args(["-v", &format!("{}:/repo:ro", repo_root.display())])
            .args(["-v", &format!("{}:/sb:ro", sb_dir.display())])
            .args(["-v", &format!("{}:/work", work.path().display())])
            .arg("recipes-imgbuild:dev")
            .args(["sh", "-c", script])
            .output()
            .expect("docker runs");
        assert!(
            out.status.success(),
            "container: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let s1 = std::fs::read(work.path().join("signed1")).unwrap();
        let s2 = std::fs::read(work.path().join("signed2")).unwrap();
        let unsigned = std::fs::read(work.path().join("pe")).unwrap();
        assert_eq!(&s1[0..2], b"MZ", "signed output is a PE");
        assert!(
            s1.len() > unsigned.len(),
            "the Authenticode cert table was appended"
        );
                                                                                                          
                                                                                                      
                                                                                                          
                                                   
        let (a1, a2, au) = (
            authenticode_covered_bytes(&s1),
            authenticode_covered_bytes(&s2),
            authenticode_covered_bytes(&unsigned),
        );
        assert_eq!(
            a1, a2,
            "two signings must agree on all Authenticode-covered bytes (signingTime lives in the excluded cert table)"
        );
        assert_eq!(
            a1, au,
            "the signed PE's Authenticode-covered bytes must reproduce the unsigned build (§9.4 transparency)"
        );
    }

    #[test]
    fn manifest_digest_mismatch_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let genk = gen_opts(tmp.path());
        generate_secure_boot_keys(&genk).unwrap();
                                                                                       
        let img = tmp.path().join("recipes-test.img");
        std::fs::write(&img, b"not really an image").unwrap();
        std::fs::write(tmp.path().join("recipes-test.loader.efi"), b"MZ-loader").unwrap();
        std::fs::write(tmp.path().join("recipes-test.vmlinuz"), b"MZ-kernel").unwrap();
        let manifest = SignManifest {
            loader: super::super::super::sign_sb::ManifestEntry {
                file: "recipes-test.loader.efi".into(),
                sha256: "0".repeat(64),                    
            },
            vmlinuz: super::super::super::sign_sb::ManifestEntry {
                file: "recipes-test.vmlinuz".into(),
                sha256: "0".repeat(64),
            },
        };
        std::fs::write(
            tmp.path().join("recipes-test.sign-manifest.toml"),
            toml::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let opts = sign_opts(tmp.path(), &img);
        let err = sign_sb(&opts).expect_err("digest mismatch refuses");
        assert!(
            matches!(err, SignSbError::ManifestDigestMismatch { .. }),
            "got {err:?}"
        );
    }
}
