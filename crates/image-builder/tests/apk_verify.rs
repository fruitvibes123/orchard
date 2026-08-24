//! Verify-against-genuine-apk tests (plan Task 1.2). The real Alpine 3.23 `musl` apk + the
//! three Alpine signing pubkeys are committed fixtures; the genuine apk is the authority.
//! `verify_apk` must ACCEPT the genuine package and REJECT every tampering class AT THE
//! CORRECT LAYER. Franken-apk tests prove the provenance layers (RSA-verify + datahash)
                                                                                           

use std::collections::HashMap;
use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use recipes_image_builder::{extract, verify_apk, AcquireError, PinnedPackage, TrustedKeys};

const MUSL_APK: &[u8] = include_bytes!("fixtures/musl-1.2.5-r23.apk");
const KEY_6165: &str = "alpine-devel@lists.alpinelinux.org-6165ee59";
const KEY_5261: &str = "alpine-devel@lists.alpinelinux.org-5261cecb";

fn trusted_keys() -> TrustedKeys {
    let mut k = HashMap::new();
    k.insert(
        "alpine-devel@lists.alpinelinux.org-4a6a0840".to_string(),
        include_bytes!("fixtures/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub").to_vec(),
    );
    k.insert(
        KEY_5261.to_string(),
        include_bytes!("fixtures/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub").to_vec(),
    );
    k.insert(
        KEY_6165.to_string(),
        include_bytes!("fixtures/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub").to_vec(),
    );
    k
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn musl_pin(sha256: String) -> PinnedPackage {
    PinnedPackage {
        name: "musl".to_string(),
        version: "1.2.5-r23".to_string(),
        sha256,
        signing_key: KEY_6165.to_string(),
    }
}

                                                                           

fn gzip(buf: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(buf).unwrap();
    e.finish().unwrap()
}

fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, content) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *content).unwrap();
    }
    b.into_inner().unwrap()
}

/// Split concatenated gzip members into their raw compressed-byte slices (mirrors the lib's
/// boundary tracking, so franken-apks can be assembled from genuine members).
fn split_members(apk: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < apk.len() {
        let mut rest: &[u8] = &apk[offset..];
        let before = rest.len();
        let mut dec = flate2::bufread::GzDecoder::new(&mut rest);
        let mut sink = Vec::new();
        if dec.read_to_end(&mut sink).is_err() {
            break;
        }
        drop(dec);
        let consumed = before - rest.len();
        if consumed == 0 {
            break;
        }
        out.push(apk[offset..offset + consumed].to_vec());
        offset += consumed;
    }
    out
}

/// The genuine RSA signature bytes from the apk's signature segment (the `.SIGN` record content).
fn genuine_sig_bytes() -> Vec<u8> {
    let m = split_members(MUSL_APK);
    let mut sig_seg = Vec::new();
    flate2::read::GzDecoder::new(&m[0][..])
        .read_to_end(&mut sig_seg)
        .unwrap();
    let mut ar = tar::Archive::new(&sig_seg[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    let mut sig = Vec::new();
    entry.read_to_end(&mut sig).unwrap();
    sig
}

                                               

#[test]
fn genuine_musl_apk_verifies() {
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let v = verify_apk(MUSL_APK, &pin, &trusted_keys());
    assert!(v.is_ok(), "genuine apk must verify: {:?}", v.err());
}

#[test]
fn wrong_content_hash_rejected() {
    let pin = musl_pin("0".repeat(64));
    assert!(matches!(
        verify_apk(MUSL_APK, &pin, &trusted_keys()),
        Err(AcquireError::ContentHash { .. })
    ));
}

                                                                                             

#[test]
fn bitflip_corrupts_gzip_member_so_decode_rejects() {
                                                                                       
                                                                                                
                                                                                    
    let mut tampered = MUSL_APK.to_vec();
    tampered[64] ^= 0xff;
    let pin = musl_pin(sha256_hex(&tampered));                                             
    assert!(matches!(
        verify_apk(&tampered, &pin, &trusted_keys()),
        Err(AcquireError::Format(_))
    ));
}

                                                                

#[test]
fn datahash_layer_rejects_swapped_data() {
                                                                                         
                                                                                                    
    let m = split_members(MUSL_APK);
    let swapped_data = gzip(&build_tar(&[("evil/payload", b"not the real musl")]));
    let franken = [m[0].clone(), m[1].clone(), swapped_data].concat();
    let pin = musl_pin(sha256_hex(&franken));
    assert!(matches!(
        verify_apk(&franken, &pin, &trusted_keys()),
        Err(AcquireError::DataHash(_))
    ));
}

                                                                                     

#[test]
fn signature_layer_rejects_forged_control() {
                                                                                                 
                                                                                              
                                                                                                     
    let m = split_members(MUSL_APK);
    let swapped_data = gzip(&build_tar(&[("evil/payload", b"not the real musl")]));
    let dh = sha256_hex(&swapped_data);
    let forged_control = gzip(&build_tar(&[(
        ".PKGINFO",
        format!("pkgname = evil\ndatahash = {dh}\n").as_bytes(),
    )]));
    let franken = [m[0].clone(), forged_control, swapped_data].concat();
    let pin = musl_pin(sha256_hex(&franken));
    assert!(matches!(
        verify_apk(&franken, &pin, &trusted_keys()),
        Err(AcquireError::Signature { .. })
    ));
}

                                                                  

#[test]
fn trusted_but_wrong_key_fails_rsa_verify() {
                                                                                                 
                                                                                               
                                                                                                
    let m = split_members(MUSL_APK);
    let renamed_sig = gzip(&build_tar(&[(
        ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
        &genuine_sig_bytes(),
    )]));
    let franken = [renamed_sig, m[1].clone(), m[2].clone()].concat();
    let mut pin = musl_pin(sha256_hex(&franken));
    pin.signing_key = KEY_5261.to_string();
    assert!(matches!(
        verify_apk(&franken, &pin, &trusted_keys()),
        Err(AcquireError::Signature { .. })
    ));
}

                                                                  

#[test]
fn signing_key_name_mismatch_rejected() {
    let mut pin = musl_pin(sha256_hex(MUSL_APK));
    pin.signing_key = "alpine-devel@lists.alpinelinux.org-deadbeef".to_string();
    assert!(matches!(
        verify_apk(MUSL_APK, &pin, &trusted_keys()),
        Err(AcquireError::Signature { .. })
    ));
}

                                               

#[test]
fn trailing_unsigned_bytes_rejected() {
    let mut franken = MUSL_APK.to_vec();
    franken.extend_from_slice(b"unsigned trailing junk, not a gzip member");
    let pin = musl_pin(sha256_hex(&franken));
    assert!(verify_apk(&franken, &pin, &trusted_keys()).is_err());
}

#[test]
fn extra_gzip_member_rejected() {
    let franken = [MUSL_APK.to_vec(), gzip(b"a fourth gzip member")].concat();
    let pin = musl_pin(sha256_hex(&franken));
    assert!(matches!(
        verify_apk(&franken, &pin, &trusted_keys()),
        Err(AcquireError::Format(_))
    ));
}

#[test]
fn truncated_apk_rejected() {
    let franken = &MUSL_APK[..MUSL_APK.len() / 2];
    let pin = musl_pin(sha256_hex(franken));
    assert!(verify_apk(franken, &pin, &trusted_keys()).is_err());
}

#[test]
fn empty_signature_segment_rejected() {
    let m = split_members(MUSL_APK);
    let franken = [gzip(&build_tar(&[])), m[1].clone(), m[2].clone()].concat();
    let pin = musl_pin(sha256_hex(&franken));
    assert!(matches!(
        verify_apk(&franken, &pin, &trusted_keys()),
        Err(AcquireError::Format(_))
    ));
}

                    

#[test]
fn extract_unpacks_data_files_only() {
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let verified = verify_apk(MUSL_APK, &pin, &trusted_keys()).expect("genuine apk verifies");
    let dir = std::env::temp_dir().join(format!("apk-extract-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    extract(&verified, &dir).expect("extract data tarball");
    assert!(
        dir.join("lib/libc.musl-x86_64.so.1").exists(),
        "expected libc in the extracted data tree"
    );
    assert!(dir.join("lib/ld-musl-x86_64.so.1").exists());
    assert!(
        !dir.join(".PKGINFO").exists(),
        ".PKGINFO must not be extracted"
    );
    std::fs::remove_dir_all(&dir).ok();
}

                                                                                           

#[test]
fn acquire_fetches_verifies_extracts() {
    use recipes_image_builder::{AlpineApkProvider, Fetcher, PackageProvider};

    struct Mock;
    impl Fetcher for Mock {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
                                                                                             
                                                                                                                    
            if url == "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/musl-1.2.5-r23.apk" {
                Ok(MUSL_APK.to_vec())
            } else {
                Err("HTTP 404".to_string())
            }
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Mock,
        drift_lookup: None,
    };
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let dir = std::env::temp_dir().join(format!("acquire-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    provider.acquire(&pin, &dir).expect("acquire genuine musl");
    assert!(dir.join("lib/libc.musl-x86_64.so.1").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn acquire_does_not_launder_tampered_main_through_community() {
                                                                                              
                                                                                               
                                                                                                
                                                                                         
                                                                                
    use recipes_image_builder::{AcquireError, AlpineApkProvider, Fetcher, PackageProvider};
    use std::cell::RefCell;

    struct Recording {
        seen: RefCell<Vec<String>>,
    }
    impl Fetcher for Recording {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.seen.borrow_mut().push(url.to_string());
            if url.contains("/main/") {
                let mut b = MUSL_APK.to_vec();
                b[5000] ^= 0xff;                       
                Ok(b)
            } else {
                Ok(MUSL_APK.to_vec())                                                  
            }
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Recording {
            seen: RefCell::new(Vec::new()),
        },
        drift_lookup: None,
    };
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let dir = std::env::temp_dir().join(format!("acquire-launder-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let r = provider.acquire(&pin, &dir);
    let extracted = dir.join("lib/libc.musl-x86_64.so.1").exists();
    let seen = provider.fetcher.seen.borrow().clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        matches!(r, Err(AcquireError::ContentHash { .. })),
        "tampered main must fail the content gate, got {r:?}"
    );
    assert_eq!(
        seen.len(),
        1,
        "must stop after main; community must not be tried: {seen:?}"
    );
    assert!(
        seen[0].contains("/main/"),
        "the one fetch is main: {seen:?}"
    );
    assert!(
        !extracted,
        "nothing may be extracted from an unverified download"
    );
}

#[test]
fn acquire_falls_back_to_community_when_main_404s() {
                                                                                                   
                                                                                        
    use recipes_image_builder::{AlpineApkProvider, Fetcher, PackageProvider};
    use std::cell::RefCell;

    struct Recording {
        seen: RefCell<Vec<String>>,
    }
    impl Fetcher for Recording {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.seen.borrow_mut().push(url.to_string());
            if url.contains("/main/") {
                Err("HTTP 404".to_string())
            } else {
                Ok(MUSL_APK.to_vec())
            }
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Recording {
            seen: RefCell::new(Vec::new()),
        },
        drift_lookup: None,
    };
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let dir = std::env::temp_dir().join(format!("acquire-fallback-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    provider
        .acquire(&pin, &dir)
        .expect("community fallback acquires");
    let extracted = dir.join("lib/libc.musl-x86_64.so.1").exists();
    let seen = provider.fetcher.seen.borrow().clone();
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(seen.len(), 2, "main then community: {seen:?}");
    assert!(
        seen[0].contains("/main/") && seen[1].contains("/community/"),
        "main first, then community: {seen:?}"
    );
    assert!(extracted, "verified community bytes must extract");
}

#[test]
fn acquire_errors_when_both_repos_fail() {
    use recipes_image_builder::{AcquireError, AlpineApkProvider, Fetcher, PackageProvider};

    struct AllMiss;
    impl Fetcher for AllMiss {
        fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
            Err("HTTP 404".to_string())
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: AllMiss,
        drift_lookup: None,
    };
    let pin = musl_pin(sha256_hex(MUSL_APK));
    let dir = std::env::temp_dir().join(format!("acquire-bothfail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let r = provider.acquire(&pin, &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        matches!(r, Err(AcquireError::Fetch(_))),
        "both repos fail -> Fetch, got {r:?}"
    );
}

                                                          

#[test]
fn pinned_apks_toml_parses_the_generated_closure() {
    use recipes_image_builder::PinnedApks;
    use std::collections::HashSet;
    let toml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/pinned-apks.toml"));
    let pins = PinnedApks::from_toml_str(toml).expect("pinned-apks.toml parses");
    assert_eq!(pins.alpine_version, "3.23");
                                                                                                      
    assert_eq!(
        pins.packages.len(),
        37,
        "resolved runtime closure size (services + the 2 app C-lib deps; -3 vs the s6-rc/s6-linux-init \
         era; +7 for the e2fsprogs-extra closure — resize2fs first-boot persist grow, O3 installer: \
         e2fsprogs + e2fsprogs-extra + e2fsprogs-libs + libblkid + libcom_err + libeconf + libuuid)"
    );
    assert_eq!(
        pins.build_inputs.len(),
        2,
        "build/boot inputs: linux-virt + syslinux"
    );

    let runtime: HashSet<&str> = pins.packages.iter().map(|p| p.name.as_str()).collect();
    let build_inputs: HashSet<&str> = pins.build_inputs.iter().map(|p| p.name.as_str()).collect();

                                                                                                     
                                                         
    assert!(
        runtime.contains("libcrypto3") && runtime.contains("libssl3"),
        "OpenSSL closure present"
    );
    assert!(!runtime.contains("libressl"), "libressl dropped (dead pin)");
                                                                                                    
                                                                               
    assert!(
        runtime.contains("libgcc") && runtime.contains("sqlite-libs"),
        "the app's musl binaries' link-deps must be in the closure"
    );
                                                                                       
    assert!(!runtime.contains("chrony"), "chrony dropped");
    assert!(
        !runtime.contains("gnutls"),
        "the gnutls/NTS stack is gone with chrony"
    );
                                            
    assert!(
        !runtime.contains("dropbear-ssh") && !runtime.contains("dropbear-dbclient"),
        "no SSH client (server-only)"
    );
                                                                                                    
                                                                                                       
    for cut in ["s6-rc", "s6-rc-libs", "s6-linux-init"] {
        assert!(
            !runtime.contains(cut),
            "{cut} dropped by the signed-exec init redesign"
        );
    }
                                                                                               
    assert_eq!(build_inputs, HashSet::from(["linux-virt", "syslinux"]));
    assert!(
        !runtime.contains("linux-virt") && !runtime.contains("syslinux"),
        "build-inputs must not appear in the rootfs closure"
    );

                                                        
    for p in pins.packages.iter().chain(pins.build_inputs.iter()) {
        assert_eq!(
            p.sha256.len(),
            64,
            "{}: sha256 must be 64 hex chars",
            p.name
        );
        assert!(
            p.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: sha256 must be hex",
            p.name
        );
        assert!(!p.signing_key.is_empty(), "{}: signing_key", p.name);
    }
}

                                                               

#[test]
fn acquire_404_names_the_drift_and_cure_when_the_hook_knows() {
    use recipes_image_builder::{AcquireError, AlpineApkProvider, Fetcher, PackageProvider};

    struct Always404;
    impl Fetcher for Always404 {
        fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
            Err("HTTP 404".to_string())
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Always404,
        drift_lookup: Some(Box::new(|name: &str| {
            (name == "linux-virt").then(|| "6.18.38-r0".to_string())
        })),
    };
    let pin = recipes_image_builder::PinnedPackage {
        name: "linux-virt".to_string(),
        version: "6.18.36-r0".to_string(),
        sha256: "aa".repeat(32),
        signing_key: "alpine-devel@lists.alpinelinux.org-6165ee59".to_string(),
    };
    let dir = std::env::temp_dir().join(format!("acquire-drift-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let err = provider.acquire(&pin, &dir).unwrap_err();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        matches!(err, AcquireError::Fetch(_)),
        "still a Fetch error: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("6.18.36-r0"),
        "names the pinned version: {msg}"
    );
    assert!(
        msg.contains("6.18.38-r0"),
        "names the mirror-current version: {msg}"
    );
    assert!(msg.contains("aged off"), "names the drift: {msg}");
    assert!(
        msg.contains("market upgrade --apks"),
        "names the cure: {msg}"
    );
    assert!(
        msg.contains("HTTP 404"),
        "the underlying fetch error is preserved, never masked: {msg}"
    );
}

#[test]
fn acquire_404_stays_plain_without_the_hook() {
    use recipes_image_builder::{AlpineApkProvider, Fetcher, PackageProvider};

    struct Always404;
    impl Fetcher for Always404 {
        fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
            Err("HTTP 404".to_string())
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Always404,
        drift_lookup: None,
    };
    let pin = recipes_image_builder::PinnedPackage {
        name: "linux-virt".to_string(),
        version: "6.18.36-r0".to_string(),
        sha256: "aa".repeat(32),
        signing_key: "alpine-devel@lists.alpinelinux.org-6165ee59".to_string(),
    };
    let dir = std::env::temp_dir().join(format!("acquire-plain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let err = provider.acquire(&pin, &dir).unwrap_err();
    std::fs::remove_dir_all(&dir).ok();

    let msg = err.to_string();
    assert!(
        msg.contains("linux-virt: HTTP 404"),
        "today's plain error shape: {msg}"
    );
    assert!(
        !msg.contains("aged off"),
        "no drift claim without the hook: {msg}"
    );
}

#[test]
fn acquire_404_stays_plain_when_the_hook_knows_nothing() {
                                                                                          
                                                                           
    use recipes_image_builder::{AlpineApkProvider, Fetcher, PackageProvider};

    struct Always404;
    impl Fetcher for Always404 {
        fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
            Err("HTTP 404".to_string())
        }
    }

    let provider = AlpineApkProvider {
        alpine_version: "3.23".to_string(),
        trusted_keys: trusted_keys(),
        fetcher: Always404,
        drift_lookup: Some(Box::new(|_| None)),
    };
    let pin = recipes_image_builder::PinnedPackage {
        name: "linux-virt".to_string(),
        version: "6.18.36-r0".to_string(),
        sha256: "aa".repeat(32),
        signing_key: "alpine-devel@lists.alpinelinux.org-6165ee59".to_string(),
    };
    let dir = std::env::temp_dir().join(format!("acquire-nodrift-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let err = provider.acquire(&pin, &dir).unwrap_err();
    std::fs::remove_dir_all(&dir).ok();
    let msg = err.to_string();
    assert!(msg.contains("linux-virt: HTTP 404"), "plain shape: {msg}");
    assert!(!msg.contains("aged off"), "{msg}");
}
