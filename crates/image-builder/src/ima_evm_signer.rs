                                                                      
//!
//! Replaces the `evmctl` build-signing call with RFC-6979 ECDSA-P256 so the `security.ima` /
//! `security.evm` xattrs are **byte-identical run-to-run** — the last rootfs non-determinism source.
//! evmctl's OpenSSL path randomizes the ECDSA nonce (OpenSSL <3.2 has no RFC-6979 mode; 3.2+ needs a
//! per-op signature param evmctl never sets), so its sigs differ each build. RustCrypto's `Signer`
//! derives the nonce by RFC-6979 (HMAC over key+message, no RNG) → the same key+file always yields the
//! same signature bytes. evmctl is retained ONLY as the differential-test oracle ([`crate::ima_evm`]).
//!
                                                                                                        
//! Both xattrs are a `struct signature_v2_hdr` (`security/integrity/integrity.h:92`), big-endian:
//! `type:u8 ‖ version:u8 ‖ hash_algo:u8 ‖ keyid:be32 ‖ sig_size:be16 ‖ sig[]`.
//! - `version = 2` (asymmetric-key sig, regular file-data hash).
//! - `hash_algo = HASH_ALGO_SHA256 = 4` (`include/uapi/linux/hash_info.h`: MD4=0,MD5,SHA1,RIPEMD160,SHA256).
//! - `security.ima`: `type = EVM_IMA_XATTR_DIGSIG = 0x03`; the kernel verifies the sig over the file's
//!   content hash, so we ECDSA-sign `sha256(content)`.
//! - `security.evm` (portable): `type = EVM_XATTR_PORTABLE_DIGSIG = 0x05`; we sign the *portable EVM hash*.
//! - `sig`: ECDSA as an ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` — the kernel's
//!   `crypto/ecdsasignature.asn1` template (`to_der()` emits exactly this; evmctl/OpenSSL too).
//!
//! ### portable-EVM hash (`evm_crypto.c::evm_calc_hmac_or_hash`, type == PORTABLE_DIGSIG)
//! A **plain SHA-256** (not the HMAC — `init_desc` keys the tfm only for `EVM_XATTR_HMAC`) over, in
//! `evm_config_default_xattrnames` order (`evm_main.c:38` — selinux, SMACK64{,EXEC,TRANSMUTE,MMAP},
//! apparmor, **ima**, **capability**), the VALUE bytes of every **present** protected xattr, then a
//! `struct h_misc`. On the box only `security.ima` (always — portable EVM *requires* an IMA hash, else
//! `evm_calc_hmac_or_hash` returns `-EPERM`) and, iff the file carries file-caps, `security.capability`
//! are present (no SELinux/SMACK/AppArmor); `ima` precedes `capability` in the list.
//!
//! `h_misc` (`hmac_add_misc`) is `{ unsigned long ino; __u32 generation; uid_t uid; gid_t gid; umode_t
//! mode; }` → on x86-64 **24 bytes** (8+4+4+4+2, struct-aligned to 8 ⇒ 2 trailing pad), `memset` 0.
//! For PORTABLE, `ino`+`generation` stay 0 and the FSUUID is skipped. `uid`/`gid` are the inode's
//! baked owner — `0:0` for every inode except manifest-declared exceptions (the
//! [`crate::ownership::OwnershipMap`]) — matching the ids mksquashfs stamps into the image, which is
//! what the kernel hashes at boot. `mode` is the file's `st_mode`. The 2 trailing pad bytes are part
//! of `sizeof(hmac_misc)` and hashed (zeroed).
//!
//! ### keyid (`be32`)
//! At verify the kernel finds the key via `request_asymmetric_key` → `"id:%08x"` → a SUFFIX match
//! (`asymmetric_type.c::asymmetric_key_id_partial`: `memcmp(kid->data + (kid->len - 4), match, 4)`)
//! against the cert's `id[0]`/`id[1]`, and `id[1] = cert->skid` (`x509_public_key.c:204`). So
//! **keyid = the last 4 bytes of the IMA leaf cert's SubjectKeyIdentifier extension**, written in
//! cert order (the `be32`/`ntohl`/`%08x`/`hex2bin` round-trip reconstructs those same 4 bytes for the
//! memcmp). This is independent of evmctl's own keyid convention — we use the SKID the kernel uses.
//!
//! Empirical fidelity (that our bytes match what the kernel appraises) is closed by the in-container
//! evmctl differential test + the QEMU boot gate; this module is source-grounded, not yet QEMU-proven.

use std::path::Path;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use x509_parser::prelude::*;

use crate::ownership::OwnershipMap;

const SIG_VERSION: u8 = 2;
const HASH_ALGO_SHA256: u8 = 4;
const EVM_IMA_XATTR_DIGSIG: u8 = 0x03;
const EVM_XATTR_PORTABLE_DIGSIG: u8 = 0x05;

/// Size of `struct h_misc` on x86-64 (the box's arch): 8(ino)+4(gen)+4(uid)+4(gid)+2(mode)+2(pad).
const H_MISC_LEN: usize = 24;

/// `S_IFMT`/`S_IFREG`: a map inode gets `security.ima`/`security.evm` `x` lines iff it is a regular
                                                                                                     
/// appraises every root-owned (`fowner=0`) BPRM exec + the build can't predict at staging which files
/// get exec'd, so the sign-scope MUST be a SUPERSET of the appraised-scope — a path/exec-bit heuristic
/// could miss a service binary staged without `+x` → unsigned-but-appraised → `-EACCES` lockout.
/// Over-signing non-exec'd data is harmless: a `security.ima` sig is only checked on exec/mmap, never
/// on plain reads (the policy is BPRM/MMAP, not FILE_CHECK). Symlinks/dirs carry only the `m` line.
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("load IMA signing key (PKCS#8 PEM): {0}")]
    KeyLoad(String),
    #[error("parse IMA cert DER: {0}")]
    CertParse(String),
    #[error(
        "IMA cert has no SubjectKeyIdentifier extension (the kernel keyid match needs id[1]=skid)"
    )]
    NoSkid,
    #[error("IMA cert SubjectKeyIdentifier is shorter than 4 bytes")]
    SkidTooShort,
    #[error("ECDSA sign: {0}")]
    Sign(String),
    #[error("read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "staged file {path:?} carries an unexpected protected xattr {xattr:?}: the portable-EVM \
         hash covers only security.ima + security.capability on this box (no SELinux/SMACK/AppArmor \
         LSM) — hashing it would mismatch the kernel's EVM hash and lock out boot"
    )]
    UnexpectedProtectedXattr { path: String, xattr: String },
}

/// The two xattr values to write on a file.
pub struct SignedXattrs {
    /// `security.ima` value.
    pub ima: Vec<u8>,
    /// `security.evm` value.
    pub evm: Vec<u8>,
}

/// A loaded IMA/EVM signing key + the kernel keyid derived from its leaf cert.
pub struct ImaEvmSigner {
    key: SigningKey,
    keyid: [u8; 4],
}

impl ImaEvmSigner {
    /// Load the IMA leaf key (PKCS#8 PEM, as `rcgen`'s `serialize_pem` writes `ima.key`) and derive
    /// the `be32` keyid from the leaf cert's SubjectKeyIdentifier (`cert_der` = `ima.crt` DER).
    pub fn new(key_pem: &str, cert_der: &[u8]) -> Result<Self, SignError> {
        let secret = p256::SecretKey::from_pkcs8_pem(key_pem)
            .map_err(|e| SignError::KeyLoad(e.to_string()))?;
        let key = SigningKey::from(&secret);
        let keyid = keyid_from_skid(cert_der)?;
        Ok(Self { key, keyid })
    }

    /// The `be32` keyid bytes (last 4 of the leaf cert SKID), as written into the header.
    pub fn keyid(&self) -> [u8; 4] {
        self.keyid
    }

    /// RFC-6979 deterministic ECDSA over `message` (the signer SHA-256's it), DER-encoded.
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
                                                                                                        
                                                                                                     
        let sig: Signature = self
            .key
            .try_sign(message)
            .map_err(|e| SignError::Sign(e.to_string()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// `security.ima` value: `signature_v2_hdr(0x03)` over `sha256(content)`.
    pub fn ima_xattr(&self, content: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig = self.sign_der(content)?;
        Ok(frame(EVM_IMA_XATTR_DIGSIG, &self.keyid, &sig))
    }

    /// `security.evm` portable value: `signature_v2_hdr(0x05)` over the portable EVM hash. `ima_xattr`
    /// is the `security.ima` value just produced (it is the first protected xattr); `security_capability`
    /// is the file's existing cap xattr (or `None`); `(uid, gid)` is the inode's baked owner (from the
    /// [`crate::ownership::OwnershipMap`]); `mode` is its `st_mode`.
    pub fn evm_portable_xattr(
        &self,
        ima_xattr: &[u8],
        security_capability: Option<&[u8]>,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<Vec<u8>, SignError> {
        let cap_len = security_capability.map_or(0, <[u8]>::len);
        let mut msg = Vec::with_capacity(ima_xattr.len() + cap_len + H_MISC_LEN);
                                                                                                      
        msg.extend_from_slice(ima_xattr);
        if let Some(cap) = security_capability {
            msg.extend_from_slice(cap);
        }
        msg.extend_from_slice(&h_misc(uid, gid, mode));
        let sig = self.sign_der(&msg)?;
        Ok(frame(EVM_XATTR_PORTABLE_DIGSIG, &self.keyid, &sig))
    }

    /// Compute both xattr values for a staged regular file: read its content + existing
    /// `security.capability` (host-side getxattr, no privilege), then sign as `(uid, gid, mode)` —
    /// the file's baked owner AND full `st_mode` from the [`crate::ownership::OwnershipMap`]
                                                                                                  
    /// and the signed `h_misc` mode cannot diverge).
    pub fn sign_file(
        &self,
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<SignedXattrs, SignError> {
        let io = |source| SignError::Io {
            path: path.display().to_string(),
            source,
        };
        let content = std::fs::read(path).map_err(io)?;
                                                                                                
                                                                                               
                                                                                                
        let cap = xattr::get(path, "security.capability").map_err(io)?;
                                                                                                         
                                                                                                          
        let names: Vec<String> = xattr::list(path)
            .map_err(io)?
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        reject_unexpected_protected_xattr(path, &names)?;
        let ima = self.ima_xattr(&content)?;
        let evm = self.evm_portable_xattr(&ima, cap.as_deref(), uid, gid, mode)?;
        Ok(SignedXattrs { ima, evm })
    }
}

/// I-2 (R1 audit): the portable-EVM hash covers ONLY `security.ima` + `security.capability` on this
/// box (no SELinux/SMACK/AppArmor LSM). Any OTHER protected `security.*` xattr on a staged file would
/// be hashed by the kernel's EVM but NOT by our preimage → a boot appraisal mismatch with NO build
/// signal. Reject it at sign time so the assumption is self-enforcing. (`security.ima`/`security.evm`
/// are computed + injected at pack time, never on the staging file here — so they're "unexpected" too.)
fn reject_unexpected_protected_xattr(path: &Path, names: &[String]) -> Result<(), SignError> {
    for n in names {
        if n.starts_with("security.") && n != "security.capability" {
            return Err(SignError::UnexpectedProtectedXattr {
                path: path.display().to_string(),
                xattr: n.clone(),
            });
        }
    }
    Ok(())
}

/// Assemble a `signature_v2_hdr`: `type ‖ version=2 ‖ sha256 ‖ keyid(be32) ‖ sig_size(be16) ‖ sig`.
fn frame(xattr_type: u8, keyid: &[u8; 4], sig_der: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + sig_der.len());
    v.push(xattr_type);
    v.push(SIG_VERSION);
    v.push(HASH_ALGO_SHA256);
    v.extend_from_slice(keyid);
    v.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
    v.extend_from_slice(sig_der);
    v
}

/// `struct h_misc` for a PORTABLE signature: 24 bytes, ino=gen=0, `uid`/`gid` (`__u32`, LE) at offsets
/// 12/16, `mode` (`umode_t`=u16, LE) at offset 20, 2 trailing pad. Native little-endian (x86-64). The
/// `(uid, gid)` are the inode's baked owner (the [`crate::ownership::OwnershipMap`]) — the same ids the
/// kernel reads from the squashfs inode at boot; a mismatch fails EVM appraisal.
fn h_misc(uid: u32, gid: u32, mode: u32) -> [u8; H_MISC_LEN] {
    let mut b = [0u8; H_MISC_LEN];
    b[12..16].copy_from_slice(&uid.to_le_bytes());
    b[16..20].copy_from_slice(&gid.to_le_bytes());
    b[20..22].copy_from_slice(&((mode & 0xffff) as u16).to_le_bytes());
    b
}

/// Last 4 bytes of the cert's SubjectKeyIdentifier extension = the `be32` keyid (kernel `id[1]` suffix).
fn keyid_from_skid(cert_der: &[u8]) -> Result<[u8; 4], SignError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| SignError::CertParse(e.to_string()))?;
    let skid = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
            _ => None,
        })
        .ok_or(SignError::NoSkid)?;
    if skid.len() < 4 {
        return Err(SignError::SkidTooShort);
    }
    let mut id = [0u8; 4];
    id.copy_from_slice(&skid[skid.len() - 4..]);
    Ok(id)
}

/// Render a **mksquashfs `-pf` pseudo-file** from the [`OwnershipMap`]: for **every** inode under
/// `staging`, a **mode-first** ownership line `"/<path> m <mode & 0o7777> <uid> <gid>"`; and, for each
/// **regular file**, the two extended-attribute lines `"/<path> x security.ima=0s<base64>"` +
/// `"… security.evm=…"`, signed with that inode's **map owner** (never the staging owner — D3/F-9).
/// mksquashfs injects all of these into the image (no live setxattr, hence no CAP_SYS_ADMIN); dropping
/// `-all-root` (the `Ownership::Map` pack, [`crate::squashfs`]) lets the `m` lines set ownership per
/// inode. The map is already sorted (`BTreeMap`), type-allowlisted, and whitespace-rejected at
/// [`OwnershipMap::build`], so this is a pure emit → the manifest is byte-reproducible (D5/U-2). The
/// `m`-line masks `& 0o7777` (perm+special bits); `h_misc` gets the FULL `st_mode` — BOTH from the
                                                                                                   
                                                                                                        
///
/// **The staging ROOT inode is deliberately NOT emitted.** mksquashfs 4.7.4 cannot modify the root via
/// `-pf` — `/ m …` → "is not a directory. Ignoring!", and `.`/`""` are rejected too (verified
/// empirically in the pinned container). `pack_squashfs` (the `Map` path) forces the root to `0:0`
/// in-container instead — what `-all-root` did for it, and what D5 byte-identity requires.
///
/// **Values are `0s<base64>`, NOT `0x<hex>` — load-bearing.** mksquashfs 4.7.4's `0x` pseudo-xattr
/// parser SEGFAULTs (SIGSEGV) on any value over 8 bytes (empirically: 16 hex OK, ≥32 hex crashes),
/// which our ~80-byte framed sigs always exceed; the `0s` base64 path is robust (validated to 200 B ×
/// 3000 entries). Do NOT "simplify" this back to `0x` — it reintroduces a hard build crash.
pub fn pseudo_manifest(
    staging: &Path,
    signer: &ImaEvmSigner,
    map: &OwnershipMap,
) -> Result<String, SignError> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = String::new();
    for (rel, owner) in map.iter() {
        let rel_str = rel.to_string_lossy();
                                                                                          
        out.push_str(&format!(
            "/{rel_str} m {:o} {} {}\n",
            owner.mode & 0o7777,
            owner.uid,
            owner.gid
        ));
                                                                                                      
                                                                                           
        if owner.mode & S_IFMT == S_IFREG {
            let x = signer.sign_file(&staging.join(rel), owner.uid, owner.gid, owner.mode)?;
            out.push_str(&format!(
                "/{rel_str} x security.ima=0s{}\n",
                b64.encode(&x.ima)
            ));
            out.push_str(&format!(
                "/{rel_str} x security.evm=0s{}\n",
                b64.encode(&x.evm)
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::OwnerException;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A throwaway SKID-bearing P-256 self-signed cert + PKCS#8 PEM key for the signer tests (rcgen,
    /// ring backend). Returns (key_pem, cert_der). (NOT a production-shape mirror — see the body comment.)
    fn test_keypair() -> (String, Vec<u8>) {
        let mut params =
            rcgen::CertificateParams::new(vec!["recipes-ima-test".to_string()]).unwrap();
                                                                                                 
                                                                                                        
                                                                                               
                                                                                               
                                                                                                               
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (kp.serialize_pem(), cert.der().to_vec())
    }

    #[test]
    fn h_misc_is_24_bytes_mode_at_20_le_rest_zero() {
        let m = h_misc(0, 0, 0o100644);                                       
        assert_eq!(m.len(), 24);
        assert_eq!(&m[20..22], &0x81A4u16.to_le_bytes());                
        assert!(m[..20].iter().all(|&b| b == 0), "ino/gen/uid/gid zeroed");
        assert_eq!(&m[22..24], &[0, 0], "trailing pad zeroed");
    }

    #[test]
    fn h_misc_places_uid_gid_mode_at_the_kernel_offsets() {
        let b = h_misc(0x11223344, 0x55667788, 0o100_644);
        assert_eq!(
            &b[12..16],
            &0x11223344u32.to_le_bytes(),
            "uid at [12..16] LE"
        );
        assert_eq!(
            &b[16..20],
            &0x55667788u32.to_le_bytes(),
            "gid at [16..20] LE"
        );
        assert_eq!(
            &b[20..22],
            &((0o100_644u32 & 0xffff) as u16).to_le_bytes(),
            "mode at [20..22] LE"
        );
        assert_eq!(&b[0..12], &[0u8; 12], "ino+gen zero for portable");
        assert_eq!(b.len(), 24);
    }

                                                                                                   
                                                                                                     
                                                                                                         
                                                                                                           
                                                                                                       
    #[test]
    fn h_misc_zero_owner_is_byte_identical_to_the_old_hardcoded_layout() {
        for mode in [0o100_644u32, 0o100_755, 0o040_755, 0o120_777] {
            let mut old = [0u8; H_MISC_LEN];
            old[20..22].copy_from_slice(&((mode & 0xffff) as u16).to_le_bytes());
            assert_eq!(
                h_misc(0, 0, mode),
                old,
                "0:0 h_misc must equal the pre-change layout for mode {mode:#o}"
            );
        }
    }

    #[test]
    fn header_framing_layout_is_be_and_typed() {
        let keyid = [0xDE, 0xAD, 0xBE, 0xEF];
        let sig = vec![0xAB; 70];
        let h = frame(EVM_IMA_XATTR_DIGSIG, &keyid, &sig);
        assert_eq!(h[0], 0x03, "security.ima type");
        assert_eq!(h[1], 2, "version 2");
        assert_eq!(h[2], 4, "HASH_ALGO_SHA256");
        assert_eq!(&h[3..7], &keyid, "keyid be32, cert order");
        assert_eq!(&h[7..9], &70u16.to_be_bytes(), "sig_size be16");
        assert_eq!(&h[9..], &sig[..]);
                                           
        let e = frame(EVM_XATTR_PORTABLE_DIGSIG, &keyid, &sig);
        assert_eq!(e[0], 0x05, "portable security.evm type");
    }

    #[test]
    fn keyid_is_last_four_of_cert_skid() {
        let (_pem, der) = test_keypair();
        let our = keyid_from_skid(&der).expect("rcgen emits a SubjectKeyIdentifier");
                                                                  
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let skid = cert
            .extensions()
            .iter()
            .find_map(|x| match x.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
            .unwrap();
        assert_eq!(our.to_vec(), skid[skid.len() - 4..].to_vec());
    }

    #[test]
    fn signatures_are_deterministic_rfc6979() {
        let (pem, der) = test_keypair();
        let s = ImaEvmSigner::new(&pem, &der).unwrap();
        let content = b"#!/bin/sh\nexec /usr/bin/recipes\n";
        let a = s.ima_xattr(content).unwrap();
        let b = s.ima_xattr(content).unwrap();
        assert_eq!(
            a, b,
            "IMA xattr byte-identical across calls (the whole point of R.4)"
        );
        let ea = s.evm_portable_xattr(&a, None, 0, 0, 0o100755).unwrap();
        let eb = s.evm_portable_xattr(&b, None, 0, 0, 0o100755).unwrap();
        assert_eq!(ea, eb, "EVM xattr byte-identical across calls");
    }

    #[test]
    fn ima_signature_verifies_over_content_hash() {
        let (pem, der) = test_keypair();
        let s = ImaEvmSigner::new(&pem, &der).unwrap();
        let content = b"hello recipes";
        let xattr = s.ima_xattr(content).unwrap();
                                                                                                         
        let sig_der = &xattr[9..];
        let sig = Signature::from_der(sig_der).expect("framed sig is DER SEQUENCE{r,s}");
        let secret = p256::SecretKey::from_pkcs8_pem(&pem).unwrap();
        let vk = VerifyingKey::from(secret.public_key());
        vk.verify(content, &sig)
            .expect("IMA sig verifies over the file content (== sha256(content))");
    }

    #[test]
    fn evm_signature_verifies_over_portable_preimage() {
        let (pem, der) = test_keypair();
        let s = ImaEvmSigner::new(&pem, &der).unwrap();
        let ima = s.ima_xattr(b"x").unwrap();
        let mode = 0o100644u32;
        let evm = s.evm_portable_xattr(&ima, None, 0, 0, mode).unwrap();
                                                                                                           
        let mut preimage = ima.clone();
        preimage.extend_from_slice(&h_misc(0, 0, mode));
        let sig = Signature::from_der(&evm[9..]).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(&pem).unwrap();
        let vk = VerifyingKey::from(secret.public_key());
        vk.verify(&preimage, &sig)
            .expect("EVM sig verifies over (security.ima ‖ h_misc)");
    }

    #[test]
    fn reject_unexpected_protected_xattr_self_enforces_the_evm_assumption() {
        let p = std::path::Path::new("/staging/bin/x");
                                                         
        assert!(reject_unexpected_protected_xattr(
            p,
            &["security.capability".into(), "user.foo".into()]
        )
        .is_ok());
                                                                          
        assert!(matches!(
            reject_unexpected_protected_xattr(p, &["security.selinux".into()]),
            Err(SignError::UnexpectedProtectedXattr { .. })
        ));
                                                                                                       
        assert!(reject_unexpected_protected_xattr(p, &["security.ima".into()]).is_err());
    }

    #[test]
    fn evm_hash_folds_security_capability_after_ima() {
                                                                                                 
                                                                                                   
                                                                                                     
                                                                                               
                                                                                                        
                                                              
        let (pem, der) = test_keypair();
        let s = ImaEvmSigner::new(&pem, &der).unwrap();
        let ima = s.ima_xattr(b"a-capable-binary").unwrap();
                                                                                     
        let cap: &[u8] = &[
            1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mode = 0o100755u32;
        let evm = s.evm_portable_xattr(&ima, Some(cap), 0, 0, mode).unwrap();
                                                                                                  
        let mut preimage = ima.clone();
        preimage.extend_from_slice(cap);
        preimage.extend_from_slice(&h_misc(0, 0, mode));
        let sig = Signature::from_der(&evm[9..]).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(&pem).unwrap();
        let vk = VerifyingKey::from(secret.public_key());
        vk.verify(&preimage, &sig)
            .expect("EVM sig verifies over (security.ima ‖ security.capability ‖ h_misc)");
        assert_ne!(
            evm,
            s.evm_portable_xattr(&ima, None, 0, 0, mode).unwrap(),
            "security.capability is folded into the EVM hash (different sig than the no-cap case)"
        );
    }

    #[test]
    fn pseudo_manifest_emits_m_for_every_inode_x_for_regular_files_sorted_and_deterministic() {
        let (pem, der) = test_keypair();
        let signer = ImaEvmSigner::new(&pem, &der).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
        std::fs::write(dir.path().join("usr/bin/recipes"), b"\x7fELFfake").unwrap();
        std::fs::write(dir.path().join("etc.conf"), b"k=v").unwrap();
                                                                                                  
        std::os::unix::fs::symlink("usr/bin/recipes", dir.path().join("link")).unwrap();
        let map = OwnershipMap::build(dir.path(), &[]).unwrap();
        let m = pseudo_manifest(dir.path(), &signer, &map).unwrap();

                                                                                                    
                                                
        for p in ["/etc.conf", "/link", "/usr", "/usr/bin", "/usr/bin/recipes"] {
            let n = m
                .lines()
                .filter(|l| l.starts_with(&format!("{p} m ")))
                .count();
            assert_eq!(n, 1, "one m-line for {p}, got:\n{m}");
        }
                                                                                       
        assert!(m.contains("/etc.conf x security.ima=0s"), "got:\n{m}");
        assert!(m.contains("/etc.conf x security.evm=0s"));
        assert!(m.contains("/usr/bin/recipes x security.ima=0s"));
        assert!(m.contains("/usr/bin/recipes x security.evm=0s"));
        assert!(!m.contains("/link x security."), "symlink not signed");
        assert!(!m.contains("/usr x security."), "dir not signed");
        assert!(!m.contains("/usr/bin x security."), "dir not signed");
                                                                                
        assert_eq!(
            m,
            pseudo_manifest(dir.path(), &signer, &map).unwrap(),
            "manifest is reproducible"
        );
    }

    #[test]
    fn pseudo_emits_mode_first_m_lines_from_the_map() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("box.json"), b"{}").unwrap();
        std::fs::set_permissions(
            dir.path().join("box.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let (pem, der) = test_keypair();
        let signer = ImaEvmSigner::new(&pem, &der).unwrap();
        let map = OwnershipMap::build(
            dir.path(),
            &[OwnerException {
                rel_path: "box.json".into(),
                uid: 5000,
                gid: 5000,
            }],
        )
        .unwrap();
        let out = pseudo_manifest(dir.path(), &signer, &map).unwrap();
                                                                           
        assert!(out.contains("/box.json m 600 5000 5000"), "got:\n{out}");
                                                                                      
        assert!(out.contains("/box.json x security.ima=0s"), "got:\n{out}");
        assert!(out.contains("/box.json x security.evm=0s"), "got:\n{out}");
    }

    #[test]
    fn pseudo_emits_root_owned_m_for_default_inodes_but_no_slash_root_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        std::fs::set_permissions(
            dir.path().join("etc"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let (pem, der) = test_keypair();
        let signer = ImaEvmSigner::new(&pem, &der).unwrap();
        let map = OwnershipMap::build(dir.path(), &[]).unwrap();
        let out = pseudo_manifest(dir.path(), &signer, &map).unwrap();
        assert!(out.contains("/etc m 755 0 0"), "got:\n{out}");
                                                                                                
                                                                                                     
        for line in out.lines() {
            assert!(!line.starts_with("/ m "), "no root `/ m` line, got: {line}");
        }
    }

                                                                                                
    /// pinned Alpine container with the reference `evmctl` (the impl the kernel demonstrably accepts),
    /// read their `security.ima`/`security.evm` back host-side, and prove OUR hash constructions match
    /// what evmctl signed — without which the box would fail-closed at boot. Load-bearing checks:
    ///   (1) evmctl's IMA sig verifies over `CONTENT`  ⇒ our IMA signed-data (= sha256(content)) is right.
    ///   (2) evmctl's EVM sig verifies over `evmctl's security.ima ‖ our h_misc(0,0,mode)`  ⇒ our portable
    ///       -EVM pre-image (xattr ordering + the 24-byte h_misc layout) is byte-exact for a `0:0` file.
                                                                                                            
    ///       real uid/gid at the kernel offsets (the `0:0` leg can't — its uid/gid bytes are zero either way).
    /// Then our signer reproduces the framing + a deterministic signature set. Run with:
    ///   `cargo test -p recipes-image-builder differential_against_evmctl -- --ignored --nocapture`
    #[test]
    #[ignore = "needs docker + CAP_SYS_ADMIN + recipes-imgbuild:dev; the evmctl fidelity oracle"]
    fn differential_against_evmctl_in_container() {
        use std::process::Command;
        const IMAGE: &str = "recipes-imgbuild:dev";
                                                                                           
        const CONTENT: &str = "recipes-ima-evm-differential-test";

                                                                                                    
                                                                                                     
        let (key_pem, cert_der) = test_keypair();
        let keydir = tempfile::tempdir().unwrap();
        std::fs::write(keydir.path().join("ima.key"), &key_pem).unwrap();
        let staging = tempfile::tempdir().unwrap();

                                                                                                      
                                                                                                         
                                                                                                        
        let flags_f =
            crate::ima_evm::evmctl_sign_argv(Path::new("/k/ima.key"), Path::new("/staging/f"));
        let flags_g =
            crate::ima_evm::evmctl_sign_argv(Path::new("/k/ima.key"), Path::new("/staging/g"));
        let script = format!(
            "set -e; \
             printf '%s' '{CONTENT}' > /staging/f; chmod 644 /staging/f; evmctl {}; \
             printf '%s' '{CONTENT}' > /staging/g; chmod 600 /staging/g; chown 5000:5000 /staging/g; evmctl {}",
            flags_f.join(" "),
            flags_g.join(" ")
        );
        let status = Command::new("docker")
            .args(["run", "--rm", "--cap-add", "SYS_ADMIN", "-v"])
            .arg(format!("{}:/staging", staging.path().display()))
            .arg("-v")
            .arg(format!("{}:/k:ro", keydir.path().display()))
            .args([IMAGE, "sh", "-c", &script])
            .status()
            .expect("docker run");
        assert!(status.success(), "evmctl reference signing in-container");

        let file = staging.path().join("f");
        let ev_ima = xattr::get(&file, "security.ima")
            .unwrap()
            .expect("evmctl wrote security.ima");
        let ev_evm = xattr::get(&file, "security.evm")
            .unwrap()
            .expect("evmctl wrote portable security.evm");
        let mode = std::fs::symlink_metadata(&file).unwrap().mode();

                                                       
        assert_eq!(
            [ev_ima[0], ev_ima[1], ev_ima[2]],
            [0x03, 2, 4],
            "evmctl security.ima framing"
        );
        assert_eq!(
            [ev_evm[0], ev_evm[1], ev_evm[2]],
            [0x05, 2, 4],
            "evmctl portable security.evm framing"
        );

        let secret = p256::SecretKey::from_pkcs8_pem(&key_pem).unwrap();
        let vk = VerifyingKey::from(secret.public_key());

                                        
        let ev_ima_sig =
            Signature::from_der(&ev_ima[9..]).expect("evmctl IMA sig is DER SEQUENCE{r,s}");
        vk.verify(CONTENT.as_bytes(), &ev_ima_sig)
            .expect("our IMA hash (sha256 of content) == what evmctl signed");

                                                                                        
        let mut evm_preimage = ev_ima.clone();
        evm_preimage.extend_from_slice(&h_misc(0, 0, mode));
        let ev_evm_sig = Signature::from_der(&ev_evm[9..]).expect("evmctl EVM sig is DER");
        vk.verify(&evm_preimage, &ev_evm_sig)
            .expect("our portable-EVM pre-image (security.ima ‖ h_misc) == what evmctl signed == the kernel");

                                                                                                      
                                                                                                         
                                                                                                
        let g = staging.path().join("g");
        let g_meta = std::fs::symlink_metadata(&g).unwrap();
        assert_eq!(
            (g_meta.uid(), g_meta.gid()),
            (5000, 5000),
            "g staged owner 5000:5000"
        );
        let g_ima = xattr::get(&g, "security.ima")
            .unwrap()
            .expect("evmctl wrote g security.ima");
        let g_evm = xattr::get(&g, "security.evm")
            .unwrap()
            .expect("evmctl wrote g portable security.evm");
        let mut g_preimage = g_ima.clone();
        g_preimage.extend_from_slice(&h_misc(5000, 5000, g_meta.mode()));
        let g_evm_sig = Signature::from_der(&g_evm[9..]).expect("evmctl g EVM sig is DER");
        vk.verify(&g_preimage, &g_evm_sig)
            .expect("our h_misc(5000,5000,mode) matches evmctl for a non-zero-uid file");

                                                                                              
                                                                                                    
                                                                                                     
                                                                                               
                                                                                                   
                                                                                                  
                                                                                                 
        let signer = ImaEvmSigner::new(&key_pem, &cert_der).unwrap();
        let clean_dir = tempfile::tempdir().unwrap();
        let clean = clean_dir.path().join("f");
        std::fs::write(&clean, CONTENT.as_bytes()).unwrap();
        std::fs::set_permissions(&clean, std::fs::Permissions::from_mode(0o644)).unwrap();
                                                                                                     
        let clean_mode = std::fs::symlink_metadata(&clean).unwrap().mode();
        let mine = signer.sign_file(&clean, 0, 0, clean_mode).unwrap();
        assert_eq!(
            &mine.ima[0..3],
            &ev_ima[0..3],
            "our IMA framing matches evmctl"
        );
        assert_eq!(
            &mine.evm[0..3],
            &ev_evm[0..3],
            "our EVM framing matches evmctl"
        );
        assert_eq!(
            &mine.ima[3..7],
            &signer.keyid(),
            "our keyid is the cert SKID suffix (kernel id[1])"
        );
        let again = signer.sign_file(&clean, 0, 0, clean_mode).unwrap();
        assert_eq!(mine.ima, again.ima, "deterministic IMA xattr");
        assert_eq!(mine.evm, again.evm, "deterministic EVM xattr");
    }
}
