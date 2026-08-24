//! Offline rescue/runtime host-key precompute (operator-host TOFU known_hosts).
//!
//! Lifted from `recipes`' `box_oneshots::rescue_keys` offline mode (OS-extraction
                                                                                    
//! baked seed from the rootfs squashfs, recomputes the dm-verity root hash (the runtime
//! HKDF nonce), and derives the ed25519 host public key the operator pins into
//! `known_hosts` before deploying. `backhand` + `veritysetup` are operator-host tools,
//! which is why this surface lives in Orchard, not the in-image crate.

use std::io::Read as _;
use std::path::Path;

/// The rootfs byte ranges the offline mode needs from `<img>.layout.toml`.
struct RootfsLayout {
    rootfs_offset: u64,
    rootfs_size: u64,
    /// Where the verity hash tree begins WITHIN the rootfs partition (= padded squashfs
    /// length). The verity DATA the build hashed is `rootfs[0..verity_hash_offset]`.
    verity_hash_offset: u64,
}

/// Parse the three `[layout]` fields the offline mode reads (the sidecar is the simple
/// `key = <u64>` grammar `image::render_layout_toml` emits — a line scan avoids a toml dep).
fn parse_rootfs_layout(toml_text: &str) -> Result<RootfsLayout, String> {
    let field = |k: &str| -> Result<u64, String> {
        toml_text
            .lines()
            .find_map(|l| {
                let (key, val) = l.split_once('=')?;
                if key.trim() == k {
                    val.trim().parse::<u64>().ok()
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("layout.toml missing or malformed field: {k}"))
    };
    Ok(RootfsLayout {
        rootfs_offset: field("rootfs_offset")?,
        rootfs_size: field("rootfs_size")?,
        verity_hash_offset: field("rootfs_verity_hash_offset")?,
    })
}

const SSH_ED25519: &[u8] = b"ssh-ed25519";

/// SSH ed25519 public-key wire blob (RFC 8709): BE32(11)||"ssh-ed25519"||BE32(32)||pubkey.
fn ssh_wire(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut w = Vec::with_capacity(4 + SSH_ED25519.len() + 4 + 32);
    w.extend_from_slice(&(SSH_ED25519.len() as u32).to_be_bytes());
    w.extend_from_slice(SSH_ED25519);
    w.extend_from_slice(&32u32.to_be_bytes());
    w.extend_from_slice(pubkey);
    w
}

/// `ssh-ed25519 AAAA…` (the known_hosts / authorized_keys key form).
fn ssh_pubkey_line(pubkey: &[u8; 32]) -> String {
    use base64::Engine as _;
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(ssh_wire(pubkey))
    )
}

/// OpenSSH `SHA256:…` fingerprint = base64-nopad of SHA-256 over the wire blob.
fn ssh_fingerprint(pubkey: &[u8; 32]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(ssh_wire(pubkey));
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// The full known_hosts line ready to append: `<host>-rescue ssh-ed25519 AAAA…` (spec L1200).
fn known_hosts_line(hostname: &str, pubkey: &[u8; 32]) -> String {
    format!("{hostname}-rescue {}", ssh_pubkey_line(pubkey))
}

/// Extract `/etc/dropbear/rescue-host-key-seed` (32 bytes) from a squashfs blob via the
/// pure-Rust backhand reader (trailing zero-pad in `squashfs` is ignored — the superblock
/// carries the real size).
fn extract_seed(squashfs: Vec<u8>) -> Result<[u8; 32], String> {
    use backhand::{FilesystemReader, InnerNode};
    let fs = FilesystemReader::from_reader(std::io::Cursor::new(squashfs))
        .map_err(|e| format!("parse rootfs squashfs: {e}"))?;
    let target = Path::new("/etc/dropbear/rescue-host-key-seed");
    for node in fs.files() {
        if node.fullpath == target {
            let InnerNode::File(f) = &node.inner else {
                return Err("/etc/dropbear/rescue-host-key-seed is not a regular file".into());
            };
            let mut buf = Vec::new();
            fs.file(f)
                .reader()
                .read_to_end(&mut buf)
                .map_err(|e| format!("read rescue-host-key-seed: {e}"))?;
            return buf.try_into().map_err(|v: Vec<u8>| {
                format!("rescue-host-key-seed is {} bytes, expected 32", v.len())
            });
        }
    }
    Err("/etc/dropbear/rescue-host-key-seed not found in the image".into())
}

/// Recompute the dm-verity root hash over `data` (the padded squashfs) with the SAME
/// `veritysetup format --no-superblock` argv the build uses (`recipes_image_builder`'s
/// `veritysetup_format_argv`) — single source, so the offline fingerprint can never drift
/// from the on-box runtime nonce.
fn recompute_verity_root_hash(data: &[u8]) -> Result<[u8; 32], String> {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let data_path = tmp.path().join("rootfs-data");
    let hash_path = tmp.path().join("hash-tree");
    std::fs::File::create(&data_path)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| format!("write verity data: {e}"))?;
    let argv = recipes_image_builder::verity::veritysetup_format_argv(&data_path, &hash_path);
                                                                                                
                                                                                 
    let out = std::process::Command::new("veritysetup")
        .args(&argv)
        .output()
        .map_err(|e| format!("run veritysetup (is it installed?): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "veritysetup format failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
                                                                                                   
    let hex = recipes_image_builder::verity::parse_veritysetup_root_hash(&stdout)
        .ok_or("veritysetup output had no valid 'Root hash:' line")?;
    decode_hex_32(&hex)
        .ok_or_else(|| format!("veritysetup root hash is not 32 bytes of hex: {hex:?}"))
}

/// Derive the box's runtime/rescue host PUBLIC key from image BYTES + the layout sidecar TEXT:
/// slice the rootfs data portion, extract the baked seed, recompute the verity nonce, derive
/// ed25519. Returns `(public_key, nonce)` — the nonce is the dm-verity root hash, exposed so a
                                                                                             
fn offline_public_key_bytes(
    img: &[u8],
    layout_text: &str,
) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let layout = parse_rootfs_layout(layout_text).map_err(boxed)?;
    let start = layout.rootfs_offset as usize;
    let part_end = start
        .checked_add(layout.rootfs_size as usize)
        .ok_or_else(|| boxed("layout rootfs range overflows".into()))?;
    let data_end = start
        .checked_add(layout.verity_hash_offset as usize)
        .ok_or_else(|| boxed("layout verity offset overflows".into()))?;
    if part_end > img.len() || data_end > part_end {
        return Err(boxed(format!(
            "layout offsets exceed image size ({} bytes)",
            img.len()
        )));
    }
                                                                                            
                                                                       
    let data = &img[start..data_end];
    let seed = extract_seed(data.to_vec()).map_err(boxed)?;
    let nonce = recompute_verity_root_hash(data).map_err(boxed)?;
    let public =
        grape::ed25519_public_from_seed(&seed, &nonce).map_err(|e| boxed(e.to_string()))?;
    Ok((public, nonce))
}

/// Derive the box's runtime/rescue host PUBLIC key from a local `.img` + its sibling
/// `.layout.toml`. The shared core of [`derive_rescue_offline`] (printing) and
/// [`offline_runtime_hostkey`] (the `deploy prod` Leg-B pin).
fn offline_public_key(image: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let img =
        std::fs::read(image).map_err(|e| boxed(format!("read image {}: {e}", image.display())))?;
                                                                                  
                                                                             
                                                                                  
    let layout_path = image.with_extension("layout.toml");
    let layout_text = std::fs::read_to_string(&layout_path)
        .map_err(|e| boxed(format!("read {}: {e}", layout_path.display())))?;
    Ok(offline_public_key_bytes(&img, &layout_text)?.0)
}

/// The post-flip runtime host key for `orchard update`, derived from the ALREADY-READ image bytes
                                                                                                 
/// hash the ceremony already holds (`expected_root_hash_hex`, read from the signed boot-fs). The
/// derivation recomputes the nonce from the sidecar-selected rootfs bytes; if it disagrees with the
/// signed value the `.layout.toml` is stale/wrong and the derived key would be silently wrong (which
                                                                                                  
                                                                                                   
pub fn offline_runtime_hostkey_verified(
    img: &[u8],
    layout_text: &str,
    expected_root_hash_hex: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (public, nonce) = offline_public_key_bytes(img, layout_text)?;
    verified_hostkey_from_parts(&public, &nonce, expected_root_hash_hex)
}

/// The cross-check + the two output forms, over ALREADY-DERIVED parts. Split from
/// [`offline_runtime_hostkey_verified`] because that function's own path is unreachable without a
/// real squashfs and the `veritysetup` host tool, so the fail-closed arm had no unit floor; the
/// rendering of the pubkey line + fingerprint lives here too, so the cross-check cannot be dropped
                                                                        
fn verified_hostkey_from_parts(
    public: &[u8; 32],
    nonce: &[u8; 32],
    expected_root_hash_hex: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let recomputed = hex32(nonce);
    if !recomputed.eq_ignore_ascii_case(expected_root_hash_hex.trim()) {
        return Err(boxed(format!(
            "post-flip key derivation: the recomputed verity root hash {recomputed} does not match \
             the signed root_hash {} — the .layout.toml is stale or does not belong to this image",
            expected_root_hash_hex.trim()
        )));
    }
    Ok((ssh_pubkey_line(public), ssh_fingerprint(public)))
}

/// Lower-hex a 32-byte hash.
fn hex32(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The derived runtime host key as `deploy prod`'s reconnect leg consumes it:
/// `(ssh-ed25519 <b64> pubkey line, SHA256:… fingerprint)`. Same derivation as
/// [`derive_rescue_offline`] without the printing — the flow pins the pubkey line into its
/// controlled known_hosts (so sshd itself enforces the pin) and cross-checks the fingerprint
/// against `--runtime-hostkey-fingerprint` when the operator passes one. (Services and rescue
/// intentionally share this derived identity — BOOT-1; the spec flags the shared-identity
/// decision for the holistic review.)
pub fn offline_runtime_hostkey(
    image: &Path,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let public = offline_public_key(image)?;
    Ok((ssh_pubkey_line(&public), ssh_fingerprint(&public)))
}

/// Orchestrate the offline precompute: derive the public key, then print the requested
/// form(s). With no flag, prints the pubkey.
pub fn derive_rescue_offline(
    image: &Path,
    print_fingerprint: bool,
    pubkey: bool,
    hostname: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let public = offline_public_key(image)?;

    let print_default = !print_fingerprint && !pubkey && hostname.is_none();
    if print_fingerprint {
        println!("{}", ssh_fingerprint(&public));
    }
    if pubkey || print_default {
        println!("{}", ssh_pubkey_line(&public));
    }
    if let Some(h) = hostname {
        println!("{}", known_hosts_line(h, &public));
    }
    Ok(())
}

/// Decode exactly 32 bytes from 64 hex chars; `None` on any non-hex char or wrong length.
/// (Copy of the `rescue_keys` runtime helper — the offline path used it via `super::`.)
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Box a String as a dyn Error (copy of the `rescue_keys` runtime helper).
fn boxed(msg: String) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rootfs_layout_reads_the_emitted_sidecar() {
                                                                                                        
                                                                                                          
        let toml = "[layout]\nboot_offset = 0\nboot_size = 100\npersist_skeleton_offset = 100\n\
                        persist_skeleton_size = 200\nrootfs_offset = 300\nrootfs_size = 4096\n\
                        rootfs_verity_hash_offset = 2048\nfirmware = \"seabios\"\n";
        let l = parse_rootfs_layout(toml).unwrap();
        assert_eq!(l.rootfs_offset, 300);
        assert_eq!(l.rootfs_size, 4096);
        assert_eq!(l.verity_hash_offset, 2048);
    }

    #[test]
    fn parse_rootfs_layout_errors_on_missing_field() {
        assert!(parse_rootfs_layout("[layout]\nrootfs_offset = 1\n").is_err());
    }

    #[test]
    fn ssh_pubkey_line_matches_independent_wire_encoding() {
        use base64::Engine as _;
        let pubkey = [0x42u8; 32];
                                                                         
        let mut wire = vec![0, 0, 0, 11];
        wire.extend_from_slice(b"ssh-ed25519");
        wire.extend_from_slice(&[0, 0, 0, 32]);
        wire.extend_from_slice(&pubkey);
        let expected = format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(&wire)
        );
        assert_eq!(ssh_pubkey_line(&pubkey), expected);
    }

    #[test]
    fn ssh_fingerprint_is_sha256_base64_nopad() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let pubkey = [0x07u8; 32];
        let mut wire = vec![0, 0, 0, 11];
        wire.extend_from_slice(b"ssh-ed25519");
        wire.extend_from_slice(&[0, 0, 0, 32]);
        wire.extend_from_slice(&pubkey);
        let expected = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&wire))
        );
        assert_eq!(ssh_fingerprint(&pubkey), expected);
        assert!(
            !ssh_fingerprint(&pubkey).ends_with('='),
            "no base64 padding"
        );
    }

    #[test]
    fn known_hosts_line_has_rescue_suffix_and_pubkey() {
        let pubkey = [0x01u8; 32];
        let line = known_hosts_line("box.example.org", &pubkey);
        assert!(line.starts_with("box.example.org-rescue ssh-ed25519 "));
    }

    /// A hand-written 32-byte nonce and its hex, independent of `hex32`.
    const NONCE: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

                                                                                       
    /// `.layout.toml` that selects the wrong rootfs bytes yields a different verity nonce, and the
                                                                                                   
    /// to refuse; the message names both hashes so the operator can tell which artifact is stale.
    #[test]
    fn the_root_hash_cross_check_refuses_a_nonmatching_expected_hash() {
        let public = [0x42u8; 32];
                                                                                                     
                                                                                        
        let (line, fpr) = verified_hostkey_from_parts(&public, &NONCE, NONCE_HEX)
            .expect("the matching root hash is accepted");
        crate::deploy::update::PostFlipHostKey::new(line.clone(), fpr.clone())
            .expect("the returned line and fingerprint correspond");
                                                                             
        assert!(verified_hostkey_from_parts(&public, &NONCE, &NONCE_HEX.to_uppercase()).is_ok());
        assert!(verified_hostkey_from_parts(&public, &NONCE, &format!("  {NONCE_HEX}\n")).is_ok());
                                             
        let mut wrong = NONCE_HEX.to_string();
        wrong.replace_range(0..1, "1");
        let err = verified_hostkey_from_parts(&public, &NONCE, &wrong)
            .expect_err("a one-nibble-different root hash must be refused")
            .to_string();
        assert!(
            err.contains(NONCE_HEX),
            "the recomputed hash is missing: {err}"
        );
        assert!(err.contains(&wrong), "the expected hash is missing: {err}");
                                                                                              
        assert!(verified_hostkey_from_parts(&public, &NONCE, "").is_err());
    }
}
