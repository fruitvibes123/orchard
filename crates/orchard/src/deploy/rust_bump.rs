//! `market upgrade --rust` — the Component C bump: fetch `channel-rust-<ver>.toml{,.asc}` from
//! static.rust-lang.org, cashew-verify the manifest against the vendored, sha256-pinned Rust release
                                                                                                  
//! version, extract the two toolchain-component url+shas, and write them into every staged `pins.toml`
//! `[rust]` (§3a-2 keeps the four repos byte-agreed). Spec: the Component C design (cookbook
                                                                                
//!
                                                                                                
//! against its `[rust-keyring]` pin BEFORE cashew parses a single byte; the manifest is VERIFIED
//! before it is parsed (parse-after-verify — the `finalize()==Ok` gate); every write goes through the
//! executor's stage (nothing pinned on any failure — the stage drops). Unlike `--kernel`, the bump
                                                                                                     
                     

use std::path::PathBuf;
use std::time::SystemTime;

use cashew::{DetachedVerifier, Fingerprint, Keyring};
use recipes_image_builder::Fetcher;
use recipes_image_builder::pins::Pins;
use recipes_image_builder::store_checks::RUST_KEYRING_SUBDIR;
use sha2::{Digest, Sha256};

use super::market_exec::{Stage, StoreLayout};
use super::market_upgrade::UpgradeError;

/// Where static.rust-lang.org publishes the version-addressable release manifests.
pub const RUST_MANIFEST_BASE: &str = "https://static.rust-lang.org/dist";

/// Fetch-body ceiling for the manifest: a real `channel-rust-<ver>.toml` is ~860 KB; 8 MiB is generous
/// headroom over a specified shape, far below host RAM. (There is NO decompression — it is plain TOML.)
pub const RUST_MANIFEST_CAP: u64 = 8 * 1024 * 1024;

/// A loose sanity bound on the detached `.asc` transport size. A real manifest `.asc` is < 1 KiB;
/// cashew's armor parse is the real fail-closed cap (64 KiB), so this only refuses an obviously
/// oversized body from a hostile CDN before it reaches the parser (mirrors the kernel `.sign` belt).
const RUST_ASC_SANITY_CAP: u64 = 128 * 1024;

/// The pinned Rust release signer (consumer-owned constant). Grounded out-of-band vs Arch's `rust`
/// PKGBUILD `validpgpkeys`; the key self-signs SHA-1, so it loads via `load_pinned_bare`, binding the
/// PRIMARY only (never subkeys). A key change = a keyring-refresh review event
/// (`keyring/rust-lang/README.md`), never a hot edit.
pub const RUST_SIGNER_FPR: &str = "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE";

                                                                                                  
/// package, the UEFI std under the `rust-std` package. A new target is a deliberate spec edit here,
/// not a runtime input.
const HOST_MUSL_TARGET: &str = "x86_64-unknown-linux-musl";
const UEFI_STD_TARGET: &str = "x86_64-unknown-uefi";

/// `<major>.<minor>.<patch>`, ASCII digits only (1–5 per component) — the whitelist for the value
/// spliced into the manifest URL + the pins. Anything else (path chars, whitespace, empty components,
/// a 2-part version) is refused before a single byte is fetched.
pub fn validate_rust_version(v: &str) -> Result<(), String> {
    let parts: Vec<&str> = v.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "--rust version {v:?} must be <major>.<minor>.<patch> (ascii digits only)"
        ))
    }
}

/// Rewrite EXACTLY the `version`, `toolchain_musl_url`, `toolchain_musl_sha256`, `std_uefi_url`, and
/// `std_uefi_sha256` lines inside the `[rust]` section, byte-preserving every other line — comments,
/// `alpine_base*`, and `container_digest` included (a rust bump touches none of those). Fails closed
/// unless the section carries exactly one of each of the five.
pub fn rewrite_rust_pin(
    pins_text: &str,
    version: &str,
    musl_url: &str,
    musl_hash: &str,
    uefi_url: &str,
    uefi_hash: &str,
) -> Result<String, String> {
    let mut in_rust = false;
                                                        
    let mut counts = [0usize; 5];
    let mut out: Vec<String> = Vec::new();
    for line in pins_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
                                                                                                 
                                                                                                  
            in_rust = trimmed == "[rust]";
            out.push(line.to_string());
        } else if in_rust && trimmed.starts_with("version = ") {
            counts[0] += 1;
            out.push(format!("version = \"{version}\""));
        } else if in_rust && trimmed.starts_with("toolchain_musl_url = ") {
            counts[1] += 1;
            out.push(format!("toolchain_musl_url = \"{musl_url}\""));
        } else if in_rust && trimmed.starts_with("toolchain_musl_sha256 = ") {
            counts[2] += 1;
            out.push(format!("toolchain_musl_sha256 = \"{musl_hash}\""));
        } else if in_rust && trimmed.starts_with("std_uefi_url = ") {
            counts[3] += 1;
            out.push(format!("std_uefi_url = \"{uefi_url}\""));
        } else if in_rust && trimmed.starts_with("std_uefi_sha256 = ") {
            counts[4] += 1;
            out.push(format!("std_uefi_sha256 = \"{uefi_hash}\""));
        } else {
            out.push(line.to_string());
        }
    }
    if counts != [1, 1, 1, 1, 1] {
        return Err(format!(
            "pins.toml [rust] must carry exactly one each of version / toolchain_musl_url / \
             toolchain_musl_sha256 / std_uefi_url / std_uefi_sha256 (found {counts:?}) — refusing a \
             blind rewrite"
        ));
    }
    let mut s = out.join("\n");
    if pins_text.ends_with('\n') {
        s.push('\n');
    }
    Ok(s)
}

/// Rewrite EXACTLY the `container_digest = "…"` line inside `[rust]` (byte-preserving every other
/// line) — the reproducibility anchor RebuildContainer (§7) sets AFTER the double-build, distinct from
/// the toolchain re-pin ([`rewrite_rust_pin`], which never touches it). Fails closed unless the section
/// carries exactly one `container_digest =` line.
pub fn rewrite_container_digest(pins_text: &str, digest: &str) -> Result<String, String> {
    let mut in_rust = false;
    let mut n = 0usize;
    let mut out: Vec<String> = Vec::new();
    for line in pins_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_rust = trimmed == "[rust]";
            out.push(line.to_string());
        } else if in_rust && trimmed.starts_with("container_digest = ") {
            n += 1;
            out.push(format!("container_digest = \"{digest}\""));
        } else {
            out.push(line.to_string());
        }
    }
    if n != 1 {
        return Err(format!(
            "pins.toml [rust] must carry exactly one `container_digest =` line (found {n})"
        ));
    }
    let mut s = out.join("\n");
    if pins_text.ends_with('\n') {
        s.push('\n');
    }
    Ok(s)
}

/// The injectable inputs of one `--rust` bump. Production fills these from the module const + the wall
/// clock (`ShellStepExec::bump_upstream`); tests + the produced-bytes gate swap ONLY the transport +
/// the signer fpr (fixture key), so the verify path is always the real one.
pub struct RustBump<'a> {
    pub fetch: &'a dyn Fetcher,
    pub now: SystemTime,
    /// The pinned signer fingerprint (hex, 40 chars) — [`RUST_SIGNER_FPR`] in production.
    pub signer_fpr: &'a str,
}

                                                                                                          
/// `load_pinned_bare` → fetch `.asc` (small, fail-fast) → fetch the manifest (capped) → verify the
/// WHOLE manifest (the sealed `Verified` is the only way past) → parse the SAME buffer (gated on
/// `finalize()==Ok`) → bind the version → extract the two components (available=true) → rewrite
/// `[rust]` in EVERY staged `pins.toml` copy. Every failure returns BEFORE the swap, nothing pinned.
pub fn bump_rust(
    bump: &RustBump<'_>,
    version: &str,
    layout: &StoreLayout,
    stage: &mut Stage,
) -> Result<(), UpgradeError> {
    let step_err = |detail: String| UpgradeError::StepFailed {
        step: "bump-upstream".into(),
        detail,
    };

                                                                          
    validate_rust_version(version).map_err(step_err)?;

                                                                                            
    let pins = Pins::load(stage.verify_root()).map_err(|e| step_err(e.to_string()))?;

                                                                                                        
                                                                                              
                                                             
    let dir = stage.verify_root().join(RUST_KEYRING_SUBDIR);
    let mut keyring_bytes = Vec::new();
    for (name, want) in &pins.rust_keyring {
        let p = dir.join(name);
        let bytes = std::fs::read(&p)
            .map_err(|e| step_err(format!("read keyring file {}: {e}", p.display())))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if &actual != want {
            return Err(step_err(format!(
                "keyring pin mismatch BEFORE parse: sha256({name}) = {actual} != [rust-keyring] pin \
                 {want} — refusing to hand unpinned bytes to the verifier (keyring/rust-lang/README.md)"
            )));
        }
        keyring_bytes.extend_from_slice(&bytes);
    }

                                                                                                          
                                                                                                  
                                           
    let fpr = Fingerprint::from_hex(bump.signer_fpr).ok_or_else(|| {
        step_err(format!(
            "bad signer fingerprint constant {:?}",
            bump.signer_fpr
        ))
    })?;
    let keyring = Keyring::load_pinned_bare(&keyring_bytes, &[fpr], bump.now)
        .map_err(|e| step_err(format!("rust keyring load failed: {e:?} — nothing pinned")))?;

                                                                                                        
                                                                                                    
    let asc_url = format!("{RUST_MANIFEST_BASE}/channel-rust-{version}.toml.asc");
    let asc = bump
        .fetch
        .get(&asc_url)
        .map_err(|e| step_err(format!("fetch {asc_url}: {e}")))?;
    if asc.len() as u64 > RUST_ASC_SANITY_CAP {
        return Err(step_err(format!(
            "{asc_url} is {} bytes — over the {RUST_ASC_SANITY_CAP}-byte sanity bound; refusing, \
             nothing pinned",
            asc.len()
        )));
    }
    let mut verifier = DetachedVerifier::new(&asc)
        .map_err(|e| step_err(format!("parse {asc_url}: {e:?} — nothing pinned")))?;

                                                                                                    
    let man_url = format!("{RUST_MANIFEST_BASE}/channel-rust-{version}.toml");
    let manifest = bump
        .fetch
        .get(&man_url)
        .map_err(|e| step_err(format!("fetch {man_url}: {e}")))?;
    if manifest.len() as u64 > RUST_MANIFEST_CAP {
        return Err(step_err(format!(
            "{man_url} is {} bytes — over the {RUST_MANIFEST_CAP}-byte manifest cap; refusing, \
             nothing pinned",
            manifest.len()
        )));
    }

                                                                                                        
                                                                                 
    verifier.update(&manifest);
    let verified = verifier.finalize(&keyring).map_err(|e| {
        step_err(format!(
            "PGP verify of channel-rust-{version}.toml FAILED: {e:?} — nothing pinned (an unknown \
             signer needs the keyring-refresh review event, keyring/rust-lang/README.md)"
        ))
    })?;
    println!(
        "bump-upstream: channel-rust-{version}.toml PGP-verified (signer {}, hash algo {})",
        hex::encode(verified.signer_fingerprint().0),
        verified.hash_algo(),
    );

                                                                                                      
                                                                                                     
                                    
    let man_str = std::str::from_utf8(&manifest)
        .map_err(|e| step_err(format!("verified manifest is not utf-8: {e}")))?;
    let man: toml::Value =
        toml::from_str(man_str).map_err(|e| step_err(format!("parse verified manifest: {e}")))?;

                                                                                                   
                                                                                                      
                                                                           
    let declared = man
        .get("pkg")
        .and_then(|p| p.get("rust"))
        .and_then(|r| r.get("version"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| step_err("verified manifest missing [pkg.rust].version".into()))?;
    let leading = declared.split_whitespace().next().unwrap_or("");
    if leading != version {
        return Err(step_err(format!(
            "manifest version binding FAILED: [pkg.rust].version leads with {leading:?} but the bump \
             requested {version:?} — refusing a genuine-signed version substitution"
        )));
    }

                                                                                             
    let (musl_url, musl_hash) =
        extract_component(&man, "rust", HOST_MUSL_TARGET).map_err(step_err)?;
    let (uefi_url, uefi_hash) =
        extract_component(&man, "rust-std", UEFI_STD_TARGET).map_err(step_err)?;

                                                                                                       
                                                                                                 
    let mut targets: Vec<PathBuf> = vec![layout.orchard_root.join("pins.toml")];
    targets.extend(layout.repos.values().map(|d| d.join("pins.toml")));
    for real in targets {
        let staged = stage.stage_write(&real)?;
        let cur = std::fs::read_to_string(&staged)
            .map_err(|e| step_err(format!("read staged {}: {e}", staged.display())))?;
        let rewritten =
            rewrite_rust_pin(&cur, version, &musl_url, &musl_hash, &uefi_url, &uefi_hash)
                .map_err(|e| step_err(format!("{}: {e}", real.display())))?;
        std::fs::write(&staged, rewritten).map_err(UpgradeError::Io)?;
    }
    Ok(())
}

/// Extract `(xz_url, xz_hash)` for `[pkg.<pkg>.target.<target>]` from the VERIFIED manifest, asserting
/// `available = true` and shape-validating the values (the same contract `pins.rs` enforces + no
/// quote/newline that could break the pins TOML). A missing/unavailable pinned target fails closed.
fn extract_component(
    man: &toml::Value,
    pkg: &str,
    target: &str,
) -> Result<(String, String), String> {
    let t = man
        .get("pkg")
        .and_then(|p| p.get(pkg))
        .and_then(|p| p.get("target"))
        .and_then(|tt| tt.get(target))
        .ok_or_else(|| format!("verified manifest missing [pkg.{pkg}.target.{target}]"))?;
    if !t
        .get("available")
        .and_then(|a| a.as_bool())
        .unwrap_or(false)
    {
        return Err(format!(
            "[pkg.{pkg}.target.{target}] is not available = true — a pinned target vanished; refusing"
        ));
    }
    let url = t
        .get("xz_url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| format!("[pkg.{pkg}.target.{target}] missing xz_url"))?;
    let hash = t
        .get("xz_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| format!("[pkg.{pkg}.target.{target}] missing xz_hash"))?;
    if !(url.starts_with("https://static.rust-lang.org/dist/") && url.ends_with(".tar.xz"))
        || url.contains('"')
        || url.contains('\n')
    {
        return Err(format!(
            "[pkg.{pkg}.target.{target}] xz_url {url:?} is not an \
             https://static.rust-lang.org/dist/… .tar.xz url"
        ));
    }
                                                                                                      
                                                                                                         
    if !url
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":/._-".contains(&b))
    {
        return Err(format!(
            "[pkg.{pkg}.target.{target}] xz_url {url:?} contains a non-URL-safe character \
             (shell-injection guard)"
        ));
    }
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "[pkg.{pkg}.target.{target}] xz_hash {hash:?} is not 64 lowercase hex"
        ));
    }
    Ok((url.to_string(), hash.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_whitelist_accepts_semver_only() {
        for good in ["1.96.0", "6.99.1", "10.0.123", "1.2.3"] {
            assert!(validate_rust_version(good).is_ok(), "{good} must pass");
        }
        for bad in [
            "1.96",
            "1.96.0.1",
            "1.96.x",
            "v1.96.0",
            "",
            "1..0",
            "1.96.",
            "1.234567.0",
            "1.96.0/x",
            " 1.96.0",
        ] {
            assert!(
                validate_rust_version(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    const PINS: &str = "\
# header, version = \"9.9.9\" in prose
[rust]
# the rust pin
version = \"1.96.0\"
alpine_base = \"alpine:3.23\"
alpine_base_digest = \"sha256:aaaa\"
toolchain_musl_url = \"https://static.rust-lang.org/dist/old/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"
toolchain_musl_sha256 = \"1111\"
std_uefi_url = \"https://static.rust-lang.org/dist/old/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"
std_uefi_sha256 = \"2222\"
container_digest = \"sha256:cccc\"

[rust-keyring]
\"rust-signing.asc\" = \"dddd\"
";

    #[test]
    fn rewrite_touches_exactly_the_five_rust_lines() {
        let out = rewrite_rust_pin(
            PINS,
            "1.97.0",
            "https://static.rust-lang.org/dist/new/rust-1.97.0-x86_64-unknown-linux-musl.tar.xz",
            &"a".repeat(64),
            "https://static.rust-lang.org/dist/new/rust-std-1.97.0-x86_64-unknown-uefi.tar.xz",
            &"b".repeat(64),
        )
        .expect("rewrites");
        let changed: Vec<(&str, &str)> = PINS
            .lines()
            .zip(out.lines())
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(
            changed.len(),
            5,
            "exactly the 5 [rust] pin lines change: {changed:?}"
        );
        assert!(out.contains("version = \"1.97.0\""));
        assert!(out.contains("rust-1.97.0-x86_64-unknown-linux-musl.tar.xz"));
        assert!(out.contains(&format!("toolchain_musl_sha256 = \"{}\"", "a".repeat(64))));
                                                        
        assert!(out.contains("alpine_base = \"alpine:3.23\""));
        assert!(out.contains("container_digest = \"sha256:cccc\""));
        assert!(out.contains("# the rust pin"), "comments preserved");
        assert!(out.contains("[rust-keyring]"), "keyring section untouched");
        assert_eq!(
            PINS.lines().count(),
            out.lines().count(),
            "no line added/dropped"
        );
    }

    #[test]
    fn rewrite_container_digest_touches_only_that_line() {
        let out = rewrite_container_digest(PINS, "sha256:beef").unwrap();
        assert!(out.contains("container_digest = \"sha256:beef\""));
        assert!(!out.contains("sha256:cccc"), "old digest replaced");
                                                        
        assert!(out.contains("version = \"1.96.0\""));
        assert!(out.contains("toolchain_musl_sha256 = \"1111\""));
        assert!(out.contains("# the rust pin"));
        assert_eq!(PINS.lines().count(), out.lines().count());
                                                      
        assert!(rewrite_container_digest("[rust]\nversion = \"1\"\n", "sha256:x").is_err());
    }

    #[test]
    fn rewrite_fails_closed_when_a_field_is_missing() {
                                                                                                       
        let partial = "[rust]\nversion = \"1.96.0\"\ntoolchain_musl_url = \"x\"\ntoolchain_musl_sha256 = \"y\"\n";
        assert!(rewrite_rust_pin(partial, "1.97.0", "u", "h", "u2", "h2").is_err());
                                    
        assert!(
            rewrite_rust_pin(
                "[kernel]\nversion = \"6.1\"\n",
                "1.97.0",
                "u",
                "h",
                "u2",
                "h2"
            )
            .is_err()
        );
    }

    fn manifest(available_uefi: bool, version: &str) -> toml::Value {
        let uefi = if available_uefi {
            "available = true\nxz_url = \"https://static.rust-lang.org/dist/d/rust-std-x86_64-unknown-uefi.tar.xz\"\nxz_hash = \"2222222222222222222222222222222222222222222222222222222222222222\""
        } else {
            "available = false"
        };
        toml::from_str(&format!(
            "[pkg.rust]\nversion = \"{version}\"\n\
             [pkg.rust.target.x86_64-unknown-linux-musl]\navailable = true\n\
             xz_url = \"https://static.rust-lang.org/dist/d/rust-x86_64-unknown-linux-musl.tar.xz\"\n\
             xz_hash = \"1111111111111111111111111111111111111111111111111111111111111111\"\n\
             [pkg.rust-std.target.x86_64-unknown-uefi]\n{uefi}\n"
        ))
        .unwrap()
    }

    #[test]
    fn extract_component_reads_available_targets_and_refuses_unavailable() {
        let m = manifest(true, "1.96.0 (h d)");
        let (url, hash) = extract_component(&m, "rust", HOST_MUSL_TARGET).unwrap();
        assert!(url.ends_with("linux-musl.tar.xz"));
        assert_eq!(hash.len(), 64);
        assert!(extract_component(&m, "rust-std", UEFI_STD_TARGET).is_ok());
                                            
        let m = manifest(false, "1.96.0 (h d)");
        assert!(
            extract_component(&m, "rust-std", UEFI_STD_TARGET)
                .unwrap_err()
                .contains("not available")
        );
                                            
        assert!(extract_component(&m, "rust", "aarch64-unknown-linux-gnu").is_err());
                                                                                                          
        let evil: toml::Value = toml::from_str(
            "[pkg.rust.target.x86_64-unknown-linux-musl]\navailable = true\n\
             xz_url = \"https://static.rust-lang.org/dist/$(touch x)/rust.tar.xz\"\n\
             xz_hash = \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
        )
        .unwrap();
        assert!(
            extract_component(&evil, "rust", HOST_MUSL_TARGET)
                .unwrap_err()
                .contains("non-URL-safe")
        );
    }
}
