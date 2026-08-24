//! `market upgrade --kernel` — the B-kernel bump: fetch `linux-<ver>.tar.{xz,sign}` from
//! cdn.kernel.org, PGP-verify the UNCOMPRESSED tar against the vendored, sha256-pinned
//! kernel.org keyring (`keyring/kernel.org/`, via cashew's streaming verify), then write the new
//! `[kernel]` version+sha256 into every staged `pins.toml` copy (§3a-2 keeps the four repos
                                                                                                  
//!
//! Trust order is load-bearing: the keyring FILES are checked byte-exact against their
//! `[kernel-keyring]` pins BEFORE cashew parses a single byte (a pin mismatch fails ahead of any
//! parse); the tarball verifies BEFORE anything is written; every write goes through the executor's
//! stage (nothing pinned on any failure — the stage drops).

use std::path::PathBuf;
use std::time::SystemTime;

use cashew::{DetachedVerifier, Fingerprint, Keyring};
use recipes_image_builder::Fetcher;
use recipes_image_builder::pins::Pins;
use recipes_image_builder::store_checks::KEYRING_SUBDIR;
use sha2::{Digest, Sha256};

use super::market_exec::{Stage, StoreLayout};
use super::market_upgrade::UpgradeError;

                                                                                              
/// their sole code home + carries their rationale docs); re-exported so existing consumers
/// (main.rs, the produced-bytes gate) keep compiling unchanged.
pub use recipes_image_builder::sources::{KERNEL_ORG_BASE, KERNEL_TAR_CEILING, KERNEL_XZ_CAP};

                                                                                                 
/// `.sign` is < 1 KiB; cashew's armor parse is the real fail-closed cap (64 KiB), so this only
/// refuses an obviously-oversized body from a hostile CDN before it reaches the parser.
const SIGN_SANITY_CAP: u64 = 128 * 1024;

                                                                                                    
/// pins as parameters; the consumer owns them). Both sign stable tarballs with their [SC] PRIMARY
                                                                                                     
/// A new signer = a keyring-refresh review event (`keyring/kernel.org/README.md`), never a hot edit.
pub const KERNEL_ORG_SIGNER_FPRS: &[&str] = &[
                         
    "647F28654894E3BD457199BE38DBBDC86092693E",
                  
    "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC",
];

/// `6.N` or `6.N.P`, ASCII digits only (1–5 per component) — the whitelist for the value that is
/// spliced into the fetch URL and the pins file. A 7.x pin is a deliberate URL-segment edit
                                                                                                
/// before a single byte is fetched.
pub fn validate_kernel_version(v: &str) -> Result<(), String> {
    let parts: Vec<&str> = v.split('.').collect();
    let ok = (parts.len() == 2 || parts.len() == 3)
        && parts[0] == "6"
        && parts[1..]
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "--kernel version {v:?} must be 6.N or 6.N.P (ascii digits only; a 7.x pin is a \
             deliberate v6.x URL-segment edit)"
        ))
    }
}

/// Rewrite EXACTLY the `version = "…"` and `sha256 = "…"` lines inside the `[kernel]` section of a
/// `pins.toml`, byte-preserving every other line — comments included (the file is operator-reviewed;
/// a `toml` round-trip that strips comments or reorders tables is off the table). The emitted lines
/// are unindented (the canonical `pins.toml` shape the typed `Pins` reader parses).
/// Fails closed unless the section carries exactly one of each.
pub fn rewrite_kernel_pin(
    pins_text: &str,
    version: &str,
    sha256_hex: &str,
) -> Result<String, String> {
    let mut in_kernel = false;
    let (mut versions, mut shas) = (0usize, 0usize);
    let mut out: Vec<String> = Vec::new();
    for line in pins_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
                                                                                                     
                                                                                                         
            in_kernel = trimmed == "[kernel]";
            out.push(line.to_string());
        } else if in_kernel && trimmed.starts_with("version = ") {
            versions += 1;
            out.push(format!("version = \"{version}\""));
        } else if in_kernel && trimmed.starts_with("sha256 = ") {
            shas += 1;
            out.push(format!("sha256 = \"{sha256_hex}\""));
        } else {
            out.push(line.to_string());
        }
    }
    if versions != 1 || shas != 1 {
        return Err(format!(
            "pins.toml [kernel] must carry exactly one `version =` and one `sha256 =` line \
             (found {versions}/{shas}) — refusing a blind rewrite"
        ));
    }
    let mut s = out.join("\n");
    if pins_text.ends_with('\n') {
        s.push('\n');
    }
    Ok(s)
}

/// The injectable inputs of one `--kernel` bump. Production fills these from the module consts +
/// the wall clock (`ShellStepExec::bump_upstream`); tests + the produced-bytes gate swap ONLY the
/// transport (and, for the bomb negative, the ceiling) — the verify path is always the real one.
pub struct KernelBump<'a> {
    pub fetch: &'a dyn Fetcher,
    pub now: SystemTime,
    pub tar_ceiling: u64,
    /// Pinned signer fingerprints (hex, 40 chars) — [`KERNEL_ORG_SIGNER_FPRS`] in production.
    pub signer_fprs: &'a [&'a str],
}

/// The whole `--kernel` bump: version whitelist → keyring-pin byte check (BEFORE any parse) →
/// cashew keyring load → fetch `.sign` (small, fail-fast) → fetch `.tar.xz` → streamed decode
                                                                                
/// full-consumption, one decoder with the bake), feeding cashew's digest → `finalize` (the
/// sealed `Verified` is the only way past) → rewrite `[kernel]` in EVERY staged `pins.toml` copy
/// (orchard + each owning repo — §3a-2 keeps the four byte-agreed). Every failure returns BEFORE
/// the swap with nothing pinned (the stage drops).
pub fn bump_kernel(
    bump: &KernelBump<'_>,
    version: &str,
    layout: &StoreLayout,
    stage: &mut Stage,
) -> Result<(), UpgradeError> {
    let step_err = |detail: String| UpgradeError::StepFailed {
        step: "bump-upstream".into(),
        detail,
    };

                                                                              
    validate_kernel_version(version).map_err(step_err)?;

                                                                                                
    let pins = Pins::load(stage.verify_root()).map_err(|e| step_err(e.to_string()))?;

                                                                                                      
                                                                                                    
                                                                   
    let dir = stage.verify_root().join(KEYRING_SUBDIR);
    let mut keyring_bytes = Vec::new();
    for (name, want) in &pins.kernel_keyring {
        let p = dir.join(name);
        let bytes = std::fs::read(&p)
            .map_err(|e| step_err(format!("read keyring file {}: {e}", p.display())))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if &actual != want {
            return Err(step_err(format!(
                "keyring pin mismatch BEFORE parse: sha256({name}) = {actual} != [kernel-keyring] \
                 pin {want} — refusing to hand unpinned bytes to the verifier \
                 (keyring/kernel.org/README.md)"
            )));
        }
        keyring_bytes.extend_from_slice(&bytes);
    }

                                                                                                     
    let fprs: Vec<Fingerprint> = bump
        .signer_fprs
        .iter()
        .map(|h| {
            Fingerprint::from_hex(h)
                .ok_or_else(|| step_err(format!("bad signer fingerprint constant {h:?}")))
        })
        .collect::<Result<_, _>>()?;
    let keyring = Keyring::load(&keyring_bytes, &fprs, bump.now)
        .map_err(|e| step_err(format!("keyring load failed: {e:?} — nothing pinned")))?;

                                                                                                
                                                                                                     
                                                                                                      
                                                                                                      
    let sign_url = format!("{KERNEL_ORG_BASE}/linux-{version}.tar.sign");
    let sign = bump
        .fetch
        .get(&sign_url)
        .map_err(|e| step_err(format!("fetch {sign_url}: {e}")))?;
    if sign.len() as u64 > SIGN_SANITY_CAP {
        return Err(step_err(format!(
            "{sign_url} is {} bytes — far over any real detached `.sign` ({SIGN_SANITY_CAP}-byte \
             sanity bound); refusing, nothing pinned",
            sign.len()
        )));
    }
    let mut verifier = DetachedVerifier::new(&sign)
        .map_err(|e| step_err(format!("parse {sign_url}: {e:?} — nothing pinned")))?;

                                                                                                     
    let xz_url = format!("{KERNEL_ORG_BASE}/linux-{version}.tar.xz");
    let xz = bump
        .fetch
        .get(&xz_url)
        .map_err(|e| step_err(format!("fetch {xz_url}: {e}")))?;

                                                                                                   
                                                                                                   
                                                                                             
                                                                                           
                                                                                              
                                                                                                  
                                                                                             
                                                                             
    let decoded = recipes_image_builder::sources::decode_verified_xz(
        &xz,
        recipes_image_builder::sources::ShaGate::Emit,
        bump.tar_ceiling,
        &mut |chunk| verifier.update(chunk),
    )
    .map_err(|e| step_err(format!("{xz_url}: {e} — nothing pinned")))?;

                                                                                     
    let verified = verifier.finalize(&keyring).map_err(|e| {
        step_err(format!(
            "PGP verify of linux-{version}.tar FAILED: {e:?} — nothing pinned (an unknown signer \
             needs the keyring-refresh review event, keyring/kernel.org/README.md)"
        ))
    })?;
    println!(
        "bump-upstream: linux-{version}.tar PGP-verified (signer {}, hash algo {}) — {} bytes streamed",
        hex::encode(verified.signer_fingerprint().0),
        verified.hash_algo(),
        decoded.decoded_bytes,
    );

                                                                                                
                                                                                                  
                                                                                                  
                                                                                          
    let xz_sha = decoded.xz_sha256;
    let mut targets: Vec<PathBuf> = vec![layout.orchard_root.join("pins.toml")];
    targets.extend(layout.repos.values().map(|dir| dir.join("pins.toml")));
    for real in targets {
        let staged = stage.stage_write(&real)?;
        let cur = std::fs::read_to_string(&staged)
            .map_err(|e| step_err(format!("read staged {}: {e}", staged.display())))?;
        let rewritten = rewrite_kernel_pin(&cur, version, &xz_sha)
            .map_err(|e| step_err(format!("{}: {e}", real.display())))?;
        std::fs::write(&staged, rewritten).map_err(UpgradeError::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_whitelist_accepts_stable_6x_shapes_only() {
        for good in ["6.1", "6.18.34", "6.99.1", "6.0", "6.12345.1"] {
            assert!(validate_kernel_version(good).is_ok(), "{good} must pass");
        }
        for bad in [
            "7.1",
            "6",
            "6.",
            "6.18.34.1",
            "6.1x",
            "v6.1",
            "",
            "6..1",
            "6.123456",
            "6.1/../evil",
            "6 .1",
            "6.-1",
        ] {
            assert!(
                validate_kernel_version(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    const PINS_FIXTURE: &str = "\
# header comment mentioning version = \"9.9.9\" in prose
[kernel]
# the kernel pin comment
version = \"6.18.34\"
sha256 = \"640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760\"

[syslinux]
version = \"6.04-pre1\"
sha256 = \"3f6d50a57f3ed47d8234fd0ab4492634eb7c9aaf7dd902f33d3ac33564fd631d\"

[rust]
version = \"1.96.0\"
alpine_base = \"alpine:3.23\"
alpine_base_digest = \"sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40\"
toolchain_musl_url = \"https://static.rust-lang.org/dist/2026-05-28/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz\"
toolchain_musl_sha256 = \"8b4db404e24a82be906170b7b64bd69807e72e59d8371bac2a7f0ade75b39697\"
std_uefi_url = \"https://static.rust-lang.org/dist/2026-05-28/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz\"
std_uefi_sha256 = \"dd8d565f061389cef66f64aa65bbfabe01954e360ada0b39f1e0d637d588e4f6\"
container_digest = \"sha256:66f48b19d6e88519e2e58bebe0d945779a6a4ca41c2db17db78c9569655b50ac\"

[kernel-keyring]
\"gregkh.asc\" = \"9dbf6e08cfd1b08c5123596091fdef160dc8ff4be9b1ee8e8b4113b04387f87c\"

[rust-keyring]
\"rust-signing.asc\" = \"e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b\"
";

    #[test]
    fn rewrite_touches_exactly_the_two_kernel_lines() {
        let new_sha = "b".repeat(64);
        let out = rewrite_kernel_pin(PINS_FIXTURE, "6.99.1", &new_sha).expect("rewrites");
        let changed: Vec<(&str, &str)> = PINS_FIXTURE
            .lines()
            .zip(out.lines())
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(
            changed,
            vec![
                ("version = \"6.18.34\"", "version = \"6.99.1\""),
                (
                    "sha256 = \"640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760\"",
                    "sha256 = \"b\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
                ),
            ],
            "EXACTLY the two [kernel] pin lines change — comments, [syslinux], [rust], \
             [kernel-keyring], and the prose header (which mentions `version = ` in a comment) stay \
             byte-identical"
        );
        assert_eq!(
            PINS_FIXTURE.lines().count(),
            out.lines().count(),
            "no line added or dropped"
        );
        assert!(out.ends_with('\n'), "trailing-newline shape preserved");
    }

    #[test]
    fn rewrite_fails_closed_on_missing_or_ambiguous_kernel_lines() {
                                      
        assert!(
            rewrite_kernel_pin("[rust]\nversion = \"1.96.0\"\n", "6.99.1", &"b".repeat(64))
                .is_err()
        );
                                                                                                      
        assert!(
            rewrite_kernel_pin(
                "[kernel] # decorated\nversion = \"6.1\"\nsha256 = \"a\"\n",
                "6.99.1",
                &"b".repeat(64)
            )
            .is_err()
        );
                                                   
        assert!(
            rewrite_kernel_pin(
                "[kernel]\nversion = \"6.1\"\nversion = \"6.2\"\nsha256 = \"a\"\n",
                "6.99.1",
                &"b".repeat(64)
            )
            .is_err()
        );
    }
}
