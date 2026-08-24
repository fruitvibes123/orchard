//! The project's central version manifest (repo-root `pins.toml`) — the single source for the
//! kernel + rust build-input pins (the values that were genuinely scattered), read at RUNTIME so the
//! deploy tooling can confirm (and later select) the build inputs rather than re-deriving them from a
//! scatter of hard-coded literals. (The Alpine branch is NOT here — it lives in apk-world.toml.)
//!
//! Two propagation paths downstream of this reader:
//!   - **kernel** — [`Pins::kernel_tarball_path`] derives the staged `.tar.xz` path; `sources.rs`
//!     reads the same typed `[kernel]` fields for the `orchard prime` fetch + the bake's
                                                                                          
//!   - **rust** — `orchard sync-pins` GENERATES `rust-toolchain.toml`
//!     ([`Pins::render_rust_toolchain_toml`]) and syncs the `Containerfile` `FROM` base + the
//!     PGP-verified toolchain-install block ([`Pins::sync_containerfile`]). Those two files are
//!     format-locked to rustup / Docker (they
//!     are read before any Rust runs), so they can't read `pins.toml` at runtime; the codegen writes
//!     them and the `tests/pins_drift.rs` gate fails the build if they ever diverge.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The parsed `pins.toml`. The repo-root manifest; see the module doc for the bump procedure. Strict
/// (`deny_unknown_fields` at every depth + validated sha format) like every other pin manifest
/// (`pin_manifest.rs`, `repo_manifest.rs`, `provenance.rs`) — a fail-open here would let a malformed pin
                                                                  
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub kernel: KernelPin,
    pub syslinux: SyslinuxPin,
    pub rust: RustPin,
    /// Vendored kernel.org signer keyring pins — filename (under `keyring/kernel.org/`) → sha256 of
    /// the armored export. REQUIRED + non-empty: the bump-time PGP trust anchor for `market upgrade
    /// --kernel` (checked byte-exact BEFORE cashew parses the file; policed by market verify §3a-8).
    /// Keys are validated as bare lowercase `.asc` filenames because consumers join them onto the
    /// keyring dir. Re-pin only as a keyring-refresh review event — `keyring/kernel.org/README.md`.
    #[serde(rename = "kernel-keyring")]
    pub kernel_keyring: std::collections::BTreeMap<String, String>,
    /// Vendored Rust release signer keyring pins — filename (under `keyring/rust-lang/`) → sha256 of
    /// the armored export. REQUIRED + non-empty: the bump-time PGP trust anchor for `market upgrade
    /// --rust` (Component C). The Rust key self-signs SHA-1, so it is loaded via cashew's
    /// `load_pinned_bare` (the documented exception), NOT the strict path; the sha256 pin is the
    /// anchor, checked byte-exact BEFORE cashew parses. Policed by market verify §3a-8 alongside
    /// `[kernel-keyring]`. Re-pin only as a keyring-refresh review event — `keyring/rust-lang/README.md`.
    #[serde(rename = "rust-keyring")]
    pub rust_keyring: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPin {
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslinuxPin {
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustPin {
    pub version: String,
    /// The build container's FROM base — a plain Alpine, tag + digest-pinned (Docker Hub;
    /// alpine-from-source is the separate paranoia cycle). `alpine_base` is the `alpine:<tag>` ref;
    /// `alpine_base_digest` is `sha256:<64hex>`. Changed only as an independent review event, NOT by a
    /// rust bump (Component C §5 step 7).
    pub alpine_base: String,
    pub alpine_base_digest: String,
    /// The PGP-verified host toolchain (rustc + cargo + musl std) — the manifest-authenticated dated
                                                                                                   
    /// security anchor, `sha256sum -c`'d at container build). `[pkg.rust.target.x86_64-unknown-linux-musl]`.
    pub toolchain_musl_url: String,
    pub toolchain_musl_sha256: String,
    /// The PGP-verified UEFI std (rambutan compiles for `x86_64-unknown-uefi`) — same shape.
    /// `[pkg.rust-std.target.x86_64-unknown-uefi]`. Replaces the old `rustup target add`.
    pub std_uefi_url: String,
    pub std_uefi_sha256: String,
    /// `sha256:...` digest of the SELF-ASSEMBLED build image — the reproducibility anchor (the
    /// double-build ROOTFS gate), re-derived on every rebuild. NO LONGER the provenance root (that is
    /// the Rust key + the component shas above). Until the operator's first `market upgrade --rust`/
    /// `--all` (RebuildContainer §7), this holds the stale pre-Component-C `rust:<ver>-alpine` digest.
    pub container_digest: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PinsError {
    #[error("read pins.toml at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse pins.toml: {0}")]
    Parse(String),
    #[error("pins.toml {field} has a malformed sha ({value:?} — need {want})")]
    BadSha {
        field: &'static str,
        value: String,
        want: &'static str,
    },
    #[error("{0}")]
    Format(String),
}

/// The self-delimiting markers of the GENERATED Rust-toolchain install block in the `Containerfile`
/// (Component C §6): `sync_containerfile` replaces everything between them (inclusive) with
/// `render_containerfile_rust_block`, and `check_drift` polices it — so the toolchain component
                                                                                   
const RUST_BLOCK_BEGIN: &str =
    "# >>> sync-pins: PGP-verified Rust toolchain (rendered from pins.toml [rust]) — DO NOT EDIT >>>";
const RUST_BLOCK_END: &str = "# <<< sync-pins: Rust toolchain <<<";

                                                                                         
                                                                                                    
                                                                                                
                                                                                                     
                                                                                              
                                                                                           
                                                                    

/// Validate one vendored-keyring pin map (`[kernel-keyring]`/`[rust-keyring]`): REQUIRED + non-empty;
/// each key a bare lowercase `.asc` filename (it is joined onto `keyring/<subdir>/`, so no traversal,
/// hidden files, or foreign kinds); each value a canonical sha256. Shared so both keyrings enforce the
                                                                                     
fn validate_keyring_map(
    section: &str,
    sha_field: &'static str,
    map: &std::collections::BTreeMap<String, String>,
) -> Result<(), PinsError> {
    use crate::pin_manifest::is_sha256_hex;
    if map.is_empty() {
        return Err(PinsError::Format(format!(
            "[{section}] must pin at least one keyring file (a bump-time trust anchor)"
        )));
    }
    for (name, sha) in map {
        let name_ok = name.ends_with(".asc")
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if !name_ok {
            return Err(PinsError::Format(format!(
                "[{section}] key {name:?} must be a bare lowercase filename ending .asc \
                 (it is joined onto keyring/<subdir>/)"
            )));
        }
        if !is_sha256_hex(sha) {
            return Err(PinsError::BadSha {
                field: sha_field,
                value: sha.clone(),
                want: "64 lowercase hex",
            });
        }
    }
    Ok(())
}

impl Pins {
    /// The canonical repo-root manifest path for a given repo root.
    pub fn manifest_path(repo_root: &Path) -> PathBuf {
        repo_root.join("pins.toml")
    }

    pub fn from_toml_str(s: &str) -> Result<Self, PinsError> {
        let p: Pins = toml::from_str(s).map_err(|e| PinsError::Parse(e.to_string()))?;
        p.validate_shas()?;
        Ok(p)
    }

    /// Each pin's sha must be canonical: kernel/syslinux `sha256` = 64 lowercase hex; rust
    /// `container_digest` = `sha256:<64 lowercase hex>`. A malformed value would silently never match a
                                                                                                  
    fn validate_shas(&self) -> Result<(), PinsError> {
        use crate::pin_manifest::is_sha256_hex;
                            
        for (field, val) in [
            ("[kernel].sha256", &self.kernel.sha256),
            ("[syslinux].sha256", &self.syslinux.sha256),
            (
                "[rust].toolchain_musl_sha256",
                &self.rust.toolchain_musl_sha256,
            ),
            ("[rust].std_uefi_sha256", &self.rust.std_uefi_sha256),
        ] {
            if !is_sha256_hex(val) {
                return Err(PinsError::BadSha {
                    field,
                    value: val.clone(),
                    want: "64 lowercase hex",
                });
            }
        }
                                    
        for (field, val) in [
            ("[rust].alpine_base_digest", &self.rust.alpine_base_digest),
            ("[rust].container_digest", &self.rust.container_digest),
        ] {
            if !val.strip_prefix("sha256:").is_some_and(is_sha256_hex) {
                return Err(PinsError::BadSha {
                    field,
                    value: val.clone(),
                    want: "sha256:<64 lowercase hex>",
                });
            }
        }
                                                                                                   
                                                                                                     
                                                                                                     
                                                                                                    
                                                                      
        for (field, val) in [
            ("[kernel].version", &self.kernel.version),
            ("[syslinux].version", &self.syslinux.version),
        ] {
            crate::sources::validate_source_component(val).map_err(|_| {
                PinsError::Format(format!(
                "{field} must be a valid source version component (1–32 of [a-z0-9._-], no leading \
                 dot — it splices into the fetch URL + the staged path), got {val:?}"
            ))
            })?;
        }
                                                                                                       
                                                                                                        
                                                                                                          
                                                       
        let ver = &self.rust.version;
        let ver_ok = ver.split('.').count() == 3
            && ver
                .split('.')
                .all(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
        if !ver_ok {
            return Err(PinsError::Format(format!(
                "[rust].version must be <major>.<minor>.<patch> ascii digits, got {ver:?}"
            )));
        }
                                                                                              
                                                                                                     
                                                                                                         
                                                                                                    
                                                                                            
        if !(self.rust.alpine_base.starts_with("alpine:")
            && self
                .rust
                .alpine_base
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b)))
        {
            return Err(PinsError::Format(format!(
                "[rust].alpine_base must be an alpine:<tag> ref, tag/URL-safe charset only (no \
                 shell/newline injection into the generated FROM line), got {:?}",
                self.rust.alpine_base
            )));
        }
        for (field, val) in [
            ("[rust].toolchain_musl_url", &self.rust.toolchain_musl_url),
            ("[rust].std_uefi_url", &self.rust.std_uefi_url),
        ] {
            if !(val.starts_with("https://static.rust-lang.org/dist/") && val.ends_with(".tar.xz"))
            {
                return Err(PinsError::Format(format!(
                    "{field} must be an https://static.rust-lang.org/dist/… .tar.xz url, got {val:?}"
                )));
            }
                                                                                                        
                                                                                                       
                                                                 
            if !val
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":/._-".contains(&b))
            {
                return Err(PinsError::Format(format!(
"{field} contains a non-URL-safe character (shell-injection guard), got {val:?}"
                )));
            }
        }
                                                                                                      
        validate_keyring_map(
            "kernel-keyring",
            "[kernel-keyring].<file>",
            &self.kernel_keyring,
        )?;
        validate_keyring_map("rust-keyring", "[rust-keyring].<file>", &self.rust_keyring)?;
        Ok(())
    }

    /// Load + parse `<repo_root>/pins.toml`.
    pub fn load(repo_root: &Path) -> Result<Self, PinsError> {
        let path = Self::manifest_path(repo_root);
        let s = std::fs::read_to_string(&path).map_err(|source| PinsError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&s)
    }

    /// The syslinux source tarball under a fetch dir: `<fetch_dir>/syslinux-<version>.tar.xz` — the
    /// path `orchard prime` stages and the `bake_boot_fs` B1 template build consumes (re-verified
                                                                                    
    /// pinned-source-tarball path from the central pin.
    pub fn syslinux_tarball_path(&self, fetch_dir: &Path) -> PathBuf {
        fetch_dir.join(format!("syslinux-{}.tar.xz", self.syslinux.version))
    }

    /// The kernel source TARBALL under a kbuild dir: `<kbuild_dir>/linux-<version>.tar.xz` — the
                                                                                                  
    /// extracts a FRESH per-build tree (no persistent `$KSRC`; the RW-tree race is closed). Mirrors
    /// [`Pins::syslinux_tarball_path`].
    pub fn kernel_tarball_path(&self, kbuild_dir: &Path) -> PathBuf {
        kbuild_dir.join(format!("linux-{}.tar.xz", self.kernel.version))
    }

    /// The fully-pinned build-container FROM base: `alpine:<tag>@<alpine_base_digest>` (Component C —
    /// the container is self-assembled on a plain Alpine, the PGP-verified rust toolchain installed atop
    /// it; the old `rust:<ver>-alpine` base is retired).
    pub fn alpine_base_ref(&self) -> String {
        format!("{}@{}", self.rust.alpine_base, self.rust.alpine_base_digest)
    }

    /// Render the canonical `rust-toolchain.toml` from `[rust].version`. This is the GENERATED file
    /// content; `sync-pins` writes it and the drift test asserts the on-disk file equals this exactly.
    pub fn render_rust_toolchain_toml(&self) -> String {
        format!(
            "# GENERATED FROM pins.toml by `orchard sync-pins` — DO NOT EDIT BY HAND.\n\
             # Bump [rust].version in pins.toml, then run `orchard sync-pins`; the image-builder\n\
             # tests/pins_drift.rs gate fails make verify if this file diverges. This pins the host /\n\
             # dev / CI toolchain (rustup auto-installs it on first cargo invocation); the box's musl\n\
             # binaries build in the Containerfile's alpine base + PGP-verified toolchain (pins.toml).\n\
             [toolchain]\n\
             channel = \"{}\"\n\
             components = [\"rustfmt\", \"clippy\"]\n",
            self.rust.version
        )
    }

    /// Render the GENERATED Rust-toolchain install block for the Containerfile (Component C §6): the
    /// marker-delimited `RUN` that fetches each PGP-verified component from its manifest-authenticated
                                                                                                   
    /// authenticity was established at bump; the container CANNOT run cashew, it has no rust yet), then
    /// runs the tarball's own `install.sh`. Includes the `# >>> … >>>`/`# <<< … <<<` markers so the
    /// block is a self-delimiting region `sync_containerfile` replaces + `check_drift` polices. The
    /// url+shas are NEVER hand-typed — they derive from `[rust]` here (§3a-5).
    pub fn render_containerfile_rust_block(&self) -> String {
        let v = &self.rust.version;
        format!(
            "{RUST_BLOCK_BEGIN}\n\
             RUN curl -fsSL -o rust-musl.tar.xz \"{musl_url}\" \\\n\
             \x20&& echo \"{musl_sha}  rust-musl.tar.xz\" | sha256sum -c - \\\n\
             \x20&& tar xJf rust-musl.tar.xz \\\n\
             \x20&& ./rust-{v}-x86_64-unknown-linux-musl/install.sh \
                 --components=rustc,cargo,rust-std-x86_64-unknown-linux-musl \\\n\
             \x20&& curl -fsSL -o rust-std-uefi.tar.xz \"{uefi_url}\" \\\n\
             \x20&& echo \"{uefi_sha}  rust-std-uefi.tar.xz\" | sha256sum -c - \\\n\
             \x20&& tar xJf rust-std-uefi.tar.xz \\\n\
             \x20&& ./rust-std-{v}-x86_64-unknown-uefi/install.sh \\\n\
             \x20&& rm -rf rust-musl.tar.xz rust-std-uefi.tar.xz \
                 rust-{v}-x86_64-unknown-linux-musl rust-std-{v}-x86_64-unknown-uefi\n\
             {RUST_BLOCK_END}",
            musl_url = self.rust.toolchain_musl_url,
            musl_sha = self.rust.toolchain_musl_sha256,
            uefi_url = self.rust.std_uefi_url,
            uefi_sha = self.rust.std_uefi_sha256,
        )
    }

    /// Return `containerfile` with (1) its single `FROM …` line replaced by [`Self::alpine_base_ref`]
    /// and (2) the `sync-pins` rust-block marker region replaced by [`Self::render_containerfile_rust_block`].
    /// Idempotent (a synced file maps to itself), so `check_drift` = "does applying this change
    /// anything". Fails closed unless the file has EXACTLY one `FROM` line and EXACTLY one well-ordered
    /// marker pair (a missing/duplicated anchor is a review event, never a silent partial sync).
    pub fn sync_containerfile(&self, containerfile: &str) -> Result<String, PinsError> {
        let is_from = |l: &str| l.trim_start().starts_with("FROM ");
        let from_count = containerfile.lines().filter(|l| is_from(l)).count();
        if from_count != 1 {
            return Err(PinsError::Format(format!(
                "Containerfile must have exactly one `FROM` line, found {from_count}"
            )));
        }
        let begin = containerfile
            .lines()
            .filter(|l| l.trim_end() == RUST_BLOCK_BEGIN)
            .count();
        let end = containerfile
            .lines()
            .filter(|l| l.trim_end() == RUST_BLOCK_END)
            .count();
        if begin != 1 || end != 1 {
            return Err(PinsError::Format(format!(
                "Containerfile must have exactly one sync-pins rust-block marker pair \
                 (found {begin} begin / {end} end)"
            )));
        }
        let from_ref = self.alpine_base_ref();
        let rendered = self.render_containerfile_rust_block();
        let had_trailing_nl = containerfile.ends_with('\n');
        let mut out: Vec<String> = Vec::new();
        let mut in_block = false;
        let mut seen_end_after_begin = false;
        for line in containerfile.lines() {
            let t = line.trim_end();
            if t == RUST_BLOCK_BEGIN {
                in_block = true;
                out.extend(rendered.lines().map(str::to_string));
                continue;
            }
            if t == RUST_BLOCK_END {
                                                                                  
                if !in_block {
                    return Err(PinsError::Format(
                        "Containerfile rust-block END precedes BEGIN".into(),
                    ));
                }
                in_block = false;
                seen_end_after_begin = true;
                continue;
            }
            if in_block {
                continue;                                                    
            }
            if is_from(line) {
                out.push(format!("FROM {from_ref}"));
            } else {
                out.push(line.to_string());
            }
        }
        if !seen_end_after_begin {
            return Err(PinsError::Format(
                "Containerfile rust-block markers are mis-ordered".into(),
            ));
        }
        let mut s = out.join("\n");
        if had_trailing_nl {
            s.push('\n');
        }
        Ok(s)
    }

    /// Verify the format-locked files agree with these pins; returns the list of drifted files
    /// (empty ⟹ in sync). The single shared check behind BOTH `deploy sync-pins --check` and the
    /// `tests/pins_drift.rs` make-verify gate, so the CLI and the test can never disagree. Covers the
    /// GENERATED `rust-toolchain.toml` and the synced `Containerfile` `FROM` (the two files rustup /
    /// Docker format-lock). The Alpine branch is apk-world.toml's concern, not this manifest's.
    pub fn check_drift(&self, repo_root: &Path) -> Result<Vec<String>, PinsError> {
        let read = |rel: &str| -> Result<String, PinsError> {
            let p = repo_root.join(rel);
            std::fs::read_to_string(&p).map_err(|source| PinsError::Io {
                path: p.display().to_string(),
                source,
            })
        };
        let mut drifted = Vec::new();

        if read("rust-toolchain.toml")? != self.render_rust_toolchain_toml() {
            drifted.push("rust-toolchain.toml".to_string());
        }
        let containerfile = read("crates/image-builder/Containerfile")?;
        if containerfile != self.sync_containerfile(&containerfile)? {
            drifted.push("crates/image-builder/Containerfile".to_string());
        }
        Ok(drifted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_BASE: &str = r#"
[kernel]
version = "6.18.34"
sha256 = "640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760"
[syslinux]
version = "6.04-pre1"
sha256 = "3f6d50a57f3ed47d8234fd0ab4492634eb7c9aaf7dd902f33d3ac33564fd631d"
[rust]
version = "1.96.0"
alpine_base = "alpine:3.23"
alpine_base_digest = "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
toolchain_musl_url = "https://static.rust-lang.org/dist/2026-05-28/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz"
toolchain_musl_sha256 = "8b4db404e24a82be906170b7b64bd69807e72e59d8371bac2a7f0ade75b39697"
std_uefi_url = "https://static.rust-lang.org/dist/2026-05-28/rust-std-1.96.0-x86_64-unknown-uefi.tar.xz"
std_uefi_sha256 = "dd8d565f061389cef66f64aa65bbfabe01954e360ada0b39f1e0d637d588e4f6"
container_digest = "sha256:66f48b19d6e88519e2e58bebe0d945779a6a4ca41c2db17db78c9569655b50ac"
"#;

    /// The canonical kernel keyring section (the real vendored-file shas — arbitrary for these tests).
    const SAMPLE_KEYRING: &str = "[kernel-keyring]\n\
         \"gregkh.asc\" = \"9dbf6e08cfd1b08c5123596091fdef160dc8ff4be9b1ee8e8b4113b04387f87c\"\n\
         \"sashal.asc\" = \"c4ed1898871201915d3e5f502925a877a43b772dab1eb93f0844f2d64584ac2a\"\n";

    /// The canonical rust keyring section (the real vendored `rust-signing.asc` sha256).
    const SAMPLE_RUST_KEYRING: &str = "[rust-keyring]\n\
         \"rust-signing.asc\" = \"e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b\"\n";

    /// Assemble a full sample from a (possibly-adversarial) kernel-keyring section — a valid
    /// `[rust-keyring]` is always appended so only the kernel section under test varies.
    fn sample_with(kernel_keyring: &str) -> String {
        format!("{SAMPLE_BASE}{kernel_keyring}{SAMPLE_RUST_KEYRING}")
    }

    fn pins() -> Pins {
        Pins::from_toml_str(&sample_with(SAMPLE_KEYRING)).expect("sample parses")
    }

    #[test]
    fn hostile_kernel_or_syslinux_version_fails_to_load() {
                                                                                                     
                                                                                   
        for bad in ["../6.1", "6.1/../etc", "6 1", ".hidden"] {
            let toml = sample_with(SAMPLE_KEYRING).replace("6.18.34", bad);
            assert!(
                Pins::from_toml_str(&toml).is_err(),
                "a hostile [kernel].version {bad:?} must be refused at parse"
            );
            let toml2 = sample_with(SAMPLE_KEYRING).replace("6.04-pre1", bad);
            assert!(
                Pins::from_toml_str(&toml2).is_err(),
                "a hostile [syslinux].version {bad:?} must be refused at parse"
            );
        }
    }

    #[test]
    fn parses_kernel_and_rust() {
        let p = pins();
        assert_eq!(p.kernel.version, "6.18.34");
        assert_eq!(p.kernel.sha256.len(), 64);
        assert_eq!(p.syslinux.version, "6.04-pre1");
        assert_eq!(p.syslinux.sha256.len(), 64);
        assert_eq!(p.rust.version, "1.96.0");
        assert_eq!(p.rust.alpine_base, "alpine:3.23");
        assert!(p.rust.alpine_base_digest.starts_with("sha256:"));
        assert!(p.rust.toolchain_musl_url.ends_with("linux-musl.tar.xz"));
        assert_eq!(p.rust.toolchain_musl_sha256.len(), 64);
        assert!(p.rust.std_uefi_url.ends_with("unknown-uefi.tar.xz"));
        assert_eq!(p.rust.std_uefi_sha256.len(), 64);
        assert!(p.rust.container_digest.starts_with("sha256:"));
        assert_eq!(p.kernel_keyring.len(), 2);
        assert_eq!(
            p.kernel_keyring["gregkh.asc"],
            "9dbf6e08cfd1b08c5123596091fdef160dc8ff4be9b1ee8e8b4113b04387f87c"
        );
        assert_eq!(p.rust_keyring.len(), 1);
        assert_eq!(
            p.rust_keyring["rust-signing.asc"],
            "e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b"
        );
    }

    #[test]
    fn rejects_missing_or_empty_rust_keyring() {
                                                                                         
        let no_rust = format!("{SAMPLE_BASE}{SAMPLE_KEYRING}");
        assert!(
            Pins::from_toml_str(&no_rust).is_err(),
            "a pins.toml without [rust-keyring] must be refused"
        );
        let empty_rust = format!("{SAMPLE_BASE}{SAMPLE_KEYRING}[rust-keyring]\n");
        assert!(
            Pins::from_toml_str(&empty_rust).is_err(),
            "an empty [rust-keyring] must be refused"
        );
    }

    #[test]
    fn rejects_malformed_rust_keyring_and_component_fields() {
                                                                                            
        let sha = "a".repeat(64);
        let bad_key =
            format!("{SAMPLE_BASE}{SAMPLE_KEYRING}[rust-keyring]\n\"../evil.asc\" = \"{sha}\"\n");
        assert!(
            Pins::from_toml_str(&bad_key).is_err(),
            "traversal keyring name must fail"
        );
                                                                                                      
        let bad_url = sample_with(SAMPLE_KEYRING).replace(
            "https://static.rust-lang.org/dist/2026-05-28/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz",
            "https://evil.example/rust.tar.xz",
        );
        assert!(matches!(
            Pins::from_toml_str(&bad_url),
            Err(PinsError::Format(_))
        ));
                                                
        let bad_sha = sample_with(SAMPLE_KEYRING).replace(
            "8b4db404e24a82be906170b7b64bd69807e72e59d8371bac2a7f0ade75b39697",
            "NOTASHA",
        );
        assert!(matches!(
            Pins::from_toml_str(&bad_sha),
            Err(PinsError::BadSha { .. })
        ));
    }

    #[test]
    fn rejects_shell_metacharacters_in_rust_url_or_version() {
                                                                                                 
                                                                                           
        let inject_url = sample_with(SAMPLE_KEYRING).replace(
            "https://static.rust-lang.org/dist/2026-05-28/rust-1.96.0-x86_64-unknown-linux-musl.tar.xz",
            "https://static.rust-lang.org/dist/$(touch pwned)/x.tar.xz",
        );
        assert!(
            matches!(Pins::from_toml_str(&inject_url), Err(PinsError::Format(_))),
            "a $()-bearing url (past the prefix/suffix check) must be refused"
        );
        let inject_ver = sample_with(SAMPLE_KEYRING)
            .replace("version = \"1.96.0\"", "version = \"1.96.0;touch x\"");
        assert!(
            matches!(Pins::from_toml_str(&inject_ver), Err(PinsError::Format(_))),
            "a shell-metacharacter version must be refused"
        );
                                                                                                        
        let inject_alpine = sample_with(SAMPLE_KEYRING).replace(
            "alpine_base = \"alpine:3.23\"",
            "alpine_base = \"alpine:3.23\\nRUN evil\"",
        );
        assert!(
            matches!(
                Pins::from_toml_str(&inject_alpine),
                Err(PinsError::Format(_))
            ),
            "a newline/shell-metacharacter alpine_base must be refused"
        );
    }

    #[test]
    fn rejects_missing_or_empty_kernel_keyring() {
                                                                                                  
                                                                         
        assert!(
            Pins::from_toml_str(SAMPLE_BASE).is_err(),
            "a pins.toml without [kernel-keyring] must be refused"
        );
        assert!(
            Pins::from_toml_str(&sample_with("[kernel-keyring]\n")).is_err(),
            "an empty [kernel-keyring] must be refused"
        );
    }

    #[test]
    fn rejects_malformed_keyring_entries() {
                                                                                                 
                                                                                                     
        let bad_sha = sample_with("[kernel-keyring]\n\"gregkh.asc\" = \"NOTASHA\"\n");
        assert!(matches!(
            Pins::from_toml_str(&bad_sha),
            Err(PinsError::BadSha { .. })
        ));
        let sha = "a".repeat(64);
        for bad_name in [
            "../evil.asc",
            "GregKH.asc",
            "key.pem",
            ".hidden.asc",
            "sub/dir.asc",
            "",
        ] {
            let s = sample_with(&format!("[kernel-keyring]\n\"{bad_name}\" = \"{sha}\"\n"));
            assert!(
                Pins::from_toml_str(&s).is_err(),
                "keyring key {bad_name:?} must be refused"
            );
        }
    }

    #[test]
    fn rejects_unknown_field_and_malformed_sha() {
                                                           
        let sample = sample_with(SAMPLE_KEYRING);
        let unknown = format!("{sample}[extra]\nx = 1\n");
        assert!(
            Pins::from_toml_str(&unknown).is_err(),
            "an unknown top-level table must be refused (deny_unknown_fields)"
        );
        let bad_kernel = sample.replace(
            "640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760",
            "NOTASHA",
        );
        assert!(matches!(
            Pins::from_toml_str(&bad_kernel),
            Err(PinsError::BadSha { .. })
        ));
        let bad_digest = sample.replace("sha256:66f48b19", "sha256:tooshort");
        assert!(matches!(
            Pins::from_toml_str(&bad_digest),
            Err(PinsError::BadSha { .. })
        ));
    }

                                                                                                     
                                                                                            
                                                                                    
                                 

    #[test]
    fn syslinux_tarball_path_is_fetchdir_slash_versioned_xz() {
        let p = pins();
        assert_eq!(
            p.syslinux_tarball_path(Path::new("/tmp/recipes-syslinux")),
            PathBuf::from("/tmp/recipes-syslinux/syslinux-6.04-pre1.tar.xz")
        );
    }

    #[test]
    fn kernel_tarball_path_is_kbuild_slash_versioned_xz() {
        let p = pins();
        assert_eq!(
            p.kernel_tarball_path(Path::new("/tmp/recipes-kbuild")),
            PathBuf::from("/tmp/recipes-kbuild/linux-6.18.34.tar.xz")
        );
    }

    #[test]
    fn render_rust_toolchain_carries_the_channel_and_generated_marker() {
        let out = pins().render_rust_toolchain_toml();
        assert!(out.contains("channel = \"1.96.0\""));
        assert!(out.contains("components = [\"rustfmt\", \"clippy\"]"));
        assert!(out.contains("DO NOT EDIT"), "must mark the file generated");
    }

    #[test]
    fn alpine_base_ref_pins_the_from_base() {
        assert_eq!(
            pins().alpine_base_ref(),
            "alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
        );
    }

    #[test]
    fn render_containerfile_rust_block_derives_url_and_shas_from_pins() {
        let p = pins();
        let block = p.render_containerfile_rust_block();
                                                                                   
        assert!(block.contains(&p.rust.toolchain_musl_url));
        assert!(block.contains(&p.rust.toolchain_musl_sha256));
        assert!(block.contains(&p.rust.std_uefi_url));
        assert!(block.contains(&p.rust.std_uefi_sha256));
                                                                                         
        assert!(block.contains("sha256sum -c -"));
        assert!(block.contains("rust-1.96.0-x86_64-unknown-linux-musl/install.sh"));
        assert!(block.contains("rust-std-1.96.0-x86_64-unknown-uefi/install.sh"));
        assert!(!block.contains("rustup"));
                                   
        assert!(block.starts_with(RUST_BLOCK_BEGIN));
        assert!(block.trim_end().ends_with(RUST_BLOCK_END));
    }

    #[test]
    fn sync_containerfile_replaces_from_and_the_rust_block_idempotently() {
        let p = pins();
        let input = format!(
            "# header\nFROM rust:1.94-alpine@sha256:dead\nRUN apk add curl\n\
             {RUST_BLOCK_BEGIN}\nRUN echo OLD-BLOCK\n{RUST_BLOCK_END}\nRUN command -v cargo\n",
        );
        let out = p.sync_containerfile(&input).unwrap();
                                                                                        
        assert!(out.contains(&format!("FROM {}", p.alpine_base_ref())));
        assert!(!out.contains("FROM rust:"));
        assert!(!out.contains("RUN echo OLD-BLOCK"));
        assert!(out.contains(&p.rust.toolchain_musl_sha256));
                                     
        assert!(out.contains("# header"));
        assert!(out.contains("RUN apk add curl"));
        assert!(out.contains("RUN command -v cargo"));
                                                                                             
        assert_eq!(p.sync_containerfile(&out).unwrap(), out);
    }

    #[test]
    fn sync_containerfile_fails_closed_on_bad_from_or_markers() {
        let p = pins();
        let block = format!("{RUST_BLOCK_BEGIN}\nRUN x\n{RUST_BLOCK_END}");
                        
        assert!(p.sync_containerfile(&format!("RUN a\n{block}\n")).is_err());
                          
        assert!(p
            .sync_containerfile(&format!("FROM a\nFROM b\n{block}\n"))
            .is_err());
                             
        assert!(p
            .sync_containerfile("FROM alpine:3.23@sha256:x\nRUN a\n")
            .is_err());
                                     
        assert!(p
            .sync_containerfile(&format!(
                "FROM a\n{RUST_BLOCK_BEGIN}\n{RUST_BLOCK_BEGIN}\nRUN x\n{RUST_BLOCK_END}\n"
            ))
            .is_err());
    }
}
