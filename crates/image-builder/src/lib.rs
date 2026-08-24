//! Operator-side image builder: fetch + verify + extract pinned Alpine apks, behind a
                                                                                         
                                                                                    
//!
//! The Alpine apk v2 format (empirically confirmed on a real 3.23 `musl` apk; the wiki
//! Apk_spec is WIP, so the genuine apk is the authority): three concatenated gzip streams
//! — signature segment ‖ control segment ‖ data tarball. Verification:
                                                                                             
//!   2. RSA PKCS#1 v1.5 signature (in the `.SIGN.RSA.<key>` record) over `sha1(control
                                                                                                 
//!   3. `.PKGINFO` `datahash == sha256(data tarball)` — ties the data to the signed control.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// Custom-kernel build driver + the build-time CONFIG assertion (Task 1.3).
pub mod kernel;
                                                                                                   
/// bake's verify-at-consumption and orchard's `kernel_bump`.
pub mod sources;

/// IMA/EVM signing orchestration (Task 1.4): the file-signing scope + the evmctl differential-test oracle.
pub mod ima_evm;

/// R.4 (3/n): the in-tree DETERMINISTIC IMA/EVM signer (RFC-6979 ECDSA) that replaces evmctl in the build.
pub mod ima_evm_signer;

/// Deterministic squashfs rootfs assembly (Task 1.4).
pub mod squashfs;

                                                                                                           
pub mod ownership;

                                                                                                         
/// write it onto the RO rootfs under `/opt/<dir>/…` with escape-proof semantics + declared mode/owner.
pub mod staged_files;

/// Rescue-host-key-seed write (Task 1.4): derives via the Task 1.1 crate, bakes 0600 into staging.
pub mod rescue_seed;

/// dm-verity hash-tree generation (Task 1.5): deterministic via fixed salt + fixed uuid.
pub mod verity;

/// In-image config generation + build-time assertions (Task 1.7): the spec-pinned dropbear/haproxy/
/// ima-policy/fstab content the builder stages, and the no-PAM / no-forbidden-component checks.
pub mod config;

/// The dha orchestrator config render (box.json + runtime.json → dha-owned 0600 rootfs data).
pub mod config_render;

                                                                                                  
/// (`run` scripts), the `.s6-svscan` shutdown/signal handlers, nftables, and the box env, as static
/// fns. Emitted onto the signed rootfs by `build_init_tree`; box-init + s6-svscan supervise it at boot
/// (the bootstrap/rescue oneshots live in the `box-init` crate, not here).
pub mod service_tree;

                                                                                                 
/// the `.layout.toml` wire enum. BOTH firmwares are built — UEFI's boot artifact is the rambutan SB
/// loader (OVMF-boot-proven); only the production substrate (real UEFI HW + enrollment) is deferred.
pub mod firmware;

/// The central version manifest (`pins.toml`): the kernel + rust build-input pins, read at runtime.
/// The kernel path derives from it; `deploy sync-pins` generates rust-toolchain.toml + the
/// Containerfile `FROM` from it; `tests/pins_drift.rs` gates no-drift. (Alpine lives in apk-world.toml.)
pub mod pins;

/// The model-weights pin manifest (`models.toml`): the sha256-pinned GGUF build input for the dha
/// tenant's RO dm-verity weights volume (Component E). Analogous to [`pins`]; the bake verifies the
/// operator-supplied GGUF against it before wrapping it in squashfs + dm-verity.
pub mod models;

/// The configured owning-repo manifest (`repo-manifest.toml`): `repo -> { path, artifacts }`. Replaces
/// the hardcoded `OWNERS` const + fixes the recipes-path; `market verify` asserts its artifact set
/// EXACTLY equals `consume-pins`'s. The `market` pin-store tool's new (fail-closed) verify root.
pub mod repo_manifest;

/// Pin provenance (lifted from `tests/pins_provenance.rs`): each consume-pin sha == the owning repo's
/// `published-pins` sha, manifest-driven; an absent owning repo is a hard fail unless `--allow-missing`.
/// The §3a-1 leg of `market verify`.
pub mod provenance;

/// Cross-repo seed agreement (lifted from `tests/pins_agree.rs`): every repo's `pins.toml` byte-matches
/// seed-vault's canonical. The §3a-2 leg of `market verify`.
pub mod seed_agree;

/// `market verify`'s reusable store checks: §3a-4 config re-derive, §3a-5 format-lock drift, §3a-6 apk
/// closure shape-lock (over the existing `Pins::check_drift` + `PinnedApks` machinery).
pub mod store_checks;

                                                                                                      
/// value without a `certifies-pin`/`superseded-by` marker or a file-level allowlist entry. Wired hot in
/// Task 8 (after the operational-rule retrofit); the self-test runs against a synthetic fixture tree.
pub mod cert_presence;

/// `.img` assembly + layout (Task 2.3): pad-squashfs-to-4096 + concat
/// `vmlinuz‖initramfs‖rootfs.verity` + the `.layout.toml` offset sidecar. Pure +
                                                                            
pub mod image;

/// Boot-fs `extlinux.conf` APPEND rendering + the O3 `rootfs-dev` byte-patch sentinel (installer
/// redesign): the runtime cmdline is baked into the boot partition fs at build time; the deploy CLI
/// byte-patches the per-target device into the sentinel field before scp. Pure + host-tested.
pub mod boot_fs;

/// §9.5 UEFI signed-USB installer: the pure-Rust GPT serializer for the installer USB's 2-partition
/// layout (ESP + ext4 data). A sibling of `initramfs_init::installer::build_gpt` (target-disk layout) —
/// it shares only the mixed-endian/CRC-32/header/pMBR/backup encoding convention, ported byte-for-byte.
pub mod gpt;

/// §9.5: assemble the installer USB `.img` — lay the baked ESP (p1) + ext4 data (p2) onto a GPT disk
/// (`assemble_usb_image`), and orchestrate producing those partitions (`build_installer_usb`, follows).
pub mod installer_usb;

/// `deploy build` orchestration (Task 2.3): wires steps 2-13 behind the
/// `BuildTools` seam, emitting the UNSIGNED `.img` triple (the `.sig` is Phase-4/5a
/// forward-debt). The orchestration logic is unit-tested with fake tools.
pub mod build;

/// Production `BuildTools` impl (Task 2.3-R.2): shells out to the pinned Alpine build
/// container. The orchestration logic is fake-tested; this seam is integration-verified.
pub mod build_tools_host;

                                                                                               
/// backup pair + two-dimensional sizing + baked-identity self-checks. Fronted by the thin
/// `orchard restore-image` CLI verb; the container bake leg lives in [`build_tools_host`].
pub mod restore_image;

/// The hand-maintained `apk-world.toml` (intent) parser — input to the lock generator.
pub mod apk_world;

/// Host-side apk drift scan (market comfort): pinned-vs-mirror classification for `market
/// outdated`, the reactive build-404 signpost, and the `--dry-run` preview. ADVISORY + off the
/// trust path; fail-soft; bounded; sanitized output.
pub mod apk_drift;

/// The apk-lock generator (`deploy refresh-apk-lock`): world → resolved-closure lock, behind a
/// resolver seam. Verify-before-record provenance; the production container resolver lands separately.
pub mod generate_lock;

                                                                                                      
/// + required-fields (the §5.3 fail-closed discipline). The typed wire format both publish and consume
/// agree on; Orchard verifies every consumed artifact's sha256 against it before baking.
pub mod pin_manifest;

                                                                                                  
/// handle is constructible only through a passing sha256 check, so un-verified bytes can't reach the
/// bake. `DirStore` is the only backend now; a `ReleaseAssetsStore` is a designed-for future drop-in.
pub mod artifact_store;

                                                                                                   
/// consume-side counterpart to publish's source tarballs — fetch+verify (the artifact_store gate) then
/// unpack into vendor/, which Orchard's Cargo.toml path-points at.
pub mod vendor;

/// Source-agnostic package acquisition seam (R1 sovereignty requirement, memory
                                                                                          
/// trait, so the upstream (Alpine today) stays a swappable provider. A provider fetches the
/// pinned package, verifies provenance + immutability, and extracts its files into staging.
/// Fails closed on any verification failure.
pub trait PackageProvider {
    fn acquire(&self, pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    #[error("fetch failed for {0}")]
    Fetch(String),
    #[error("content-hash mismatch for {pkg}: expected {expected}, got {got}")]
    ContentHash {
        pkg: String,
        expected: String,
        got: String,
    },
    #[error("signature verification failed for {pkg}: {reason}")]
    Signature { pkg: String, reason: String },
    #[error("data integrity (datahash) mismatch for {0}")]
    DataHash(String),
    #[error("apk format error: {0}")]
    Format(String),
    #[error("extraction failed: {0}")]
    Extract(#[source] std::io::Error),
}

/// One pinned package — a row of `image-builder/pinned-apks.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PinnedPackage {
    pub name: String,
    pub version: String,
                                                                                   
    pub sha256: String,
    /// `<key_name>` of the Alpine signing key (matches a `<key_name>.rsa.pub` trust anchor).
    pub signing_key: String,
}

/// The `pinned-apks.toml` document: the GENERATED lock (full runtime closure + the
/// build/boot-input pins), produced from `apk-world.toml` by `deploy refresh-apk-lock`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PinnedApks {
    pub alpine_version: String,
    /// The runtime-services closure — every package extracted into the rootfs squashfs.
    #[serde(default, rename = "package")]
    pub packages: Vec<PinnedPackage>,
    /// Build/boot-INPUT pins (`linux-virt` → kernel `config-virt`; `syslinux` → deploy-time
    /// bootloader install). Fetched + verified like runtime packages, but NEVER extracted into
    /// the rootfs — they are build/deploy inputs, not runtime components (box-apk-closure spec
    /// §Finding 2026-05-27). `default` so an older single-section lock still parses.
    #[serde(default, rename = "build_input")]
    pub build_inputs: Vec<PinnedPackage>,
}

impl PinnedApks {
    pub fn from_toml_str(s: &str) -> Result<Self, AcquireError> {
        toml::from_str(s).map_err(|e| AcquireError::Format(format!("pinned-apks.toml: {e}")))
    }
}

#[cfg(test)]
mod pinned_apks_tests {
    use super::*;

    #[test]
    fn parses_runtime_and_build_input_sections() {
        let toml = r#"
alpine_version = "3.23"
[[package]]
name = "musl"
version = "1.2.5-r23"
sha256 = "aa"
signing_key = "k"
[[build_input]]
name = "linux-virt"
version = "6.18.34-r0"
sha256 = "bb"
signing_key = "k"
"#;
        let p = PinnedApks::from_toml_str(toml).unwrap();
        assert_eq!(p.packages.len(), 1, "runtime [[package]] rows");
        assert_eq!(p.packages[0].name, "musl");
        assert_eq!(p.build_inputs.len(), 1, "[[build_input]] rows");
        assert_eq!(p.build_inputs[0].name, "linux-virt");
    }

    #[test]
    fn build_inputs_defaults_empty_for_older_single_section_locks() {
        let p = PinnedApks::from_toml_str("alpine_version = \"3.23\"\n").unwrap();
        assert!(p.packages.is_empty());
        assert!(p.build_inputs.is_empty(), "build_inputs is optional");
    }
}

/// Trusted Alpine signing keys: `<key_name>` -> RSA public key (SPKI PEM bytes). Operator
/// pins these (the `/etc/apk/keys/*.rsa.pub` set) so the trust anchor is operator-owned.
pub type TrustedKeys = HashMap<String, Vec<u8>>;

/// A verified apk's extractable payload — the gzipped data tarball (stream 3). The private
/// field means a `VerifiedApk` can ONLY be produced by [`verify_apk`]: holding one is proof
/// the provenance + immutability checks passed.
pub struct VerifiedApk {
    data_tarball_gz: Vec<u8>,
}

/// Verify an apk's immutability + provenance (offline; the security core). Order: cheap
/// immutability gate first, then provenance signature, then the data-integrity chain. Fails closed.
pub fn verify_apk(
    apk_bytes: &[u8],
    pin: &PinnedPackage,
    trusted_keys: &TrustedKeys,
) -> Result<VerifiedApk, AcquireError> {
                                                                                             
    let got = sha256_hex(apk_bytes);
    if got != pin.sha256 {
        return Err(AcquireError::ContentHash {
            pkg: pin.name.clone(),
            expected: pin.sha256.clone(),
            got,
        });
    }
                                                                                           
    let (signer, verified) = verify_apk_provenance(apk_bytes, trusted_keys, &pin.name)?;
                                                                                                      
                                                                 
    if signer != pin.signing_key {
        return Err(AcquireError::Signature {
            pkg: pin.name.clone(),
            reason: format!(
                "apk signed by '{signer}', pin expects '{}'",
                pin.signing_key
            ),
        });
    }
    Ok(verified)
}

                                                                                               
/// chain — against the trusted key set, returning the signer's `<key_name>` and the extractable
/// payload. Unlike [`verify_apk`] this carries NO sha256 immutability pin: the lock generator
/// (`deploy refresh-apk-lock`) verifies provenance and THEN records the computed sha256 (the pin
/// doesn't exist yet at generate-time — a compromised mirror can't inject a bad sha256 because the
/// signature is checked first). [`verify_apk`] layers its sha256 gate on top of this. `pkg` is the
/// package name, for error context only. Fails closed.
pub fn verify_apk_provenance(
    apk_bytes: &[u8],
    trusted_keys: &TrustedKeys,
    pkg: &str,
) -> Result<(String, VerifiedApk), AcquireError> {
                                                                                 
    let members = split_gzip_members(apk_bytes)?;
    if members.len() != 3 {
        return Err(AcquireError::Format(format!(
            "expected 3 gzip streams (signature/control/data), found {}",
            members.len()
        )));
    }
    let sig_segment = &members[0].1;                                      
    let control_compressed = members[1].0;                                                        
    let control_segment = &members[1].1;                                    
    let data_compressed = members[2].0;                                      

                                                                                                   
                                                                                                      
    let (key_name, signature) = parse_sign_segment(sig_segment)?;
    let pubkey_pem = trusted_keys
        .get(&key_name)
        .ok_or_else(|| AcquireError::Signature {
            pkg: pkg.to_string(),
            reason: format!("signing key '{key_name}' is not in the trusted set"),
        })?;
                                                                             
    rsa_pkcs1_sha1_verify(pubkey_pem, control_compressed, &signature).map_err(|reason| {
        AcquireError::Signature {
            pkg: pkg.to_string(),
            reason,
        }
    })?;

                                                                                     
    let datahash = parse_pkginfo_datahash(control_segment)?;
    if sha256_hex(data_compressed) != datahash {
        return Err(AcquireError::DataHash(pkg.to_string()));
    }

    Ok((
        key_name,
        VerifiedApk {
            data_tarball_gz: data_compressed.to_vec(),
        },
    ))
}

/// Extract a verified apk's data tarball into `staging_root`. Control scripts are never run
/// (we supply our own init + configs — spec step 4, "skip Alpine post-install hooks").
pub fn extract(verified: &VerifiedApk, staging_root: &Path) -> Result<(), AcquireError> {
                                                                                       
                                                                                      
                                                                                 
    let gz = flate2::read::GzDecoder::new(&verified.data_tarball_gz[..]);
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(staging_root)
        .map_err(AcquireError::Extract)?;
    Ok(())
}

/// Fetches raw bytes for a URL — the network seam, injected so `acquire`'s orchestration
/// (URL building + verify + extract) is testable offline. Production uses [`HttpFetcher`].
pub trait Fetcher {
    /// `Err` = not-found (e.g. HTTP 404, so the caller tries the next repo) or transport error.
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;

                                                                                                    
    /// ADDITIVE: the default is a plain atomic [`Fetcher::get`] with ZERO ticks, so every existing
    /// impl (apk / musl / the test maps) is unchanged; only [`HttpFetcher`] overrides it to stream
    /// the body and tick from the response's `Content-Length`. `total` is a best-effort hint (the
    /// running length when the server omits `Content-Length`), never a gate.
    fn get_with_progress(
        &self,
        url: &str,
        _tick: &mut dyn FnMut(u64, u64),
    ) -> Result<Vec<u8>, String> {
        self.get(url)
    }
}

/// The reactive drift hook (market comfort §5.3): `name -> Some(mirror-current version)` for a pin
/// known GONE from the mirror; the version string is pre-sanitized [`apk_drift`] output.
pub type DriftLookup = Box<dyn Fn(&str) -> Option<String>>;

/// The Alpine-apk implementation of the acquisition seam.
pub struct AlpineApkProvider<F: Fetcher> {
    pub alpine_version: String,
    pub trusted_keys: TrustedKeys,
    pub fetcher: F,
    /// Consulted ONLY on a fetch failure — to name pin-drift + the cure in the error message —
    /// never on the accept path (the happy path is unchanged, and verify decisions never read
    /// it). `None`, or a lookup answering `None`, leaves the plain fetch error untouched
    /// (advisory + fail-soft by construction).
    pub drift_lookup: Option<DriftLookup>,
}

impl<F: Fetcher> AlpineApkProvider<F> {
    /// Candidate dl-cdn URLs for a pinned apk — `main` then `community`, tried in order.
    fn apk_urls(&self, pin: &PinnedPackage) -> [String; 2] {
        let url = |repo: &str| {
            format!(
                "https://dl-cdn.alpinelinux.org/alpine/v{}/{}/x86_64/{}-{}.apk",
                self.alpine_version, repo, pin.name, pin.version
            )
        };
        [url("main"), url("community")]
    }
}

impl<F: Fetcher> PackageProvider for AlpineApkProvider<F> {
    fn acquire(&self, pin: &PinnedPackage, staging_root: &Path) -> Result<(), AcquireError> {
        let mut last_err = "no repository tried".to_string();
        let mut fetched = None;
        for url in self.apk_urls(pin) {
            match self.fetcher.get(&url) {
                Ok(bytes) => {
                    fetched = Some(bytes);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let bytes = match fetched {
            Some(b) => b,
            None => {
                                                                                                   
                                                                                                   
                                                                                               
                                                                     
                let plain = format!("{}: {last_err}", pin.name);
                let msg = match self.drift_lookup.as_ref().and_then(|look| look(&pin.name)) {
                    Some(avail) => format!(
                        "{}-{} is no longer on the mirror (it now serves {avail}) — the pin aged \
                         off. This is pin-drift, not a build bug: run `orchard market outdated` \
                         to see all drift, then `orchard market upgrade --apks` to re-pin (you \
                         review + commit the diff). (underlying fetch error: {plain})",
                        pin.name, pin.version
                    ),
                    None => plain,
                };
                return Err(AcquireError::Fetch(msg));
            }
        };
                                                                                         
        let verified = verify_apk(&bytes, pin, &self.trusted_keys)?;
        extract(&verified, staging_root)
    }
}

/// Production fetcher: HTTPS GET via `ureq` (rustls + ring; no openssl / native-tls / aws-lc,
/// enforced by the workspace surface-cut sentry). Hardened against an untrusted mirror: a body
/// cap (no OOM before verify; with ureq's auto-decompress features off there is no gzip-bomb
/// amplification either) and connect/read timeouts (no slow-loris hang). A non-2xx status is a
/// soft error so the caller falls through to the next repo (`main` → `community`).
pub struct HttpFetcher {
    agent: ureq::Agent,
    /// Body ceiling — reject-not-truncate (the +1 read in `get`). `new()` = the apk-sized default;
    /// a larger pinned artifact (the kernel `.tar.xz`) gets a purpose-sized cap via
    /// [`HttpFetcher::with_body_cap`] (F-2ES-R1-6 — parameterize, don't inflate the apk default).
    max_body_bytes: u64,
}

impl HttpFetcher {
    /// Body ceiling — far above the largest pinned apk (~15 MB), far below build-machine RAM.
    const MAX_APK_BYTES: u64 = 64 * 1024 * 1024;

    pub fn new() -> Self {
        Self::with_body_cap(Self::MAX_APK_BYTES)
    }

    /// A fetcher with a caller-sized body ceiling (still reject-not-truncate; same transport
    /// hardening) — the kernel-bump path fetches a ~150 MB `.tar.xz`, far over the apk default.
    pub fn with_body_cap(max_body_bytes: u64) -> Self {
        let agent = ureq::builder()
            .timeout_connect(std::time::Duration::from_secs(15))
            .timeout_read(std::time::Duration::from_secs(120))
            .build();
        Self {
            agent,
            max_body_bytes,
        }
    }

    #[cfg(test)]
    pub(crate) fn body_cap(&self) -> u64 {
        self.max_body_bytes
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpFetcher {
    /// The shared read core: stream the body in chunks (never a silent truncation — the `+1` over
    /// the cap makes an over-limit body an error), ticking `(done, total)` per chunk. `get` passes a
    /// no-op tick; `get_with_progress` passes the caller's. `total` is `Content-Length` when present,
    /// else the running length (a hint, not a gate — the cap is the only enforced bound).
    fn read_body(&self, url: &str, tick: &mut dyn FnMut(u64, u64)) -> Result<Vec<u8>, String> {
        match self.agent.get(url).call() {
            Ok(resp) => {
                let total = resp
                    .header("Content-Length")
                    .and_then(|s| s.parse::<u64>().ok());
                let mut reader = resp.into_reader().take(self.max_body_bytes + 1);
                let mut buf = Vec::new();
                let mut chunk = vec![0u8; 256 * 1024];
                loop {
                    let n = reader
                        .read(&mut chunk)
                        .map_err(|e| format!("read body: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let done = buf.len() as u64;
                    tick(done, total.unwrap_or(done).max(done));
                }
                if buf.len() as u64 > self.max_body_bytes {
                    return Err(format!("body exceeds {}-byte cap", self.max_body_bytes));
                }
                Ok(buf)
            }
            Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
            Err(e) => Err(format!("transport: {e}")),
        }
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.read_body(url, &mut |_done, _total| {})
    }

    fn get_with_progress(
        &self,
        url: &str,
        tick: &mut dyn FnMut(u64, u64),
    ) -> Result<Vec<u8>, String> {
        self.read_body(url, tick)
    }
}

                      

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A split gzip member: its raw compressed bytes (a slice of the apk) + its decompressed content.
type GzipMember<'a> = (&'a [u8], Vec<u8>);

/// Split a buffer of concatenated gzip members into `(compressed_slice, decompressed)` per
/// member. APK v2 = 3 members (signature, control, data); the control member's *compressed*
/// bytes are exactly what the signature covers, so the byte boundaries are load-bearing.
fn split_gzip_members(buf: &[u8]) -> Result<Vec<GzipMember<'_>>, AcquireError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut rest: &[u8] = &buf[offset..];
        let before = rest.len();
        let mut dec = flate2::bufread::GzDecoder::new(&mut rest);
        let mut decompressed = Vec::new();
        dec.read_to_end(&mut decompressed)
            .map_err(|e| AcquireError::Format(format!("gzip stream {}: {e}", out.len())))?;
        drop(dec);
        let consumed = before - rest.len();
        if consumed == 0 {
            break;
        }
        out.push((&buf[offset..offset + consumed], decompressed));
        offset += consumed;
    }
    Ok(out)
}

/// Parse the signature tar segment: returns the signer `<key_name>` (from the
/// `.SIGN.RSA.<key_name>.rsa.pub` record name) and the raw RSA signature bytes (its content).
fn parse_sign_segment(decompressed: &[u8]) -> Result<(String, Vec<u8>), AcquireError> {
    let mut archive = tar::Archive::new(decompressed);
    let mut entries = archive
        .entries()
        .map_err(|e| AcquireError::Format(format!("signature segment: {e}")))?;
    let mut entry = entries
        .next()
        .ok_or_else(|| AcquireError::Format("signature segment is empty".into()))?
        .map_err(|e| AcquireError::Format(format!("signature record: {e}")))?;
    let name = entry
        .path()
        .map_err(|e| AcquireError::Format(format!("signature record name: {e}")))?
        .to_string_lossy()
        .into_owned();
    let key_name = name
        .strip_prefix(".SIGN.RSA.")
        .and_then(|s| s.strip_suffix(".rsa.pub"))
        .ok_or_else(|| AcquireError::Format(format!("unexpected signature record name: {name}")))?
        .to_string();
    let mut signature = Vec::new();
    entry
        .read_to_end(&mut signature)
        .map_err(|e| AcquireError::Format(format!("signature read: {e}")))?;
    Ok((key_name, signature))
}

/// Find `.PKGINFO` in the control tar segment and return its `datahash` value (hex sha256).
fn parse_pkginfo_datahash(decompressed: &[u8]) -> Result<String, AcquireError> {
    let mut archive = tar::Archive::new(decompressed);
    let entries = archive
        .entries()
        .map_err(|e| AcquireError::Format(format!("control segment: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| AcquireError::Format(format!("control record: {e}")))?;
        let name = entry
            .path()
            .map_err(|e| AcquireError::Format(format!("control record name: {e}")))?
            .to_string_lossy()
            .into_owned();
        if name == ".PKGINFO" {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| AcquireError::Format(format!(".PKGINFO read: {e}")))?;
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("datahash = ") {
                    return Ok(v.trim().to_string());
                }
            }
            return Err(AcquireError::Format(
                ".PKGINFO has no datahash field".into(),
            ));
        }
    }
    Err(AcquireError::Format(
        ".PKGINFO not found in control segment".into(),
    ))
}

/// RSA PKCS#1 v1.5 signature verification over SHA-1 of `message`, against an SPKI-PEM pubkey.
///
/// NOTE: the `rsa` crate carries RUSTSEC-2023-0071 (Marvin timing sidechannel), which applies
/// ONLY to RSA *decryption* — a private-key operation. This path does public-key *verification*
/// only (no secret, no timing oracle), so the advisory is not applicable here. (Audit note,
/// Task 1.2 spot.) Alpine apk v2 signs with SHA-1; the load-bearing immutability gate is our
/// SHA-256 content-hash pin, with this signature as provenance / defense-in-depth.
fn rsa_pkcs1_sha1_verify(
    pubkey_pem: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::Pkcs1v15Sign;
    use sha1::{Digest, Sha1};

    let pem = std::str::from_utf8(pubkey_pem).map_err(|e| format!("pubkey not UTF-8: {e}"))?;
    let key =
        rsa::RsaPublicKey::from_public_key_pem(pem).map_err(|e| format!("parse pubkey: {e}"))?;
    let digest = Sha1::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, signature)
        .map_err(|e| format!("RSA verify failed: {e}"))
}

#[cfg(test)]
mod internal_tests {
    //! Unit tests reaching private internals — the rejection paths the public-API
                                                                          
    use super::*;

    #[test]
    fn http_fetcher_cap_is_parameterized() {
                                                                                                 
                                           
        assert_eq!(HttpFetcher::new().body_cap(), 64 * 1024 * 1024);
        assert_eq!(HttpFetcher::with_body_cap(7).body_cap(), 7);
    }
    use std::io::Write as _;

    fn gz(buf: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(buf).unwrap();
        e.finish().unwrap()
    }

    fn tar_one(name: &str, content: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, content).unwrap();
        b.into_inner().unwrap()
    }

    /// Build a one-entry tar with an UNVALIDATED name (writing the raw header name field to
    /// bypass `Builder::append_data`'s `..` rejection) so we can craft a path-traversal entry
    /// and exercise the *extractor's* guard rather than the builder's.
    fn tar_one_unchecked(name: &str, content: &[u8]) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        let nb = name.as_bytes();
        h.as_mut_bytes()[..nb.len()].copy_from_slice(nb);                                
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, content).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn pkginfo_without_datahash_is_format_error() {
        let control = tar_one(".PKGINFO", b"pkgname = x\npkgver = 1\n");
        assert!(matches!(
            parse_pkginfo_datahash(&control),
            Err(AcquireError::Format(_))
        ));
    }

    #[test]
    fn pkginfo_missing_is_format_error() {
        let control = tar_one("not-pkginfo", b"whatever");
        assert!(matches!(
            parse_pkginfo_datahash(&control),
            Err(AcquireError::Format(_))
        ));
    }

    #[test]
    fn sign_segment_non_sign_first_entry_is_format_error() {
        let seg = tar_one("not-a-sign-record", b"xxx");
        assert!(matches!(
            parse_sign_segment(&seg),
            Err(AcquireError::Format(_))
        ));
    }

    #[test]
    fn extract_refuses_parent_traversal() {
                                                                                              
                                                                                               
                                                                                                  
                                                  
        let verified = VerifiedApk {
            data_tarball_gz: gz(&tar_one_unchecked("../escaped", b"pwned")),
        };
        let base = std::env::temp_dir().join(format!("rib-traversal-{}", std::process::id()));
        let staging = base.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let _ = extract(&verified, &staging);                                                 
        let leaked = base.join("escaped").exists();
        std::fs::remove_dir_all(&base).ok();
        assert!(!leaked, "path traversal escaped the staging dir");
    }
}
