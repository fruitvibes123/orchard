                                                                                                  
//! "am I ready to build/deploy?" and replaces the serial-refusal first-run experience. Advisory:
                                                                                                   
                                                                                                     
//! `market store status` (fail-honest, exit 0, no network — mirror drift stays `market outdated`'s job).
//!
//! This is the PURE model (Task 5): [`run_checks`] is a predicate over an injected [`Probes`] — tests
//! build it literally, no real docker/kvm. Task 6 adds `Probes::gather` (the real probing) + the CLI verb.

use std::path::{Path, PathBuf};

                                                                                                   
/// fails to RUN is Unknown, never Ok). `NA` = not applicable to this scope / this substrate (rendered `−`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckState {
    Ok,
    Fail,
    NA,
    Unknown(String),
}

                                                                                                      
/// the cure column is TOTAL over the Fail rows).
#[derive(Debug, Clone)]
pub struct Check {
    pub label: String,
    pub state: CheckState,
    pub cure: Option<String>,
}

impl Check {
    fn ok(label: impl Into<String>) -> Self {
        Check {
            label: label.into(),
            state: CheckState::Ok,
            cure: None,
        }
    }
    fn na(label: impl Into<String>) -> Self {
        Check {
            label: label.into(),
            state: CheckState::NA,
            cure: None,
        }
    }
    fn unknown(label: impl Into<String>, reason: impl Into<String>) -> Self {
        Check {
            label: label.into(),
            state: CheckState::Unknown(reason.into()),
            cure: None,
        }
    }
    fn fail(label: impl Into<String>, cure: &str) -> Self {
        Check {
            label: label.into(),
            state: CheckState::Fail,
            cure: Some(cure.into()),
        }
    }
}

/// Which verb's prerequisite set to scope the report to. `Full` (unscoped) = every row.
#[derive(Debug, Clone)]
pub enum Scope {
    Full,
    Build,
    Dryrun,
    Prod { image: Option<PathBuf> },
    BootGate,
}

fn scope_label(scope: &Scope) -> &'static str {
    match scope {
        Scope::Full => "full",
        Scope::Build => "build",
        Scope::Dryrun => "dryrun",
        Scope::Prod { .. } => "prod",
        Scope::BootGate => "boot-gate",
    }
}

                                                                                                             
const CURE_DOCKER: &str = "install docker + build the pinned image (guide §4.1): docker build -t recipes-imgbuild:dev -f crates/image-builder/Containerfile crates/image-builder";
const CURE_KVM: &str = "enable virtualization + join the kvm group so /dev/kvm is usable";
const CURE_BOOT_TOOLS: &str = "install the boot-verification tools via your distro (qemu-system-x86_64, veritysetup, ssh, curl)";
const CURE_BUILD_TOOLS: &str =
    "install the build tools via your distro (fakeroot, mke2fs / e2fsprogs)";
const CURE_CERT_KEYS: &str = "orchard generate-keys";
const CURE_ARTIFACT_SIGNING: &str = "orchard generate-keys --artifact-signing software (or docker); if the keys live elsewhere, pass --keys-dir";
const CURE_PRIME: &str = "orchard prime (or make prime)";
const CURE_VENDOR: &str = "make vendor; run market verify for detail";
const CURE_TMP: &str = "free /tmp (~15-20 GB needed); clear leaked root-owned tempdirs: docker run --rm -v /tmp:/t recipes-imgbuild:dev sh -c 'rm -rf /t/.tmp*'";
const CURE_GIT: &str = "commit crates/image-builder/pinned-cert-fingerprints.toml (the generate-keys write), or pass --allow-dirty";
const CURE_PROD_SIDECARS: &str = "rebuild the image (orchard build) so the .layout.toml/.sha256 sidecars are complete for this --image";
const CURE_PROD_FPR: &str =
    "the .fpr sidecar is written by build/sign — rebuild or re-sign the image";
const CURE_PROD_IDENTITY: &str = "check the identity paths exist (--ssh-identity / --pubkey)";

/// Fold a tri-state probe: `Some(true)`→Ok, `Some(false)`→Fail(cure), `None`→Unknown(reason).
fn tri(label: impl Into<String>, probe: Option<bool>, cure: &str, unknown_reason: &str) -> Check {
    let label = label.into();
    match probe {
        Some(true) => Check::ok(label),
        Some(false) => Check::fail(label, cure),
        None => Check::unknown(label, unknown_reason),
    }
}

/// A grouped PATH-tools check: any un-probeable tool ⇒ Unknown; else Fail listing the missing ones; else Ok.
fn grouped_tools_check(label: &str, tools: &[(&str, Option<bool>)], cure: &str) -> Check {
    if tools.iter().any(|(_, s)| s.is_none()) {
        return Check::unknown(label, "a PATH probe could not run");
    }
    let missing: Vec<&str> = tools
        .iter()
        .filter(|(_, s)| *s == Some(false))
        .map(|(n, _)| *n)
        .collect();
    if missing.is_empty() {
        Check::ok(label)
    } else {
        Check::fail(format!("{label} (missing: {})", missing.join(", ")), cure)
    }
}

fn docker_check(p: &Probes) -> Check {
    if !p.docker_invokable {
        Check::fail("docker invokable", CURE_DOCKER)
    } else if !p.container_image_present {
        Check::fail(
            "pinned build image present (recipes-imgbuild:dev)",
            CURE_DOCKER,
        )
    } else {
        Check::ok("docker invokable + pinned build image present")
    }
}

fn kvm_check(p: &Probes) -> Check {
    tri(
        "/dev/kvm usable",
        p.kvm_probe,
        CURE_KVM,
        "could not probe /dev/kvm",
    )
}

fn boot_tools_check(p: &Probes) -> Check {
    let tools = [
        ("qemu-system-x86_64", p.qemu_on_path),
        ("veritysetup", p.veritysetup_on_path),
        ("ssh", p.ssh_on_path),
        ("curl", p.curl_on_path),
    ];
    grouped_tools_check("boot-verification tools on PATH", &tools, CURE_BOOT_TOOLS)
}

fn build_tools_check(p: &Probes) -> Check {
    let tools = [
        ("fakeroot", p.fakeroot_on_path),
        ("mke2fs", p.mke2fs_on_path),
    ];
    grouped_tools_check("build tools on PATH", &tools, CURE_BUILD_TOOLS)
}

fn cert_key_set_check(p: &Probes) -> Check {
                                                                                                          
    if !p.cert_key_set_present {
        Check::fail("operator cert key set present", CURE_CERT_KEYS)
    } else if !p.cert_key_set_loadable {
        Check::fail(
            "operator cert key set present but NOT loadable (corrupt?)",
            CURE_CERT_KEYS,
        )
    } else {
        Check::ok("operator cert key set (present + loadable)")
    }
}

fn artifact_signing_check(p: &Probes) -> Check {
                                                                                                          
    if !p.artifact_signing_pinned {
        Check::na("artifact-signing rung not pinned — builds UNSIGNED (a legitimate floor)")
    } else {
        tri(
            "artifact-signing rung (pinned + loadable)",
            p.artifact_signing_loadable,
            CURE_ARTIFACT_SIGNING,
            "could not load the artifact key set",
        )
    }
}

fn sb_family_check(p: &Probes) -> Check {
                                                                                                        
    if p.sb_family_present {
        Check::ok("Secure Boot key family present")
    } else {
        Check::na(
            "Secure Boot key family absent (only needed for --firmware uefi: generate-keys --secure-boot software)",
        )
    }
}

fn primed_source_check(p: &Probes) -> Check {
    if !p.kernel_primed_present || !p.syslinux_primed_present {
        return Check::fail("primed kernel/syslinux source present", CURE_PRIME);
    }
    match (p.kernel_primed_matches_pins, p.syslinux_primed_matches_pins) {
        (Some(true), Some(true)) => {
            Check::ok("primed kernel + syslinux source (present + matches pins.toml)")
        }
        (Some(false), _) | (_, Some(false)) => {
            Check::fail("primed source does NOT match pins.toml (stale)", CURE_PRIME)
        }
        _ => Check::unknown(
            "primed source matches pins.toml",
            "could not verify the primed source sha against pins.toml",
        ),
    }
}

fn vendor_check(p: &Probes) -> Check {
    tri(
        "vendor/ + store consistency",
        p.vendor_store_consistent,
        CURE_VENDOR,
        "could not run the vendor/store scan",
    )
}

fn tmp_check(p: &Probes) -> Check {
    match p.tmp_headroom_ok {
        None => Check::unknown(
            "/tmp headroom (~15-20 GB)",
            "could not stat /tmp free space",
        ),
        Some(false) => Check::fail("/tmp headroom (~15-20 GB)", CURE_TMP),
                                                                                                             
        Some(true) if p.tmp_leaked_tempdirs => Check::fail(
            "/tmp has leaked root-owned .tmp* dirs (they eat build headroom)",
            CURE_TMP,
        ),
        Some(true) => Check::ok("/tmp headroom (~15-20 GB)"),
    }
}

fn git_check(p: &Probes) -> Check {
    tri(
        "git tree clean (build-affecting)",
        p.git_tree_clean,
        CURE_GIT,
        "could not run git status",
    )
}

fn prod_sidecars_check(p: &Probes, image: Option<&Path>) -> Check {
    let label = match image {
        Some(img) => format!("prod image triple + sidecars complete ({})", img.display()),
        None => "prod image triple + sidecars complete".to_string(),
    };
    tri(
        label,
        p.prod_image_sidecars_complete,
        CURE_PROD_SIDECARS,
        "no --image given",
    )
}

fn prod_fpr_check(p: &Probes) -> Check {
    tri(
        "prod .fpr sidecar present",
        p.prod_fpr_sidecar_present,
        CURE_PROD_FPR,
        "no --image given",
    )
}

fn prod_identity_check(p: &Probes) -> Check {
    tri(
        "prod identity files exist",
        p.prod_identity_files_exist,
        CURE_PROD_IDENTITY,
        "could not stat the identity paths",
    )
}

/// The injected facts the predicates read. `bool` = always probeable; `Option<bool>` = the probe may
/// fail to RUN (`None` ⇒ Unknown). Production fills it via `Probes::gather` (Task 6); tests build it literally.
#[derive(Debug, Clone)]
pub struct Probes {
    pub docker_invokable: bool,
    pub container_image_present: bool,
    pub kvm_probe: Option<bool>,
    pub qemu_on_path: Option<bool>,
    pub veritysetup_on_path: Option<bool>,
    pub ssh_on_path: Option<bool>,
    pub curl_on_path: Option<bool>,
    pub fakeroot_on_path: Option<bool>,
    pub mke2fs_on_path: Option<bool>,
    pub cert_key_set_present: bool,
    pub cert_key_set_loadable: bool,
    pub artifact_signing_pinned: bool,
    pub artifact_signing_loadable: Option<bool>,
    pub sb_family_present: bool,
    pub kernel_primed_present: bool,
    pub kernel_primed_matches_pins: Option<bool>,
    pub syslinux_primed_present: bool,
    pub syslinux_primed_matches_pins: Option<bool>,
    pub vendor_store_consistent: Option<bool>,
    pub tmp_headroom_ok: Option<bool>,
    pub tmp_leaked_tempdirs: bool,
    pub git_tree_clean: Option<bool>,
    pub prod_image_sidecars_complete: Option<bool>,
    pub prod_fpr_sidecar_present: Option<bool>,
    pub prod_identity_files_exist: Option<bool>,
}

impl Probes {
    /// A fixture where every probe passes — tests start here and poke individual fields.
    pub fn all_present_for_test() -> Self {
        Probes {
            docker_invokable: true,
            container_image_present: true,
            kvm_probe: Some(true),
            qemu_on_path: Some(true),
            veritysetup_on_path: Some(true),
            ssh_on_path: Some(true),
            curl_on_path: Some(true),
            fakeroot_on_path: Some(true),
            mke2fs_on_path: Some(true),
            cert_key_set_present: true,
            cert_key_set_loadable: true,
            artifact_signing_pinned: true,
            artifact_signing_loadable: Some(true),
            sb_family_present: true,
            kernel_primed_present: true,
            kernel_primed_matches_pins: Some(true),
            syslinux_primed_present: true,
            syslinux_primed_matches_pins: Some(true),
            vendor_store_consistent: Some(true),
            tmp_headroom_ok: Some(true),
            tmp_leaked_tempdirs: false,
            git_tree_clean: Some(true),
            prod_image_sidecars_complete: Some(true),
            prod_fpr_sidecar_present: Some(true),
            prod_identity_files_exist: Some(true),
        }
    }
}

/// Build the scoped readiness rows. `Full` = every row; each verb scope = its prerequisite subset
                                                                                                       
pub fn run_checks(p: &Probes, scope: &Scope) -> Vec<Check> {
    let mut checks = Vec::new();
                                                                                                        
    checks.push(docker_check(p));
    checks.push(cert_key_set_check(p));
    checks.push(primed_source_check(p));

    match scope {
        Scope::Full => {
            checks.push(kvm_check(p));
            checks.push(boot_tools_check(p));
            checks.push(build_tools_check(p));
            checks.push(artifact_signing_check(p));
            checks.push(sb_family_check(p));
            checks.push(vendor_check(p));
            checks.push(tmp_check(p));
            checks.push(git_check(p));
        }
        Scope::Build => {
            checks.push(build_tools_check(p));
            checks.push(artifact_signing_check(p));
            checks.push(vendor_check(p));
            checks.push(tmp_check(p));
            checks.push(git_check(p));
        }
        Scope::Dryrun => {
            checks.push(kvm_check(p));
            checks.push(boot_tools_check(p));
        }
        Scope::Prod { image } => {
                                                                                               
            checks.push(kvm_check(p));
            checks.push(build_tools_check(p));
            checks.push(artifact_signing_check(p));
            checks.push(tmp_check(p));
            checks.push(git_check(p));
            checks.push(prod_sidecars_check(p, image.as_deref()));
            checks.push(prod_fpr_check(p));
            checks.push(prod_identity_check(p));
        }
        Scope::BootGate => {
            checks.push(kvm_check(p));
            checks.push(boot_tools_check(p));
            checks.push(tmp_check(p));
        }
    }
    checks
}

/// Render the report: `✓`/`✗`/`−`/`? … could not check (reason)`, the exact cure on every `✗`, and a
/// closing tally. Advisory only — the caller ALWAYS exits 0 regardless of what this contains.
pub fn render(checks: &[Check], scope: &Scope) -> String {
    let mut s = format!("orchard doctor — {} readiness\n\n", scope_label(scope));
    for c in checks {
        match &c.state {
            CheckState::Ok => s.push_str(&format!("  \u{2713} {}\n", c.label)),
            CheckState::NA => s.push_str(&format!("  \u{2212} {}\n", c.label)),
            CheckState::Unknown(reason) => {
                s.push_str(&format!("  ? {} — could not check ({reason})\n", c.label))
            }
            CheckState::Fail => {
                s.push_str(&format!("  \u{2717} {}\n", c.label));
                if let Some(cure) = &c.cure {
                    s.push_str(&format!("      \u{2192} {cure}\n"));
                }
            }
        }
    }
    let fails = checks
        .iter()
        .filter(|c| c.state == CheckState::Fail)
        .count();
    let unknowns = checks
        .iter()
        .filter(|c| matches!(c.state, CheckState::Unknown(_)))
        .count();
    s.push('\n');
    if fails == 0 && unknowns == 0 {
        s.push_str("ready.\n");
    } else {
        s.push_str(&format!(
            "{fails} unmet, {unknowns} unverifiable — see the cures above (advisory; exit 0).\n"
        ));
    }
    s
}

                                                                                                 
  
                                                                                                     
                                                                                                       
                                                                                                    
                                                                        

use std::io::Read;
use std::process::{Command, Stdio};

/// Is `bin` an executable on `$PATH`? `None` iff `$PATH` is unreadable (the probe couldn't run).
fn on_path(bin: &str) -> Option<bool> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if let Ok(md) = candidate.metadata()
            && md.is_file()
            && md.permissions().mode() & 0o111 != 0
        {
            return Some(true);
        }
    }
    Some(false)
}

/// Stream-hash a file to lowercase-hex sha256 (64 KiB chunks — no whole-file buffering).
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// `true` iff a command runs and exits 0 (output discarded). Missing binary ⇒ `false`.
fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Free GiB on `/tmp` via `df -Pk /tmp` (portable). `None` if `df` cannot run / parse.
fn tmp_free_gib() -> Option<f64> {
    let out = Command::new("df").args(["-Pk", "/tmp"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
                                                             
    let avail_kb: f64 = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()?;
    Some(avail_kb / (1024.0 * 1024.0))
}

/// Any root-owned `/tmp/.tmp*` entry — the leaked-build-tempdir class the guide's cleanup line targets.
fn scan_leaked_tmp() -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(rd) = std::fs::read_dir("/tmp") else {
        return false;
    };
    rd.flatten().any(|e| {
        e.file_name().to_string_lossy().starts_with(".tmp")
            && e.metadata().map(|m| m.uid() == 0).unwrap_or(false)
    })
}

/// git working tree clean? `None` iff `git status` cannot run.
fn git_clean(repo_root: &Path) -> Option<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout.is_empty())
}

                                                                                                    
/// A present-but-corrupt `.key` (truncated PEM, garbled header) must FAIL the readiness check, never
/// a false ✓ — so a non-empty check is NOT enough. Best-effort: a `.key` that cannot be read or
/// parsed ⇒ false; all three parsing ⇒ true. Reuses the crate's existing `rcgen` dep (no new crate).
fn cert_key_set_parses(keys_dir: &Path) -> bool {
    use rcgen::KeyPair;
    ["image-signing.key", "signing-ca.key", "ima.key"]
        .iter()
        .all(|f| {
            std::fs::read_to_string(keys_dir.join(f))
                .ok()
                .and_then(|pem| KeyPair::from_pem(&pem).ok())
                .is_some()
        })
}

impl Probes {
    /// Probe the live host best-effort. `keys_dir` = the operator key set dir; `repo_root` = the
    /// orchard checkout (passed in — `repo_root()` lives in the binary). Never panics; advisory only.
    pub fn gather(scope: &Scope, keys_dir: &Path, repo_root: &Path) -> Probes {
        use recipes_image_builder::pins::Pins;

        let docker_invokable = cmd_ok("docker", &["info"]);
        let container_image_present =
            docker_invokable && cmd_ok("docker", &["image", "inspect", "recipes-imgbuild:dev"]);

        let cert_key_set_present = super::keys::signing_set_exists(keys_dir);
                                                                                                   
                                                                                                 
                                                                             
        let cert_key_set_loadable = cert_key_set_present
            && super::keys::SIGNING_FILES.iter().all(|f| {
                std::fs::metadata(keys_dir.join(f))
                    .map(|m| m.len() > 0)
                    .unwrap_or(false)
            })
            && cert_key_set_parses(keys_dir);

                                                                                                                
        let artifact_signing_pinned = super::artifact_keys::read_root_pub(keys_dir).is_ok();
        let artifact_signing_loadable = artifact_signing_pinned
            .then(|| super::artifact_keys::load_artifact_keys(keys_dir).is_ok());

        let sb_family_present = super::secure_boot_keys::SECURE_BOOT_FILES
            .iter()
            .all(|f| keys_dir.join(f).exists());

                                                                                          
        let pins = Pins::load(repo_root).ok();
        let primed = |path: PathBuf, want_sha: Option<&str>| -> (bool, Option<bool>) {
            let present = path.exists();
            let matches = if present {
                match (sha256_file(&path).ok(), want_sha) {
                    (Some(h), Some(w)) => Some(h == w),
                    _ => None,
                }
            } else {
                None
            };
            (present, matches)
        };
        let (kernel_primed_present, kernel_primed_matches_pins) = match &pins {
            Some(p) => primed(
                p.kernel_tarball_path(Path::new(super::build_image::DEFAULT_KBUILD_DIR)),
                Some(&p.kernel.sha256),
            ),
            None => (false, None),
        };
        let (syslinux_primed_present, syslinux_primed_matches_pins) = match &pins {
            Some(p) => primed(
                p.syslinux_tarball_path(Path::new(super::build_image::DEFAULT_SYSLINUX_DIR)),
                Some(&p.syslinux.sha256),
            ),
            None => (false, None),
        };

                                                                                                           
        let vendor_store_consistent = match std::fs::read_dir(repo_root.join("vendor")) {
            Ok(rd) => Some(rd.filter_map(|e| e.ok()).count() >= 4),
            Err(_) => Some(false),
        };

        let tmp_headroom_ok = tmp_free_gib().map(|gib| gib >= 20.0);
        let tmp_leaked_tempdirs = scan_leaked_tmp();
        let git_tree_clean = git_clean(repo_root);

                                                                                                       
                                                                     
        let (prod_image_sidecars_complete, prod_fpr_sidecar_present) = match scope {
            Scope::Prod { image: Some(img) } if img.exists() => (
                Some(
                    img.with_extension("layout.toml").exists()
                        && img.with_extension("sha256").exists(),
                ),
                Some(img.with_extension("operator-pubkey.fpr").exists()),
            ),
                                                                                                     
            Scope::Prod { image: Some(_) } => (Some(false), Some(false)),
                                                                       
            Scope::Prod { image: None } => (None, None),
            _ => (Some(true), Some(true)),                                                         
        };

        Probes {
            docker_invokable,
            container_image_present,
            kvm_probe: Some(Path::new("/dev/kvm").exists()),
            qemu_on_path: on_path("qemu-system-x86_64"),
            veritysetup_on_path: on_path("veritysetup"),
            ssh_on_path: on_path("ssh"),
            curl_on_path: on_path("curl"),
            fakeroot_on_path: on_path("fakeroot"),
            mke2fs_on_path: on_path("mke2fs"),
            cert_key_set_present,
            cert_key_set_loadable,
            artifact_signing_pinned,
            artifact_signing_loadable,
            sb_family_present,
            kernel_primed_present,
            kernel_primed_matches_pins,
            syslinux_primed_present,
            syslinux_primed_matches_pins,
            vendor_store_consistent,
            tmp_headroom_ok,
            tmp_leaked_tempdirs,
            git_tree_clean,
            prod_image_sidecars_complete,
            prod_fpr_sidecar_present,
            prod_identity_files_exist: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_good() -> Probes {
        Probes::all_present_for_test()
    }

    #[test]
    fn every_fail_carries_a_cure() {
        let mut p = all_good();
        p.docker_invokable = false;
        p.cert_key_set_loadable = false;
        let checks = run_checks(&p, &Scope::Full);
        for c in &checks {
            if matches!(c.state, CheckState::Fail) {
                assert!(c.cure.is_some(), "fail check {:?} has no cure", c.label);
            }
        }
                                                                
        assert!(checks.iter().any(|c| matches!(c.state, CheckState::Fail)));
    }

    #[test]
    fn an_unprobeable_check_is_unknown_never_ok() {
        let mut p = all_good();
        p.kvm_probe = None;                 
        let checks = run_checks(&p, &Scope::Full);
        let kvm = checks.iter().find(|c| c.label.contains("kvm")).unwrap();
        assert!(
            matches!(kvm.state, CheckState::Unknown(_)),
            "unprobeable kvm must be Unknown, not Ok"
        );
    }

    #[test]
    fn prod_scope_checks_the_image_sidecars() {
        let mut p = all_good();
        p.prod_image_sidecars_complete = Some(false);
        let checks = run_checks(
            &p,
            &Scope::Prod {
                image: Some("/tmp/x.img".into()),
            },
        );
        assert!(
            checks
                .iter()
                .any(|c| c.label.contains("sidecar") && matches!(c.state, CheckState::Fail))
        );
    }

    #[test]
    fn cert_set_check_requires_loadable_not_just_present() {
        let mut p = all_good();
        p.cert_key_set_present = true;
        p.cert_key_set_loadable = false;                       
        let checks = run_checks(&p, &Scope::Full);
        let cert = checks
            .iter()
            .find(|c| c.label.contains("cert key set"))
            .unwrap();
        assert!(
            matches!(cert.state, CheckState::Fail),
            "present-but-unloadable cert set must FAIL"
        );
    }

    #[test]
    fn render_reports_could_not_check_for_unknown_and_never_a_false_ok() {
        let mut p = all_good();
        p.vendor_store_consistent = None;                       
        let checks = run_checks(&p, &Scope::Full);
        let out = render(&checks, &Scope::Full);
        assert!(
            out.contains("could not check"),
            "unprobeable renders honestly:\n{out}"
        );
    }

    #[test]
    fn healthy_full_scope_renders_ready_and_exit0_posture() {
        let checks = run_checks(&all_good(), &Scope::Full);
                                         
        assert!(!checks.iter().any(|c| matches!(c.state, CheckState::Fail)));
        assert!(render(&checks, &Scope::Full).contains("ready"));
    }

    #[test]
    fn cert_key_set_parses_rejects_a_garbled_key() {
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let good = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem();
        for f in ["image-signing.key", "signing-ca.key", "ima.key"] {
            std::fs::write(dir.path().join(f), &good).unwrap();
        }
        assert!(
            cert_key_set_parses(dir.path()),
            "three valid PEM keys parse"
        );
        std::fs::write(
            dir.path().join("ima.key"),
            "-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(!cert_key_set_parses(dir.path()), "a garbled key FAILS");
    }
}
