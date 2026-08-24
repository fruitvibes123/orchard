//! `orchard deploy-model` — the operator's one-intent model hotswap (hotswap v4 §5, plan Task 8):
//! pack + sign a model artifact (`Purpose::Weights`, operator key, off-box — box-never-signs) and
//! stream it to the box's `fb-weights swap` endpoint over ssh. The box runs the whole fail-closed
//! swap sequence (preflight → stop → teardown → write-verified raw write → runtime verity → real
//! inference health → atomic commit) and this verb reports its verdict FAITHFULLY:
//! COMMITTED / REFUSED (disk untouched) / DEGRADED (engine down, re-push restores) — never an
                                                                                   
//!
//! A DATA push, not an A/B rootfs update: it never touches `fb-update`, slots, floors, or the
//! (converged, separately-executed) appliance-compat guard — structurally, by never invoking them.
//!
//! The orchestration is host-tested over [`DeployModelOps`] (the `UpdateOps` mirror);
//! [`SshModelOps`] is the produced-bytes boundary the boot gate exercises. Known shared debt: the
//! push frame `Vec`-holds the model image (the streaming-installer class, same as the update
//! ceremony's framed pipe) — fine for bench-class models, a named limit for multi-GB ones.

use super::host_pins::{self, PinError, PinOutcome, PinnedKey};
use super::keys::DeployKeyError;
use super::update::{Authorize, CeremonyOpts};
use dragonfruit::Purpose;
use std::path::Path;

/// The FFI seam (the `UpdateOps` mirror): keyscan/pin, the explicit authorize, the ssh-exec push.
pub trait DeployModelOps {
    /// Keyscan the box → the `SHA256:…` fingerprint (the pin-store input).
    fn host_fingerprint(&self) -> Result<String, String>;
    /// The y/N gate (also carries first-contact pin assent).
    fn confirm_authorize(&self, summary: &str) -> Result<bool, String>;
    /// Stream the framed push to `fb-weights swap` (stdin over ssh); return the REMOTE exit code.
    fn fb_weights_swap(&self, framed: &[u8]) -> Result<i32, String>;
}

/// Everything derived locally before any remote contact: the packed weights image
/// (squashfs ‖ verity hash tree) + its identity + the canonical UNSIGNED manifest bytes.
pub struct PreparedModelPush {
    /// The full image the raw partition receives (padded squashfs ‖ hash tree).
    pub image: Vec<u8>,
    /// The canonical 4-line manifest (the artifact the Weights bundle signs).
    pub manifest: Vec<u8>,
    /// The dm-verity root hash (display/summary).
    pub root_hash: String,
    /// The source GGUF's sha256 hex + byte size (the operator-facing summary — what is being pushed).
    pub gguf_sha256: String,
    pub gguf_size: u64,
}

/// The swap's terminal verdict, mapped 1:1 from `fb-weights swap`'s exit contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelPushReport {
    /// Health-checked and committed (record + floor advanced). Exit 0.
    Committed,
    /// Preflight/teardown refusal — disk untouched, the OLD model still serves. Exit 3
    /// (or 19: the swap lock / box context was unavailable — equally nothing changed).
    Refused { detail: String },
    /// The old bytes are gone and the record was NOT advanced: the engine is down + visible; the
    /// box otherwise serves; re-push restores. Exit 4.
    Degraded { detail: String },
}

/// Pack the operator's GGUF into the weights image locally (docker: the SAME
/// `pack_weights_squashfs` + verity the bake uses — one packing, no drift) and render the
/// canonical manifest. No remote contact, no signing yet.
pub fn prepare_model_push(
    gguf: &Path,
    container_image: &str,
    repo_root: &Path,
) -> Result<PreparedModelPush, String> {
    use recipes_image_builder::build::BuildTools;
    let (gguf_sha256, gguf_size) = super::artifact_sign::streaming_sha256(gguf)
        .map(|h| {
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            (hex, std::fs::metadata(gguf).map(|m| m.len()).unwrap_or(0))
        })
        .map_err(|e| format!("deploy-model: hash {}: {e}", gguf.display()))?;

    let tools =
        recipes_image_builder::build_tools_host::HostBuildTools::new(container_image, repo_root);
                                                                                                
                                                                                               
                                                                                     
                                                                                                        
                                                                                                          
                                                                                   
    let squashfs = tools
        .pack_weights_squashfs(gguf, None, 0)
        .map_err(|e| format!("deploy-model: pack weights squashfs: {e}"))?;
    let verity = tools
        .build_verity(&squashfs)
        .map_err(|e| format!("deploy-model: verity over the weights squashfs: {e}"))?;
    let component =
        recipes_image_builder::image::build_rootfs_component(&squashfs, &verity.hash_tree);
    let manifest = recipes_image_builder::build::render_weights_manifest_bytes(
        &verity.root_hash,
        component.verity_hash_offset,
        &component.bytes,
    );
    Ok(PreparedModelPush {
        image: component.bytes,
        manifest,
        root_hash: verity.root_hash,
        gguf_sha256,
        gguf_size,
    })
}

/// Sign the manifest with the operator's `Purpose::Weights` delegation, routed through the
/// `plan_signing` rung matrix (spec debt-burndown Component C): raw custody signs on the host,
/// wrapped custody signs IN the pinned container (the operator types the passphrase there — the
/// host never buffers it), and the unsigned floor is a HARD error (the box always verifies; an
/// unsigned weights push does not exist). Fail-closed with the actionable
/// `orchard redelegate --purpose weights` message on a pre-hotswap key set (the
/// `sign_update_manifest` mirror).
pub fn sign_model_manifest(
    keys_dir: &Path,
    pin_path: &Path,
    manifest: &[u8],
) -> Result<Vec<u8>, String> {
    use super::artifact_sign::{SignPlan, plan_signing, sign_bytes};
    let plan = plan_signing(keys_dir, pin_path).map_err(|e| match e {
        DeployKeyError::MissingDelegation { .. } => e.to_string(),                              
        other => format!("deploy-model: cannot plan the manifest signing: {other}"),
    })?;
    match plan {
        SignPlan::Host(set) => sign_bytes(&set, Purpose::Weights, manifest).map_err(|e| match e {
            DeployKeyError::MissingDelegation { .. } => e.to_string(),
            other => format!("deploy-model: signing failed: {other}"),
        }),
        SignPlan::Docker => super::artifact_sign::docker_sign_manifest_bytes(
            keys_dir,
            Purpose::Weights,
            manifest,
            "model-manifest",
        ),
        SignPlan::UnsignedFloor => Err(
            "deploy-model: no artifact signing rung is configured (no keys, no committed \
             pinned-artifact-root.toml) — an unsigned weights push does not exist (the box \
             always verifies); run `orchard generate-keys --artifact-signing …` first"
                .to_string(),
        ),
    }
}

/// Frame the `fb-weights swap` push (the box-side `read_frame_header` contract):
/// `u64-le manifest_len ‖ manifest ‖ u64-le sig_len(=254) ‖ sig ‖ u64-le image_len ‖ image`.
pub fn frame_model_push(manifest: &[u8], sig: &[u8], image: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + manifest.len() + sig.len() + image.len());
    out.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    out.extend_from_slice(manifest);
    out.extend_from_slice(&(sig.len() as u64).to_le_bytes());
    out.extend_from_slice(sig);
    out.extend_from_slice(&(image.len() as u64).to_le_bytes());
    out.extend_from_slice(image);
    out
}

/// The push ceremony: pin the host key (non-silent first contact), summarize + EXPLICITLY
/// authorize, sign, stream, and map the box's exit contract to an honest report. Reuses the
/// update ceremony's [`CeremonyOpts`] (host / keys / authorize / host-pin store) verbatim.
/// `pin_path` is the committed `pinned-artifact-root.toml` (the durable rung-adopted marker
                                                                                               
pub fn run_model_ceremony(
    prepared: &PreparedModelPush,
    pin_path: &Path,
    opts: &CeremonyOpts<'_>,
    ops: &dyn DeployModelOps,
) -> Result<ModelPushReport, String> {
    let presented = ops.host_fingerprint()?;
    let _pin: PinnedKey = resolve_or_bootstrap_pin(opts, ops, &presented)?;

    let summary = format!(
        "deploy-model to {}: gguf sha256 {} ({} bytes) -> image {} bytes, verity root {}",
        opts.host,
        prepared.gguf_sha256,
        prepared.gguf_size,
        prepared.image.len(),
        prepared.root_hash,
    );
    let authorized = match opts.authorize {
        Authorize::Confirmed => true,
        Authorize::Interactive => ops.confirm_authorize(&summary)?,
    };
    if !authorized {
        return Err(
            "deploy-model: operator did not authorize the push — aborted (no changes made)"
                .to_string(),
        );
    }

    let sig = sign_model_manifest(opts.keys_dir, pin_path, &prepared.manifest)?;
    let framed = frame_model_push(&prepared.manifest, &sig, &prepared.image);
    let code = ops
        .fb_weights_swap(&framed)
        .map_err(|e| format!("deploy-model: streaming to fb-weights swap failed: {e}"))?;
    match code {
        0 => Ok(ModelPushReport::Committed),
        3 => Ok(ModelPushReport::Refused {
            detail: "the box refused the push (preflight/teardown — disk untouched, the old model \
                     still serves; see the box's stderr above)"
                .to_string(),
        }),
        19 => Ok(ModelPushReport::Refused {
            detail: "the box could not take the swap lock / assemble its context (a concurrent \
                     swap, or missing baked runbook files) — nothing changed"
                .to_string(),
        }),
        4 => Ok(ModelPushReport::Degraded {
            detail: "the swap DEGRADED past the point of no return: the engine is down + visible, \
                     the record was NOT advanced; re-push to restore (see the box's stderr above)"
                .to_string(),
        }),
        other => Err(format!(
            "deploy-model: fb-weights swap exited with unexpected code {other}"
        )),
    }
}

/// The update ceremony's pin resolve, mirrored (its own is private and update-coupled): stable pin
/// → proceed; first contact → interactive assent or an explicit `--host-fingerprint`; a CHANGED key
/// → hard refusal (never a silent re-pin).
fn resolve_or_bootstrap_pin(
    opts: &CeremonyOpts<'_>,
    ops: &dyn DeployModelOps,
    presented: &str,
) -> Result<PinnedKey, String> {
    match host_pins::resolve_host_pin(opts.host, presented, &opts.host_pin) {
        Ok(PinOutcome::Stable(k)) | Ok(PinOutcome::Bootstrapped(k)) => Ok(k),
        Err(PinError::FirstContactNeedsConfirm { presented, .. }) => {
            let ok = ops.confirm_authorize(&format!(
                "FIRST CONTACT with {}: trust the presented SSH host key {presented}? (this pins it)",
                opts.host
            ))?;
            if !ok {
                return Err(
                    "deploy-model: operator declined to trust the box's host key — aborted"
                        .to_string(),
                );
            }
            host_pins::commit_pin(opts.host, &presented, &opts.host_pin).map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The real ssh-backed ops (the produced-bytes boundary — `make boot-gate-hotswap`): the same
/// keyscan → pinned per-invocation `known_hosts` → hardened ssh argv discipline as
/// [`super::update::SshUpdateOps`]; the remote command is `fb-weights swap` reading the frame from
/// stdin, and the REMOTE exit code (ssh propagates it) is the verdict channel.
pub struct SshModelOps {
    pub host: String,
    pub port: u16,
    pub identity: std::path::PathBuf,
    pub is_tty: bool,
    host_key_line: std::cell::RefCell<Option<String>>,
}

impl SshModelOps {
    pub fn new(host: String, port: u16, identity: std::path::PathBuf, is_tty: bool) -> Self {
        SshModelOps {
            host,
            port,
            identity,
            is_tty,
            host_key_line: std::cell::RefCell::new(None),
        }
    }

    fn known_hosts_file(&self) -> Result<tempfile::NamedTempFile, String> {
        let line = self
            .host_key_line
            .borrow()
            .clone()
            .ok_or("deploy-model: internal — host key not captured before an ssh exec")?;
        let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("known_hosts temp: {e}"))?;
        use std::io::Write as _;
        writeln!(f, "{}", line.trim()).map_err(|e| format!("write known_hosts: {e}"))?;
        Ok(f)
    }
}

impl DeployModelOps for SshModelOps {
    fn host_fingerprint(&self) -> Result<String, String> {
        let out = std::process::Command::new("ssh-keyscan")
            .args(["-t", "ed25519", "-p", &self.port.to_string(), &self.host])
            .output()
            .map_err(|e| format!("ssh-keyscan: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text
            .lines()
            .find(|l| l.contains("ssh-ed25519") && !l.trim_start().starts_with('#'))
            .ok_or("ssh-keyscan returned no ed25519 host key")?
            .to_string();
        *self.host_key_line.borrow_mut() = Some(line.clone());
        let mut f = tempfile::NamedTempFile::new().map_err(|e| format!("keyscan temp: {e}"))?;
        use std::io::Write as _;
        writeln!(f, "{}", line.trim()).map_err(|e| format!("write keyscan: {e}"))?;
        let fpr_out = std::process::Command::new("ssh-keygen")
            .args(["-lf", &f.path().display().to_string()])
            .output()
            .map_err(|e| format!("ssh-keygen -lf: {e}"))?;
        String::from_utf8_lossy(&fpr_out.stdout)
            .split_whitespace()
            .find(|t| t.starts_with("SHA256:"))
            .map(str::to_string)
            .ok_or_else(|| "ssh-keygen produced no SHA256 fingerprint".to_string())
    }

    fn confirm_authorize(&self, summary: &str) -> Result<bool, String> {
        if !self.is_tty {
            return Err(
                "deploy-model: authorization needed but no tty — pass --confirmed (never a silent \
                 host-key TOFU)"
                    .to_string(),
            );
        }
        eprint!("{summary}\nProceed? [y/N] ");
        use std::io::Write as _;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("read confirmation: {e}"))?;
        Ok(matches!(line.trim(), "y" | "Y" | "yes"))
    }

    fn fb_weights_swap(&self, framed: &[u8]) -> Result<i32, String> {
        use std::io::Write as _;
        let known_hosts = self.known_hosts_file()?;
        let mut args = super::prod_orchestrate::prod_ssh_args(
            &self.host,
            &self.identity,
            known_hosts.path(),
            self.port,
        );
        args.push("fb-weights swap".to_string());
        let mut child = std::process::Command::new("ssh")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn ssh: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("ssh stdin unavailable")?
            .write_all(framed)
            .map_err(|e| format!("stream the push frame: {e}"))?;
        let status = child.wait().map_err(|e| format!("await ssh: {e}"))?;
        status
            .code()
            .ok_or_else(|| "ssh terminated without an exit code (signal?)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::artifact_keys::{Custody, generate_artifact_keys};
    use crate::deploy::host_pins::HostPinOpts;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;

    #[test]
    fn wrapped_custody_push_plans_docker_not_refusal() {
                                                                                     
                                                                                   
                                               
        use crate::deploy::artifact_sign::{SignPlan, plan_signing};
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        generate_artifact_keys(&keys, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();
        let plan = plan_signing(&keys, &dir.path().join("no-pin")).unwrap();
        assert!(matches!(plan, SignPlan::Docker));
    }

    #[test]
    fn push_with_no_rung_is_a_hard_actionable_error() {
                                                                                         
                                                                                 
        let dir = tempfile::tempdir().unwrap();
        let err = sign_model_manifest(
            &dir.path().join("no-keys"),
            &dir.path().join("no-pin"),
            b"m",
        )
        .unwrap_err();
        assert!(
            err.contains("unsigned weights push does not exist"),
            "{err}"
        );
        assert!(err.contains("generate-keys"), "not actionable: {err}");
    }

    struct FakeOps {
        captured: RefCell<Option<Vec<u8>>>,
        confirm: bool,
        exit_code: i32,
        confirms_asked: RefCell<Vec<String>>,
    }
    impl FakeOps {
        fn new(exit_code: i32) -> Self {
            FakeOps {
                captured: RefCell::new(None),
                confirm: true,
                exit_code,
                confirms_asked: RefCell::new(vec![]),
            }
        }
    }
    impl DeployModelOps for FakeOps {
        fn host_fingerprint(&self) -> Result<String, String> {
            Ok("SHA256:fakefingerprintfakefingerprintfakefingerpri".to_string())
        }
        fn confirm_authorize(&self, summary: &str) -> Result<bool, String> {
            self.confirms_asked.borrow_mut().push(summary.to_string());
            Ok(self.confirm)
        }
        fn fb_weights_swap(&self, framed: &[u8]) -> Result<i32, String> {
            self.captured.borrow_mut().replace(framed.to_vec());
            Ok(self.exit_code)
        }
    }

    fn prepared() -> PreparedModelPush {
                                                                                               
                                                                                             
                               
        let mut image = vec![0x77u8; 8192];
        image.extend_from_slice(&[0xCD; 256]);
        let manifest = recipes_image_builder::build::render_weights_manifest_bytes(
            &"ab".repeat(32),
            8192,
            &image,
        );
        PreparedModelPush {
            image,
            manifest,
            root_hash: "ab".repeat(32),
            gguf_sha256: "cd".repeat(32),
            gguf_size: 4096,
        }
    }

    fn opts<'a>(keys_dir: &'a Path, pin_store: &'a Path) -> CeremonyOpts<'a> {
        CeremonyOpts {
            host: "203.0.113.7",
            keys_dir,
            authorize: Authorize::Confirmed,
            host_pin: HostPinOpts {
                host_fingerprint: Some("SHA256:fakefingerprintfakefingerprintfakefingerpri"),
                is_tty: false,
                pin_dir: pin_store,
            },
        }
    }

    /// The full happy path: the framed push parses back per the box contract AND the signed
    /// manifest quince-verifies under Purpose::Weights against the minted operator root.
    #[test]
    fn ceremony_frames_a_quince_verifiable_weights_push() {
        let keys = tempfile::tempdir().unwrap();
        let pins = tempfile::tempdir().unwrap();
        generate_artifact_keys(keys.path(), 365, false, Custody::Raw).unwrap();
        let p = prepared();
        let ops = FakeOps::new(0);

        let report = run_model_ceremony(
            &p,
            &keys.path().join("no-pin"),
            &opts(keys.path(), pins.path()),
            &ops,
        )
        .unwrap();
        assert_eq!(report, ModelPushReport::Committed);

                                                                         
        let framed = ops.captured.borrow().clone().expect("frame captured");
        let u64at = |o: usize| u64::from_le_bytes(framed[o..o + 8].try_into().unwrap());
        let mlen = u64at(0) as usize;
        let manifest = &framed[8..8 + mlen];
        assert_eq!(manifest, &p.manifest[..]);
        let sig_off = 8 + mlen;
        assert_eq!(u64at(sig_off), 254, "sig_len field");
        let sig = &framed[sig_off + 8..sig_off + 8 + 254];
        let img_off = sig_off + 8 + 254;
        assert_eq!(u64at(img_off) as usize, p.image.len(), "image_len field");
        assert_eq!(
            &framed[img_off + 8..],
            &p.image[..],
            "image streamed verbatim"
        );

                                                                                                  
                                                                                            
        let root_pub = crate::deploy::artifact_keys::read_root_pub(keys.path()).unwrap();
        let artifact_hash: [u8; 32] = Sha256::digest(manifest).into();
        quince_like_verify(&root_pub, sig, &artifact_hash);
    }

    /// dragonfruit-level verify (orchard has no quince dep; same call quince makes).
    fn quince_like_verify(root_pub: &[u8; 32], sig: &[u8], artifact_hash: &[u8; 32]) {
        let bf = dragonfruit::BundleFile::from_bytes(sig).expect("254-byte bundle");
        dragonfruit::verify_bundle_no_window(
            &bf.as_bundle(),
            root_pub,
            artifact_hash,
            Purpose::Weights,
            0,
        )
        .expect("the pushed manifest must verify under Purpose::Weights");
    }

    #[test]
    fn refused_and_degraded_exit_codes_map_honestly() {
        let keys = tempfile::tempdir().unwrap();
        let pins = tempfile::tempdir().unwrap();
        generate_artifact_keys(keys.path(), 365, false, Custody::Raw).unwrap();
        let p = prepared();
        for (code, want_refused, want_degraded) in
            [(3, true, false), (19, true, false), (4, false, true)]
        {
            let ops = FakeOps::new(code);
            let report = run_model_ceremony(
                &p,
                &keys.path().join("no-pin"),
                &opts(keys.path(), pins.path()),
                &ops,
            )
            .unwrap();
            assert_eq!(
                matches!(report, ModelPushReport::Refused { .. }),
                want_refused,
                "code {code}"
            );
            assert_eq!(
                matches!(report, ModelPushReport::Degraded { .. }),
                want_degraded,
                "code {code}"
            );
        }
                                                                 
        let ops = FakeOps::new(77);
        assert!(
            run_model_ceremony(
                &p,
                &keys.path().join("no-pin"),
                &opts(keys.path(), pins.path()),
                &ops
            )
            .is_err()
        );
    }

    #[test]
    fn interactive_decline_aborts_before_any_push() {
        let keys = tempfile::tempdir().unwrap();
        let pins = tempfile::tempdir().unwrap();
        generate_artifact_keys(keys.path(), 365, false, Custody::Raw).unwrap();
        let p = prepared();
        let mut o = opts(keys.path(), pins.path());
        o.authorize = Authorize::Interactive;
        let mut ops = FakeOps::new(0);
        ops.confirm = false;
        let e = run_model_ceremony(&p, &keys.path().join("no-pin"), &o, &ops).unwrap_err();
        assert!(e.contains("did not authorize"), "{e}");
        assert!(
            ops.captured.borrow().is_none(),
            "nothing may be pushed without authorization"
        );
    }

    #[test]
    fn pre_weights_key_set_gives_the_redelegate_message() {
                                                                                                
                                                                                     
        let keys = tempfile::tempdir().unwrap();
        let pins = tempfile::tempdir().unwrap();
        generate_artifact_keys(keys.path(), 365, false, Custody::Raw).unwrap();
        std::fs::remove_file(keys.path().join("artifact-delegation-weights.bundle")).unwrap();
        let p = prepared();
        let ops = FakeOps::new(0);
        let e = run_model_ceremony(
            &p,
            &keys.path().join("no-pin"),
            &opts(keys.path(), pins.path()),
            &ops,
        )
        .unwrap_err();
        assert!(e.contains("redelegate"), "actionable cure: {e}");
        assert!(ops.captured.borrow().is_none());
    }
}
