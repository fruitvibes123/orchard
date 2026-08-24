                                                                                  
//!
//! Boots a from-pins REFERENCE recipes box (`-kernel`, the [`super::runtime::boot_and_verify`]
//! path — a serving box whose operator SSH is root) and drives the two coupled components on the
//! real, re-pinned `fb-oneshots` / `fb-acme` binaries + the periodic_loop `service-manifest`:
//!
                                                                                                  
                                                                                                  
                                                                                                  
                                                                                             
                                                                                                     
                                                                                                   
                                                                                          
                                                                                                          
                                                                                           
                                                                                               
                                                                                          
                                                                                                
                                                                                            
//!
//! The renewer cadence is a full day (86400 s), so the gate can't wait for a natural cycle: it runs
//! the EXACT scheduled loop-body (`s6-envdir … s6-setuidgid fb-acme … fb-acme renew …`) once over
//! SSH — which IS one cycle on the real binary — and reads the decision off stdout.
//!
//! Certs are minted host-side with `openssl` (no new orchard dep) and pushed atomically over SSH.
//! `#[ignore]`-gated in `orchard/tests/deploy_acme_lifecycle.rs`; run via `make boot-gate-acme`.

use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use super::assertions::assert_recipes_http;
use super::qemu::*;
use super::*;

/// Boot the reference box and run every cert-lifecycle leg against it. Holds the QEMU guard to the
/// end so the VM stays up through all SSH/TLS assertions, then tears down on drop.
pub fn boot_acme_lifecycle_and_verify(img: &Path, opts: &DryrunOpts) -> Result<(), DryrunError> {
    preflight()?;
    require_openssl()?;

                                                                                                      
                                                                                                         
                                                                                                      
                                                                                  
    let hermetic = DryrunOpts {
        restrict_net: true,
        ..opts.clone()
    };
    let opts = &hermetic;

    let layout = parse_layout(&layout_sidecar(img))?;
    let workdir = tempfile::Builder::new()
        .prefix("recipes-acme-gate-")
        .tempdir()
        .map_err(DryrunError::io("creating acme-gate workdir"))?;
    let wd = workdir.path();

                                                                                                   
                                                                                              
    let vmlinuz = local_artifact(img, "vmlinuz")?;
    let initramfs = local_artifact(img, "initramfs")?;
    let rootfs = wd.join("rootfs");
    let rootfs_data = wd.join("rootfs-data");
    slice(img, layout.rootfs_offset, layout.rootfs_size, &rootfs)?;
    slice(
        img,
        layout.rootfs_offset,
        layout.rootfs_verity_hash_offset,
        &rootfs_data,
    )?;
    let root_hash = recompute_verity_root_hash(&rootfs_data, &wd.join("verity.hash"))?;

    let privkey = wd.join("id");
    let pubkey = wd.join("id.pub");
    ssh_keygen(&privkey)?;
    let persist = wd.join("persist.img");
    super::runtime::stage_persist_disk(&pubkey, wd, &persist)?;

    let console = wd.join("console.log");
    let mut guard = launch_qemu(
        &vmlinuz,
        &initramfs,
        &rootfs,
        &persist,
        &root_hash,
        layout.rootfs_verity_hash_offset,
        opts,
        &console,
    )?;

    wait_for_ssh(
        &privkey,
        opts.ssh_port,
        opts.boot_timeout,
        &mut guard,
        &console,
    )?;
                                                                                           
    assert_recipes_http(opts, &mut guard)?;

    let port = opts.ssh_port;
    let https = opts.https_port;
                                                                                           
    let domain = discover_domain(&privkey, port)?;
    let acme_dir = format!("/persist/acme/{domain}");

                                              
    let fp0 = served_leaf_fp(https, &domain)?;
    let master0 = haproxy_master_pid(&privkey, port)?;
    let cert_a = mint_selfsigned(wd, "cert-a", &domain)?;
    stage_cert_atomic(&privkey, port, &acme_dir, &cert_a.full_pem)?;
    let fp_a = cert_fingerprint(&cert_a.cert_pem)?;
    poll_served_fp_becomes(
        https,
        &domain,
        &fp_a,
        Duration::from_secs(45),
        &mut guard,
        "watcher swap",
    )?;
    assert_ne_fp(
        &fp0,
        &fp_a,
        "the staged cert must differ from the initial leaf",
    )?;
    let master1 = haproxy_master_pid(&privkey, port)?;
    if master1 != master0 {
        return Err(DryrunError::AcmeLifecycle(format!(
            "haproxy master PID changed across the reload ({master0} -> {master1}) — \
             a RESTART, not a SIGUSR2 hitless reload"
        )));
    }

                                                              
    let bad = wd.join("bad-full.pem");
    std::fs::write(
        &bad,
        b"-----BEGIN CERTIFICATE-----\nnot a valid certificate\n-----END CERTIFICATE-----\n",
    )
    .map_err(DryrunError::io("writing malformed cert"))?;
    stage_cert_atomic(&privkey, port, &acme_dir, &bad)?;
                                                                                                      
                                                                                                   
    sleep(Duration::from_secs(25));
    let fp_after_bad = served_leaf_fp(https, &domain)?;
    assert_eq_fp(
        &fp_after_bad,
        &fp_a,
        "recovery: haproxy must keep serving the good leaf after a rejected reload",
    )?;
    let cert_b = mint_selfsigned(wd, "cert-b", &domain)?;
    stage_cert_atomic(&privkey, port, &acme_dir, &cert_b.full_pem)?;
    let fp_b = cert_fingerprint(&cert_b.cert_pem)?;
    poll_served_fp_becomes(
        https,
        &domain,
        &fp_b,
        Duration::from_secs(45),
        &mut guard,
        "recovery good-cert swap",
    )?;
    let master2 = haproxy_master_pid(&privkey, port)?;
    if master2 != master0 {
        return Err(DryrunError::AcmeLifecycle(format!(
            "recovery: haproxy master PID changed ({master0} -> {master2}) — the master did not survive the bad-cert cycle"
        )));
    }

                                                                                                  
                                                                                                        
                                                                                                      
                                                                                                      
                                                                                     
    assert_renew_render_sealed(&privkey, port)?;

                                                                         
                                                                                                   
    let real = mint_real_shaped(wd, &domain)?;
    stage_cert_atomic(&privkey, port, &acme_dir, &real.full_pem)?;
                                                                                                        
    poll_served_fp_becomes(
        https,
        &domain,
        &cert_fingerprint(&real.cert_pem)?,
        Duration::from_secs(45),
        &mut guard,
        "real-cert swap",
    )?;
    let (idle_ok, idle_out) = run_renew_cycle(&privkey, port, &domain, 20)?;
    if !idle_out.contains("cert healthy, not due; idle") {
        return Err(DryrunError::AcmeLifecycle(format!(
            "Idle: a healthy real cert must log the idle decision (re-issuance loop dead); got (ok={idle_ok}): {idle_out}"
        )));
    }
                                                                                                      
                                                                                                        
                                                                                                       
                                                                         
    stage_cert_atomic(&privkey, port, &acme_dir, &cert_a.full_pem)?;
    let (_obtain_ok, obtain_out) = run_renew_cycle(&privkey, port, &domain, 6)?;
    if !obtain_out.contains("obtaining (self-signed)") {
        return Err(DryrunError::AcmeLifecycle(format!(
            "Obtain: a self-signed cert must log the obtaining(self-signed) decision; got: {obtain_out}"
        )));
    }

                                                                           
    assert_fifo_no_wedge(&privkey, port)?;

    Ok(())
}

/// A minted key‖cert pair on the host (full.pem = key then cert, the box's ordering).
struct MintedCert {
    full_pem: std::path::PathBuf,
    cert_pem: std::path::PathBuf,
}

fn require_openssl() -> Result<(), DryrunError> {
    Command::new("openssl")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            DryrunError::AcmeLifecycle(format!("host `openssl` required for the gate: {e}"))
        })
        .and_then(|s| {
            s.success()
                .then_some(())
                .ok_or_else(|| DryrunError::AcmeLifecycle("`openssl version` failed".into()))
        })
}

/// Mint a distinct self-signed P-256 leaf (Issuer==Subject) into `<wd>/<tag>-full.pem`. The key is
/// PKCS#8 (`genpkey`, matching the box's real full.pem shape) — see [`mint_real_shaped`]; keeping both
/// minters on `genpkey` also avoids the version-dependent SEC1/PKCS#8 output of `req -newkey ec`
                             
fn mint_selfsigned(wd: &Path, tag: &str, cn: &str) -> Result<MintedCert, DryrunError> {
    let key = wd.join(format!("{tag}.key"));
    let cert = wd.join(format!("{tag}.crt"));
    openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        &key.display().to_string(),
    ])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        &key.display().to_string(),
        "-out",
        &cert.display().to_string(),
        "-days",
        "3650",
        "-subj",
        &format!("/CN={cn}"),
    ])?;
    let full = wd.join(format!("{tag}-full.pem"));
    concat_key_cert(&key, &cert, &full)?;
    Ok(MintedCert {
        full_pem: full,
        cert_pem: cert,
    })
}

/// Mint a REAL-shaped leaf: a throwaway CA + a CA-signed leaf (Issuer≠Subject, far notAfter) — the
/// shape the renewer classifies `Real` and, being far from expiry, decides `Idle`.
///
/// The leaf key is PKCS#8 (`genpkey` → `-----BEGIN PRIVATE KEY-----`), matching the box's real
/// `full.pem` (rcgen/instant-acme + the fb-oneshots selfsign bootstrap all emit PKCS#8) — a fidelity
                                                                                                     
/// `EC PRIVATE KEY` block "errors x509-parser's PEM iterator": it does NOT — verified against
                                                                                                    
/// OWNERSHIP one in `stage_cert_atomic` (chown to fb-acme so the uid-101 renewer can read the cert);
/// the key encoding was never the cause.)
fn mint_real_shaped(wd: &Path, cn: &str) -> Result<MintedCert, DryrunError> {
    let ca_key = wd.join("ca.key");
    let ca_crt = wd.join("ca.crt");
    openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        &ca_key.display().to_string(),
    ])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        &ca_key.display().to_string(),
        "-out",
        &ca_crt.display().to_string(),
        "-days",
        "3650",
        "-subj",
        "/CN=acme-gate-fake-ca/O=acme-gate",
    ])?;
    let leaf_key = wd.join("leaf.key");
    let leaf_csr = wd.join("leaf.csr");
    let leaf_crt = wd.join("leaf.crt");
    openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        &leaf_key.display().to_string(),
    ])?;
    openssl(&[
        "req",
        "-new",
        "-key",
        &leaf_key.display().to_string(),
        "-out",
        &leaf_csr.display().to_string(),
        "-subj",
        &format!("/CN={cn}"),
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        &leaf_csr.display().to_string(),
        "-CA",
        &ca_crt.display().to_string(),
        "-CAkey",
        &ca_key.display().to_string(),
        "-CAcreateserial",
        "-out",
        &leaf_crt.display().to_string(),
        "-days",
        "3000",
    ])?;
    let full = wd.join("real-full.pem");
    concat_key_cert(&leaf_key, &leaf_crt, &full)?;
    Ok(MintedCert {
        full_pem: full,
        cert_pem: leaf_crt,
    })
}

fn concat_key_cert(key: &Path, cert: &Path, out: &Path) -> Result<(), DryrunError> {
    let mut buf = std::fs::read(key).map_err(DryrunError::io("read minted key"))?;
    buf.extend_from_slice(&std::fs::read(cert).map_err(DryrunError::io("read minted cert"))?);
    std::fs::write(out, buf).map_err(DryrunError::io("write minted full.pem"))?;
    Ok(())
}

fn openssl(args: &[&str]) -> Result<(), DryrunError> {
    let out = Command::new("openssl").args(args).output().map_err(|e| {
        DryrunError::AcmeLifecycle(format!(
            "spawn openssl {}: {e}",
            args.first().unwrap_or(&"")
        ))
    })?;
    if !out.status.success() {
        return Err(DryrunError::AcmeLifecycle(format!(
            "openssl {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The SHA-256 fingerprint of a cert PEM, normalized (hex, no colons, uppercase).
fn cert_fingerprint(cert_pem: &Path) -> Result<String, DryrunError> {
    let out = Command::new("openssl")
        .args([
            "x509",
            "-in",
            &cert_pem.display().to_string(),
            "-noout",
            "-fingerprint",
            "-sha256",
        ])
        .output()
        .map_err(|e| DryrunError::AcmeLifecycle(format!("openssl fingerprint: {e}")))?;
    parse_fingerprint(&String::from_utf8_lossy(&out.stdout))
}

/// The SHA-256 fingerprint of the leaf actually SERVED on `:https_port`, via a host `s_client`.
fn served_leaf_fp(https_port: u16, domain: &str) -> Result<String, DryrunError> {
    let pipeline = format!(
        "echo | openssl s_client -connect 127.0.0.1:{https_port} -servername {domain} 2>/dev/null \
         | openssl x509 -noout -fingerprint -sha256"
    );
    let out = Command::new("sh")
        .args(["-c", &pipeline])
        .output()
        .map_err(|e| DryrunError::AcmeLifecycle(format!("s_client fingerprint: {e}")))?;
    parse_fingerprint(&String::from_utf8_lossy(&out.stdout))
}

fn parse_fingerprint(s: &str) -> Result<String, DryrunError> {
                                                     
    s.split('=')
        .nth(1)
        .map(|f| f.trim().replace(':', "").to_uppercase())
        .filter(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            DryrunError::AcmeLifecycle(format!("could not parse a SHA-256 fingerprint from: {s:?}"))
        })
}

/// Poll `:https_port` until the served leaf's fingerprint equals `want`, or the deadline. Bails if
/// QEMU dies. This is the watcher's reload-latency window (cadence + reload settle + QEMU slack).
fn poll_served_fp_becomes(
    https_port: u16,
    domain: &str,
    want: &str,
    timeout: Duration,
    guard: &mut QemuGuard,
    what: &str,
) -> Result<(), DryrunError> {
    let deadline = Instant::now() + timeout;
    let mut last = String::from("(none)");
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            return Err(DryrunError::AcmeLifecycle(format!(
                "{what}: qemu exited early ({status}) before the served leaf converged"
            )));
        }
        if let Ok(fp) = served_leaf_fp(https_port, domain) {
            if fp == want {
                return Ok(());
            }
            last = fp;
        }
        if Instant::now() >= deadline {
            return Err(DryrunError::AcmeLifecycle(format!(
                "{what}: :443 did not serve the expected leaf within {}s (want {want}, last {last}) — \
                 the watcher did not reload haproxy",
                timeout.as_secs()
            )));
        }
        sleep(Duration::from_secs(3));
    }
}

fn assert_eq_fp(got: &str, want: &str, msg: &str) -> Result<(), DryrunError> {
    if got == want {
        Ok(())
    } else {
        Err(DryrunError::AcmeLifecycle(format!(
            "{msg}: got {got}, want {want}"
        )))
    }
}

fn assert_ne_fp(a: &str, b: &str, msg: &str) -> Result<(), DryrunError> {
    if a != b {
        Ok(())
    } else {
        Err(DryrunError::AcmeLifecycle(format!(
            "{msg}: both fingerprints were {a}"
        )))
    }
}

/// Push `pem` atomically to `<acme_dir>/full.pem` over root SSH: a sibling temp then `mv -f`
/// (rename), mirroring `fb-acme`/`selfsign`'s temp+rename shape so the watcher never reads a partial.
///
/// **Owned `fb-acme:fb-acme`** (the box's `/persist/acme` is uid-101-owned; a real `fb-acme renew`
/// writes its cert AS uid 101): we stage over root SSH, so without the `chown` the file lands
/// `root:root 0600` and the renewer — which drops to uid 101 via `s6-setuidgid fb-acme` — hits EACCES
/// reading it and (correctly, per the totality arm) classifies it `Unparseable`⇒Obtain, defeating the
                                                                                                
/// (Boot-gate-proven 2026-07-21.)
fn stage_cert_atomic(
    privkey: &Path,
    port: u16,
    acme_dir: &str,
    pem: &Path,
) -> Result<(), DryrunError> {
    let remote = format!(
        "set -e; d='{acme_dir}'; t=\"$d/.full.pem.gate.$$\"; cat > \"$t\"; chown fb-acme:fb-acme \"$t\"; chmod 600 \"$t\"; mv -f \"$t\" \"$d/full.pem\""
    );
    let pem_file =
        std::fs::File::open(pem).map_err(DryrunError::io("open minted pem for staging"))?;
    let status = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg(&remote)
        .stdin(pem_file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| DryrunError::AcmeLifecycle(format!("ssh stage-cert: {e}")))?;
    if !status.success() {
        return Err(DryrunError::AcmeLifecycle(format!(
            "staging a cert to {acme_dir}/full.pem exited {status}"
        )));
    }
    Ok(())
}

/// `s6-svstat /run/service/haproxy` → the supervised pid (the haproxy MASTER; the run script execs
/// it directly, and a SIGUSR2 reload re-execs the master keeping this PID).
fn haproxy_master_pid(privkey: &Path, port: u16) -> Result<String, DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "s6-svstat /run/service/haproxy")?;
    if !ok {
        return Err(DryrunError::AcmeLifecycle(format!(
            "s6-svstat haproxy failed: {out}"
        )));
    }
                                       
    out.split("pid ")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .ok_or_else(|| DryrunError::AcmeLifecycle(format!("haproxy not `up (pid …)`: {out}")))
}

/// Which domain the box serves — the single dir under `/persist/acme` the bootstrap oneshot created.
fn discover_domain(privkey: &Path, port: u16) -> Result<String, DryrunError> {
    let (ok, out) = ssh_capture(privkey, port, "ls -1 /persist/acme")?;
    let domain = out.lines().map(str::trim).find(|l| !l.is_empty());
    match (ok, domain) {
        (true, Some(d)) => Ok(d.to_string()),
        _ => Err(DryrunError::AcmeLifecycle(format!(
            "could not discover the serving domain under /persist/acme: {out}"
        ))),
    }
}

/// Run ONE scheduled renewer cycle — the exact periodic_loop body — over SSH, capturing its decision
/// line. `timeout_secs` bounds the Obtain leg (which would otherwise enter the no-LE network path).
/// `--min-epoch 0` disables the build-epoch floor so the booted box's real (kvm) clock reads synced.
fn run_renew_cycle(
    privkey: &Path,
    port: u16,
    domain: &str,
    timeout_secs: u32,
) -> Result<(bool, String), DryrunError> {
    let cmd = format!(
        "timeout {timeout_secs} s6-envdir /etc/recipes/env s6-setuidgid fb-acme \
         /usr/bin/fb-acme renew --domain {domain} --min-epoch 0 2>&1 || true"
    );
    ssh_capture(privkey, port, &cmd)
}

                                                                                                     
/// the daily periodic_loop with envdir preserved — the property `run_renew_cycle` can't prove because
/// it hand-builds the loop body (the 86400 s cadence can't be waited out). A render regression to
/// `exec`, a dropped `s6-envdir`, or a wrong interval would strand the "re-issuance loop is dead"
/// claim on nothing; this seals it on produced bytes.
fn assert_renew_render_sealed(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let (ok, run) = ssh_capture(privkey, port, "cat /run/service/fb-acme-renew/run")?;
    if !ok {
        return Err(DryrunError::AcmeLifecycle(format!(
            "could not read /run/service/fb-acme-renew/run (is the renewer servicedir present?): {run}"
        )));
    }
                                                                                                             
                                        
    for needle in [
        "while : ; do",
        "sleep 86400",
        "s6-envdir '/etc/recipes/env'",
        "s6-setuidgid 'fb-acme'",
        "'/usr/bin/fb-acme' 'renew'",
    ] {
        if !run.contains(needle) {
            return Err(DryrunError::AcmeLifecycle(format!(
                "rendered fb-acme-renew/run is not the expected daily periodic_loop (missing {needle:?}); \
                 an exec/dropped-envdir/bad-interval regression would revive the re-issuance loop. Got:\n{run}"
            )));
        }
    }
    if run.contains("exec /usr/bin/fb-acme") {
        return Err(DryrunError::AcmeLifecycle(format!(
            "fb-acme-renew/run is an EXEC longrun (the re-issuance-loop shape), not a periodic_loop:\n{run}"
        )));
    }
    Ok(())
}

                                                                                               
/// PROMPTLY (the O_NONBLOCK + S_ISREG hardening) rather than blocking forever on the FIFO. A wedge
/// would be killed by `timeout 15` → exit 124; a healthy reader exits 0 well under it.
fn assert_fifo_no_wedge(privkey: &Path, port: u16) -> Result<(), DryrunError> {
    let setup = "d=/persist/acme/fifo-probe.test; mkdir -p \"$d\"; rm -f \"$d/full.pem\"; mkfifo \"$d/full.pem\"";
    let (ok, out) = ssh_capture(privkey, port, setup)?;
    if !ok {
        return Err(DryrunError::AcmeLifecycle(format!(
            "planting the FIFO probe failed: {out}"
        )));
    }
    let start = Instant::now();
    let (_ok, out) = ssh_capture(
        privkey,
        port,
        "timeout 15 /usr/bin/fb-oneshots cert-reload-check --domain fifo-probe.test; echo rc=$?",
    )?;
    if out.contains("rc=124") {
        return Err(DryrunError::AcmeLifecycle(
"cert-reload-check WEDGED on a FIFO (killed by timeout) — the O_NONBLOCK hardening is gone".into(),
        ));
    }
    if start.elapsed() > Duration::from_secs(14) {
        return Err(DryrunError::AcmeLifecycle(format!(
            "cert-reload-check took {}s on a FIFO — suspiciously close to the wedge timeout",
            start.elapsed().as_secs()
        )));
    }
    Ok(())
}

/// SSH a command, capturing `(success, combined-ish stdout)`. Mirrors `install_dha`'s helper.
fn ssh_capture(privkey: &Path, port: u16, cmd: &str) -> Result<(bool, String), DryrunError> {
    let out = Command::new("ssh")
        .args(ssh_base_args(privkey, port))
        .arg(cmd)
        .output()
        .map_err(|e| DryrunError::AcmeLifecycle(format!("ssh `{cmd}`: {e}")))?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}
