                                                                                                 
//! configs the image-builder renders into the squashfs staging tree, plus the build-time assertion
//! helpers the golden sentries (`tests/image_content_golden.rs`) exercise.
//!
//! **Scope (operator decision — option 1):** only the configs the spec FULLY pins —
                                                                                                
//!  - **haproxy**: ported from the audited `nix/haproxy-config.nix` — the load-bearing strip-then-set
                                                                                                    
//!    `/api/pair` log redaction are preserved; cert/ca paths adapted to the `/persist` layout +
                                      
                                                                                                  
                                                                    
//!
                                                                                                    
//! The servicedir/supervision tree + nftables ARE spec-pinned (L657/L1043) and land in this init/service-layer
                                                                                                 
//! builder emits these STATIC contents; there is no operator-mutable config surface (spec lines 533/539).

/// Why a build-time config assertion failed (each → the image build fails closed).
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
                                                                                                         
    DropbearPam,
    /// A forbidden component (systemd / package manager / PAM) is present in the staging tree.
    ForbiddenComponent(String),
    /// A required load-bearing component is ABSENT from the staging tree (M-3: the absence-only
    /// checks must not vacuously pass on an empty / under-extracted tree).
    MissingRequiredComponent(String),
    /// The operator-provided domain is not a valid RFC-1123 hostname (M-2: config-injection guard).
    InvalidDomain(String),
    /// A staged ELF's DT_NEEDED soname resolves to no lib in the rootfs — the link-closure is
                                                                                          
    UnresolvedLink {
        elf: String,
        soname: String,
    },
    /// An operator-supplied `--manifest` failed to read / parse / validate (the §5.3 fail-closed bake
    /// gate). Unlike the in-tree reference manifest (whose validation failure is a build bug → panic),
    /// a supplied manifest is operator input → a clean, REFUSED-at-bake error.
    Manifest(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DropbearPam => write!(
                f,
"a rootfs binary links PAM (libpam in DT_NEEDED) — dropbear must be built without --enable-pam"
            ),
            Self::ForbiddenComponent(p) => {
                write!(f, "forbidden component present in rootfs staging tree: {p}")
            }
            Self::MissingRequiredComponent(p) => {
                write!(f, "required component MISSING from rootfs staging tree: {p}")
            }
            Self::InvalidDomain(m) => write!(f, "invalid --domain: {m}"),
            Self::UnresolvedLink { elf, soname } => write!(
                f,
                "rootfs link-incompleteness: {elf} needs '{soname}' but no such lib is in the rootfs"
            ),
            Self::Manifest(m) => write!(f, "service manifest REFUSED at bake: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

                                                                                                    

/// The services dropbear host-key path. BOOT-1 (network-bringup holistic R2): the original
/// `/persist/dropbear/...` + `-R` was SSH-inaccessible — this dropbear's `-R` regenerates host keys
/// at the COMPILED-IN default `/etc/dropbear/` (the RO verity rootfs) regardless of `-r`, so the
/// running services box rejected every connection (`Read-only file system` → exit-before-auth). Fix:
/// stage the box's HKDF-derived host key to this WRITABLE tmpfs path via the `services-keys-stage`
/// box-init oneshot and drop `-R` — mirroring `rescue-dropbear` (which is boot-gate-proven). Services
/// + rescue now share ONE operator-precomputable host identity (`derive-rescue-host-keys`).
pub const DROPBEAR_HOST_KEY: &str = "/run/dropbear/dropbear_ed25519_host_key";

/// The pinned dropbear argv. The SECURITY-relevant flags are the spec line-149 set MINUS `-R`:
/// `-r <hostkey> -s -G ssh -I 1800 -K 300 -T 3`. `-R` was DROPPED (BOOT-1, see [`DROPBEAR_HOST_KEY`]):
/// it regenerates at the RO `/etc/dropbear/` regardless of `-r`, so the host key is pre-staged to the
/// writable `-r` path instead (like `rescue-dropbear`). `-F`/`-E` (foreground + log-to-stderr) are s6
/// supervision plumbing — not in the spec's security enumeration, and NOT forbidden flags.
pub fn dropbear_argv() -> Vec<String> {
    [
        "/usr/sbin/dropbear",
        "-F",                              
        "-E",                               
        "-r",
        DROPBEAR_HOST_KEY,                                                               
        "-s",                                                    
        "-G",
        "ssh",                                        
        "-I",
        "1800",                       
        "-K",
        "300",                            
        "-T",
        "3",                  
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Flags the dropbear run script MUST NOT contain (spec line 149 forbidden set): `-c` forced-command,
/// `-w` disable-root (would lock the operator out of the root-only box), `--enable-pam` (compile-time
/// — also caught by [`check_no_pam_needed`]).
pub const FORBIDDEN_DROPBEAR_FLAGS: [&str; 3] = ["-c", "-w", "--enable-pam"];

/// The dropbear `run` script body — the flag set is the load-bearing content. Used by
/// [`crate::service_tree`]'s `dropbear` servicedir (the s6-svscan run script); the no-forbidden-flags
/// golden sentry (`image_content_golden.rs`) checks it.
pub fn dropbear_run_script() -> String {
    format!("#!/bin/sh\nexec {}\n", dropbear_argv().join(" "))
}

                                                                                             
/// `/etc/pam.d`, an auth path the box's pubkey-only model forbids. Scans every staged ELF's
/// DT_NEEDED. Named separately from the general completeness check for a clear failure (libpam is
/// ALSO caught as an unresolved link — it isn't in the closure — so this is belt + suspenders).
pub fn check_no_pam_needed(needed: &[(String, Vec<String>)]) -> Result<(), ConfigError> {
    for (_elf, sonames) in needed {
        if sonames.iter().any(|s| s.contains("libpam")) {
            return Err(ConfigError::DropbearPam);
        }
    }
    Ok(())
}

                                                                                                  
/// ELF must resolve to a shared object present in the rootfs. The structural backstop to the
/// generated closure — a missing lib FAILS the build (fail-closed), not the boot. `needed` is
/// `(elf, its NEEDED sonames)`; `available` is the set of soname filenames in the rootfs lib dirs.
pub fn check_link_completeness(
    needed: &[(String, Vec<String>)],
    available: &std::collections::HashSet<String>,
) -> Result<(), ConfigError> {
    for (elf, sonames) in needed {
        for soname in sonames {
            if !available.contains(soname) {
                return Err(ConfigError::UnresolvedLink {
                    elf: elf.clone(),
                    soname: soname.clone(),
                });
            }
        }
    }
    Ok(())
}

                                                                                                      

/// Render the box's `/etc/haproxy/haproxy.cfg` for `domain`. Faithful port of the audited
/// `nix/haproxy-config.nix`: the strip-then-set `X-SSL-Client-*` block, the per-IP stick-table +
/// caps, the `/api/v1/` + `/download/` mTLS gate, the `/api/pair` log redaction, the port-80
/// silent-deny, and HSTS are all preserved. Cert + CA paths use the `/persist` layout; `master-worker`
                                                                                    
/// `selfsign-acme-cert` bootstrap writes a self-signed cert to the same path before the first renew),
/// so there is no dev/prod cert-path branch.
///
/// `Err` is the fail-closed render refusal (spec Component A): a throttle rule with an empty
/// `paths` set has no legitimate reading and would render a parse-fatal bare acl — refused at
/// build, never discovered on the box. (An empty `mtls_paths` is legitimate — "no mTLS surface" —
/// and renders the §(3) gate block conditionally instead; see [`compose_mtls_gate`].)
pub fn haproxy_config(
    edge: &fb_manifest::manifest::EdgeSpec,
    ctx: &fb_manifest::PlaceholderCtx,
) -> Result<String, String> {
                                                                                 
                                                                                   
                                                                          
    for rule in &edge.throttle_rules {
        if rule.paths.is_empty() {
            return Err(format!(
                "haproxy config: a throttle rule (max_req_rate={}) declares no paths — \
                 remove the rule or give it paths",
                rule.max_req_rate
            ));
        }
    }
    let cert = format!("/persist/acme/{}/full.pem", ctx.domain);
    let ca = &edge.ca_file;
    let backend = &edge.backend;
    let redaction = compose_redaction(edge);
    let throttle = compose_throttle(edge);
    let mtls_gate = compose_mtls_gate(edge);
    Ok(format!(
        r#"global
    # Log to STDOUT, not /dev/log — the box runs no syslog daemon,
    # so the classic `/dev/log` socket never exists and every access-log line (incl. the
    # /api/pair redaction below) was silently dropped. `stdout` rides the s6/console capture like the
    # other services (haproxy is foreground under `-db`). The redaction control stays load-bearing now
    # that a sink actually exists.
    log stdout format raw local0
    maxconn 1024
    user haproxy
    group haproxy
    # master-worker enables SIGUSR2 cert-reload without dropping connections.
    master-worker

defaults
    mode http
    log global
    # The custom log-format redacts /api/pair/<code> before journald (replaces option httplog).
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs \"%HM %[var(txn.logged_url)] %HV\""
    option dontlognull
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-request 10s
    timeout http-keep-alive 5s

frontend http-in
    bind *:80
    acl is_acme path_beg /.well-known/acme-challenge/
    # http-request rules BEFORE use_backend — haproxy
    # processes them in that order regardless, but file order matching it
    # silences the "http-request rule placed after a use_backend rule" load
    # warning (smoke Run-2 observation). Behaviour unchanged: deny 410
    # unless is_acme lets acme requests fall through to use_backend.
    http-request set-var(txn.logged_url) {redaction}
    http-request set-log-level silent unless is_acme
    http-request deny status 410 unless is_acme
    use_backend acme_be if is_acme

backend per_ip_throttle
    stick-table type ip size 100k expire 1m store conn_cur,conn_rate(60s),http_req_rate(60s)

frontend https-in
    bind *:443 ssl crt {cert} ca-file {ca} verify optional

    # tcp-request connection rules BEFORE any http-request —
    # they evaluate at connection-accept time regardless, but file order
    # matching it silences the "tcp-request connection rule placed after an
    # http-request rule" load warning (smoke Run-2 observation).
    tcp-request connection track-sc0 src table per_ip_throttle
    tcp-request connection reject if {{ sc_conn_cur(0) gt 20 }}

    http-request set-var(txn.logged_url) {redaction}
    http-request deny status 429 if {{ sc_http_req_rate(0) gt 200 }}

{throttle}

    # (1) Strip any client-supplied trust-relevant headers (rendered unconditionally).
    http-request del-header X-SSL-Client-Verify
    http-request del-header X-SSL-Client-CN
    http-request del-header X-SSL-Client-DN
    http-request del-header X-SSL-Client-Fingerprint
    http-request del-header X-Forwarded-Client-Cert
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host
    http-request del-header Forwarded
    http-request del-header X-Real-IP
    http-request del-header Via
    http-request del-header True-Client-IP
    http-request del-header CF-Connecting-IP

    # (2) Set them ourselves from the actual handshake, gated on ssl_c_used.
    http-request set-header X-SSL-Client-Verify %[ssl_c_verify] if {{ ssl_c_used }}
    http-request set-header X-SSL-Client-CN %[ssl_c_s_dn(CN)] if {{ ssl_c_used }}
    # SHA-256(DER), not SHA-1. haproxy 3.2 has
    # no `ssl_c_sha256` fetch (verified against the 3.2.19 manual), so compose
    # `ssl_c_der,sha2(256),hex`. The DeviceCertAuth guard binds this to the
    # pairing-time SHA-256(DER); `hex` emits uppercase, the guard compares
    # case-insensitively. The unconditional del-header above strips any
    # client-supplied value first.
    http-request set-header X-SSL-Client-Fingerprint %[ssl_c_der,sha2(256),hex] if {{ ssl_c_used }}

{mtls_gate}

    # (4) HSTS on every HTTPS response.
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"

    default_backend recipes_be

backend recipes_be
    option forwardfor
    server local {backend}

backend acme_be
    server acme_local 127.0.0.1:8081
"#
    ))
}

                                                                                                   
/// validated edge charset `[A-Za-z0-9._/:@=+-]` excludes every regex grammar-breaker (`( ) [ ] * ? \ ^
/// $ | ,`), but `.` and `+` are ACTIVE regex metacharacters — left unescaped they BROADEN the match
/// (fail-safe for redaction, but a §5.1a "never a regex" contract gap + a latent trap at any future
/// narrowing sink). Escape them so the token matches LITERALLY. The reference tenant's paths carry no
/// `.`/`+`, so this is a NO-OP there (the haproxy golden is unchanged); only a `.`/`+`-bearing tenant
/// token changes. (The `path_beg`/mTLS sinks are literal prefix matches — they don't go through this.)
fn regex_escape_token(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        if c == '.' || c == '+' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Compose the redaction `regsub` list (§5.1a) — path-segment redactions + query-param redactions. The
/// `url,` prefix + the regsub grammar are OS-invariant; only the path/param SETS are tenant data. Each
                                                                                                        
/// prefix shown in the log.
fn compose_redaction(edge: &fb_manifest::manifest::EdgeSpec) -> String {
    let mut s = "url".to_string();
    for p in &edge.redacted_paths {
        s.push_str(&format!(
            ",regsub(^{m}[^/?]+,{p}<redacted>)",
            m = regex_escape_token(p)
        ));
    }
    for q in &edge.redacted_query_params {
        s.push_str(&format!(
            ",regsub({m}=[^&]+,{q}=<redacted>)",
            m = regex_escape_token(q)
        ));
    }
    s
}

/// Compose the per-path throttle acls + deny rules (§5.1a). The acl NAME derives deterministically from
/// the paths (so the reference tenant reproduces `is_login_or_recover`/`is_api_pair` byte-exactly); the
/// match keyword is `path` (Exact) / `path_beg` (Prefix). The global rate + conn-limit + stick-table stay
/// OS-invariant. The acls come first (haproxy file-order), then the denies; no trailing newline (the
/// template's `\n` after `{throttle}` provides it).
fn compose_throttle(edge: &fb_manifest::manifest::EdgeSpec) -> String {
    use fb_manifest::manifest::ThrottleMatch;
    let acl_name = |paths: &[String]| -> String {
        let parts: Vec<String> = paths
            .iter()
            .map(|p| p.trim_matches('/').replace('/', "_"))
            .collect();
        format!("is_{}", parts.join("_or_"))
    };
    let mut acls = String::new();
    let mut denies = String::new();
    for rule in &edge.throttle_rules {
        let name = acl_name(&rule.paths);
        let kw = match rule.match_kind {
            ThrottleMatch::Exact => "path",
            ThrottleMatch::Prefix => "path_beg",
        };
        let expr: Vec<String> = rule.paths.iter().map(|p| format!("{kw} {p}")).collect();
        acls.push_str(&format!("    acl {name} {}\n", expr.join(" || ")));
        denies.push_str(&format!(
            "    http-request deny status 429 if {name} {{ sc_http_req_rate(0) gt {} }}\n",
            rule.max_req_rate
        ));
    }
    format!("{acls}{denies}").trim_end_matches('\n').to_string()
}

/// Compose the mTLS-gate acl expression (§5.1a) — `path_beg <p> || …` over the declared mTLS paths.
fn compose_mtls_acl(edge: &fb_manifest::manifest::EdgeSpec) -> String {
    edge.mtls_paths
        .iter()
        .map(|p| format!("path_beg {p}"))
        .collect::<Vec<_>>()
        .join(" || ")
}

/// The whole §(3) mTLS-gate block, rendered conditionally (spec Component A): a tenant
/// with mTLS paths gets the exact five-line block (byte-identical to the pre-fix render —
/// AC-A1); an empty `mtls_paths` (an EXPLICIT `[]` — the field is required, non-defaulted)
/// gets a single comment so the numbered-section structure stays readable, and none of the
/// three acls or the two 401 denies are emitted (they would be dead or parse-fatal).
fn compose_mtls_gate(edge: &fb_manifest::manifest::EdgeSpec) -> String {
    if edge.mtls_paths.is_empty() {
        return "    # (3) no mTLS-gated paths declared by this tenant.".to_string();
    }
    format!(
        "    # (3) mTLS gate on /api/v1/* + /download/* (two ACLs + two deny rules; both load-bearing).\n\
         \x20   acl is_android_api {}\n\
         \x20   acl cert_present ssl_c_used\n\
         \x20   acl cert_verified ssl_c_verify -m int 0\n\
         \x20   http-request deny status 401 if is_android_api !cert_present\n\
         \x20   http-request deny status 401 if is_android_api !cert_verified",
        compose_mtls_acl(edge)
    )
}

                                                                                                    

                                                                                                  
/// Signed with the IMA key at build time (`REQUIRE_POLICY_SIGS=y`); the init loads it by path so the
/// kernel appraises this file's own signature.
pub const IMA_POLICY: &str = "\
appraise func=BPRM_CHECK fowner=0 appraise_type=imasig
appraise func=MMAP_CHECK fowner=0 appraise_type=imasig
appraise func=MODULE_CHECK appraise_type=imasig
";

                                                                                                    

                                                                                             
/// identifiers are partition LABELs (disk-name independent across sda/vda/nvme; the installer formats
/// each partition with the matching label) — the same disk-variance concern the runtime cmdline's
/// `fb.rootfs-dev` resolves operator-side. Mount options are the load-bearing part: `/boot` ro +
                                                                                                   
/// fs-option `errors=remount-ro` (fail-closed on a run-time fs error → next-boot `prepare-persist`
/// recovery; persist-crash-recovery F-12), but NO mount(8) pseudo-options (`auto`/`nofail`): box-init's
/// mount-persist runs busybox `mount /persist`, which passes any non-MS_ option straight to the ext4
/// kernel mount, which ACCEPTS `errors=` (an fs-specific option) but REJECTS `auto`/`nofail` (mount(8)
/// pseudo-options — boot-gate finding); the
/// `nofail` fail-soft comes from box-init diverting to rescue on a mount failure (data-only, never exec —
/// 914/1042). The rootfs `/` is NOT in fstab — the initramfs-init verity-mounts it read-only. (The
                                                                                                      
                                                                                                   
/// resolve through the scan-directory symlinks onto the signed rootfs (the kernel checks the *resolved*
/// mount), so noexec never fires on a legitimate exec — it only fail-closes an accidental tmpfs target.)
pub const FSTAB: &str = "\
# /etc/fstab — generated statically by recipes-image-builder; no operator-mutable fstab.
LABEL=boot    /boot   ext4  ro,nodev,nosuid,noexec           0 0
LABEL=persist /persist ext4 nosuid,nodev,noexec,errors=remount-ro  0 0
tmpfs         /tmp    tmpfs nosuid,nodev,noexec,mode=1777     0 0
tmpfs         /run    tmpfs nosuid,nodev,noexec,mode=0755     0 0
";

                                                                                                    

                                                                                                
/// fb-backup, fb-cert-check, haproxy, dropbear-rescue). These are renderer-owned (NOT manifest data); the
/// tenant declares ONLY its own app identities, which the renderer appends. The single source of truth
                                                                                                        
/// disjoint from these).
const OS_FIXED_IDENTITIES: &[(&str, u32)] = &[
    ("root", 0),
    ("fb-acme", 101),
    ("fb-backup", 102),
    ("fb-cert-check", 103),
    ("haproxy", 104),
    ("dropbear-rescue", 105),
];

/// The OS-fixed identity set for `fb_manifest::parse_and_validate` (the gate DERIVES the reserved-uid set
                                                                              
pub fn os_identities() -> fb_manifest::OsIdentities {
    fb_manifest::OsIdentities {
        fixed: OS_FIXED_IDENTITIES
            .iter()
            .map(|(n, u)| (n.to_string(), *u))
            .collect(),
    }
}

                                                                                                   
/// Post-shed orchard holds NO recipes manifest — the production reference tenant is fetched +
/// sha256-verified from the pinned store at bake ([`parse_validated_manifest`], via `build_image.rs`).
/// The render goldens need a COMPLETE valid tenant to render; this loads orchard's own non-recipes
/// fixture. `#[cfg(test)]` so neither the fixture bytes nor this helper land in the production lib.
#[cfg(test)]
pub(crate) fn sample_manifest() -> fb_manifest::ValidatedManifest {
    parse_validated_manifest(include_str!("../tests/fixtures/sample-tenant.toml"))
        .expect("the synthetic sample-tenant.toml must validate")
}

/// Parse + validate a service-manifest's TOML through the §5.3 fail-closed gate against
                                                                                                   
/// fetched + sha256-VERIFIED from the pinned artifact store at consumption (`build_image.rs`), never an
/// in-tree copy. A malformed / privilege-escalating / tampered manifest is a clean, REFUSED-at-bake
/// [`ConfigError::Manifest`], NEVER a panic.
pub fn parse_validated_manifest(toml: &str) -> Result<fb_manifest::ValidatedManifest, ConfigError> {
    fb_manifest::parse_and_validate(toml, &os_identities())
        .map_err(|e| ConfigError::Manifest(e.to_string()))
}

/// Load + validate the operator-supplied `--manifest <path>` (read → parsed → §5.3 fail-closed gate via
/// [`parse_validated_manifest`]). A supplied manifest that fails to read / parse / validate is a clean,
/// REFUSED-at-bake [`ConfigError::Manifest`] (operator error), NEVER a panic. The reference tenant (no
                                                                                                        
/// pinned store in `build_image.rs` (the §9 verify-at-consumption path).
pub fn load_manifest(
    path: &std::path::Path,
) -> Result<fb_manifest::ValidatedManifest, ConfigError> {
    let toml = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::Manifest(format!("read {}: {e}", path.display())))?;
    parse_validated_manifest(&toml)
}

fn passwd_row(name: &str, uid: u32) -> String {
    if uid == 0 {
        format!("{name}:x:0:0:{name}:/root:/bin/sh")
    } else {
        format!("{name}:x:{uid}:{uid}:{name}:/var/empty:/sbin/nologin")
    }
}

/// OS-fixed ∪ tenant identities, uid-sorted (a stable, byte-identical-for-the-reference layout).
fn sorted_identities(tenant: &[fb_manifest::manifest::Identity]) -> Vec<(String, u32)> {
    let mut ids: Vec<(String, u32)> = OS_FIXED_IDENTITIES
        .iter()
        .map(|(n, u)| (n.to_string(), *u))
        .collect();
    for id in tenant {
        ids.push((id.name.clone(), id.uid));
    }
    ids.sort_by_key(|(_, u)| *u);
    ids
}

                                                                                                       
/// the service users get `/sbin/nologin`. The box has no `alpine-baselayout` + the extract-only model
/// runs no apk user-creation, so the image-builder bakes the identity files. Byte-identical for the
/// reference tenant (recipes=100, fb-acme=101, …).
pub fn passwd(tenant: &[fb_manifest::manifest::Identity]) -> String {
    let rows: Vec<String> = sorted_identities(tenant)
        .iter()
        .map(|(n, u)| passwd_row(n, *u))
        .collect();
    format!("{}\n", rows.join("\n"))
}

                                                                                                    
/// member so dropbear's `-G ssh` (services + rescue) admits the operator's root login.
pub fn group(tenant: &[fb_manifest::manifest::Identity]) -> String {
    let mut rows: Vec<String> = sorted_identities(tenant)
        .iter()
        .map(|(n, u)| format!("{n}:x:{u}:"))
        .collect();
    rows.push("ssh:x:22:root".to_string());
    format!("{}\n", rows.join("\n"))
}

                                                                                                   
///
/// fb-backup reads this signed (dm-verity + IMA-covered) file at runtime for its source/vacuum set
/// instead of hardcoding the recipes data shape (`images`/`shopping-lists`/`secrets`/`ca.crt` +
/// `recipes.db`) — so a NON-recipes tenant gets a correct backup, not the recipes layout. One directive
/// per line: `source <rel>` (a dir OR file under the data root, added to the tarball) / `vacuum <rel>`
/// (a sqlite db online-backed-up). The paths are gate-validated relative (no `..`, no leading `/`,
/// charset-clean — so they never carry whitespace that would break the `<directive> <path>` line form);
/// fb-backup RE-validates each at the sink before joining it under the data root (defense-in-depth).
pub fn fb_backup_config(backup: &fb_manifest::manifest::BackupSpec) -> String {
    let mut out = String::from(
"# /etc/fb-backup/config — generated from the service manifest [backup] section .\n \
         # fb-backup reads + re-validates this signed file. `source <rel>` = a dir/file under the data\n\
         # root added to the tarball; `vacuum <rel>` = a sqlite db online-backed-up. One per line.\n",
    );
    if let Some(vt) = &backup.vacuum_target {
        out.push_str(&format!("vacuum {vt}\n"));
    }
    for src in &backup.sources {
        out.push_str(&format!("source {src}\n"));
    }
    out
}

                                                                                                    

/// Path substrings whose presence in the rootfs means the small-surface contract was violated: a
/// service manager other than s6, a package manager, or PAM. (busybox provides `init` shims etc.;
/// these markers are specific binaries/dirs that should never appear.)
pub const FORBIDDEN_COMPONENT_MARKERS: [&str; 6] = [
    "systemd",                                             
    "/sbin/apk",                                           
    "/etc/pam.d",                      
    "libpam",                      
    "/usr/bin/dpkg",
    "/usr/bin/rpm",
];

/// Assert no forbidden component appears in the staging-tree manifest (list of rootfs paths). Fails
/// the build closed on the first hit.
pub fn check_no_forbidden_components<'a>(
    manifest: impl IntoIterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    for path in manifest {
        for marker in FORBIDDEN_COMPONENT_MARKERS {
            if path.contains(marker) {
                return Err(ConfigError::ForbiddenComponent(path.to_string()));
            }
        }
    }
    Ok(())
}

                                                                                                     

/// The load-bearing binaries that MUST be present in the staging tree — verified present in a real
/// build (`unsquashfs -ll` of a built rootfs). Pairing the forbidden-marker blacklist with this
                                                                                                 
/// empty or under-extracted staging tree FAILS instead of silently passing the absence-only checks.
pub const REQUIRED_COMPONENT_PATHS: [&str; 12] = [
    "/usr/sbin/dropbear",
    "/usr/sbin/haproxy",
    "/usr/bin/s6-svscan",
                                                                                                  
    "/usr/bin/s6-svscanctl",
                                                                                                      
                                                                                                        
                                                                                                      
                                                                                                        
                                                                               
    "/usr/sbin/nft",
    "/usr/bin/recipes",
    "/usr/bin/recipes-admin",
    "/usr/bin/fb-acme",
                                                                                         
                                                                                                        
    "/usr/bin/fb-oneshots",
    "/usr/bin/fb-backup",
    "/usr/bin/fb-cert-check",
                                                                                                   
                                                                                                           
                                                                                                         
                                                                                                
                                                                                               
    "/sbin/e2fsck",
];

/// Assert every [`REQUIRED_COMPONENT_PATHS`] entry is present in the staging manifest (exact match —
/// each is a distinct leaf path from `collect_staging_paths`). Fails closed on the first missing one.
/// MUST run before the absence-checks so an empty/under-extracted tree cannot vacuously pass (M-1 + M-3).
pub fn check_required_components<'a>(
    manifest: impl IntoIterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    let paths: std::collections::HashSet<&str> = manifest.into_iter().collect();
    for required in REQUIRED_COMPONENT_PATHS {
        if !paths.contains(required) {
            return Err(ConfigError::MissingRequiredComponent(required.to_string()));
        }
    }
    Ok(())
}

/// busybox applets the box's run-scripts / oneshots / svscan handlers invoke by BARE NAME (PATH-resolved
/// against the `busybox --install -s` symlinks). M-3 (network-bringup holistic R2): closes the "no build
/// check that a shelled applet exists" class — the same gap that let H-1's absent `openssl` ship. A
/// busybox compiled without one of these boots fine and only fails when the script runs: a missing
/// `reboot`/`halt`/`poweroff` wedges PID-1 on shutdown (the `.s6-svscan/finish` handler), a missing `ip`
/// breaks `network-up`, a missing `mountpoint`/`umount` breaks persist mount + the orderly stop. Pairs
                                                                                                  
/// non-busybox tools the scripts also shell are guarded too (L-1, network-bringup holistic R3): `nft`
/// (absolute-path-invoked) rides [`REQUIRED_COMPONENT_PATHS`]; the bare-name PATH-resolved s6 tools
/// `s6-envdir`/`s6-setuidgid` ride [`REQUIRED_PATH_COMMANDS`] (basename presence — matching how they're
/// invoked, since a bare name has no fixed path to exact-match).
pub const REQUIRED_BUSYBOX_APPLETS: [&str; 33] = [
                                                                                                       
                                                                                               
                                                                                                     
                                                                                      
    "sh",
                                                                    
    "mkdir",
    "chmod",
    "chown",
    "mount",
    "mountpoint",
    "cp",
                                                                                         
                                                                                                       
                                                                                                        
                                                                                                       
                                                                                                
                                                                     
    "mv",
                                                                                                        
                                                                                                        
                                                                                                      
                                                                                                   
                                                                                                       
    "findfs",
                                                                                                     
    "grep",
                                                                                          
    "cat",
    "echo",
    "sync",
    "umount",
    "reboot",
    "halt",
    "poweroff",
                                                                                     
    "ip",
    "ntpd",
    "sleep",
                                                                                                       
                                                                                                   
                                                                                                        
                                                                                                            
                                                                                                    
                                                                                                
    "awk",
    "cut",
    "date",
    "mktemp",
    "pkill",
    "printf",
    "rm",
    "rmdir",
    "sed",
    "stat",
    "tail",
    "tr",
    "wc",
];

/// Assert every [`REQUIRED_BUSYBOX_APPLETS`] name appears as SOME staging-manifest path's basename (the
/// `busybox --install -s` symlink — dir-agnostic, since busybox installs each applet to its own canonical
/// dir). Runs at the same downstream point as [`check_required_init_components`] (AFTER `build_init_tree`,
/// where `busybox --install -s` ran). Fails closed on the first missing applet.
pub fn check_required_applets<'a>(
    manifest: impl IntoIterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    let basenames: std::collections::HashSet<&str> = manifest
        .into_iter()
        .filter_map(|p| p.rsplit('/').next())
        .collect();
    for applet in REQUIRED_BUSYBOX_APPLETS {
        if !basenames.contains(applet) {
            return Err(ConfigError::MissingRequiredComponent(format!(
                "busybox applet: {applet}"
            )));
        }
    }
    Ok(())
}

/// Non-busybox, NON-absolute bare-name commands the run-scripts/oneshots/staged-probes shell via PATH:
/// the s6 tools the privilege-dropping run scripts + the CA/cert bootstrap oneshots invoke (`s6-envdir`,
/// `s6-setuidgid`) + the ones the staged `/opt/dha/ac-i-selftest.sh` probe requires present and invokes
/// (`s6-svc`, `s6-svstat` — its preflight `command -v`s both and it runs `s6-svc -t`; I-R2-1 fold, the
/// same census class as the L-1 s6-envdir/s6-setuidgid add), plus `resize2fs` + `tune2fs` (the offline
/// grow + Layer-2 journal-add inside the `prepare-persist` oneshot, persist-crash-recovery; both
/// `/usr/sbin/` e2fsprogs-extra tools).
/// L-1 (network-bringup holistic R3): completes the M-3 shell-dependency guard for the apk-provided
/// tools — `nft` is shelled by ABSOLUTE path so it rides [`REQUIRED_COMPONENT_PATHS`] (exact match);
/// these are shelled BARE so they ride a basename-presence check (a bare name has no fixed path to
/// exact-match — PATH resolution finds it in whatever dir the apk staged it to). apk-provided: `s6`
/// (the same closure as the already-required s6-svscan/s6-svscanctl) for all four s6 tools,
/// `e2fsprogs-extra` for `resize2fs` (`/usr/sbin/resize2fs`; its `findfs` companion is a busybox applet,
/// in [`REQUIRED_BUSYBOX_APPLETS`]). Checked at step 6a (`run_hardening_checks`, over the full extracted
/// staging tree — all are apk-extracted before `build_init_tree`).
pub const REQUIRED_PATH_COMMANDS: [&str; 6] = [
    "s6-envdir",
    "s6-setuidgid",
    "s6-svc",
    "s6-svstat",
    "resize2fs",
    "tune2fs",
];

/// Assert every [`REQUIRED_PATH_COMMANDS`] name appears as SOME staging-manifest path's basename (PATH
/// resolution finds it). Runs at step 6a (the s6 tools are apk-extracted — present before
/// build_init_tree, unlike the busybox applets). Fails closed on the first missing one.
pub fn check_required_path_commands<'a>(
    manifest: impl IntoIterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    let basenames: std::collections::HashSet<&str> = manifest
        .into_iter()
        .filter_map(|p| p.rsplit('/').next())
        .collect();
    for cmd in REQUIRED_PATH_COMMANDS {
        if !basenames.contains(cmd) {
            return Err(ConfigError::MissingRequiredComponent(format!(
                "PATH command: {cmd}"
            )));
        }
    }
    Ok(())
}

/// The init/supervision components [`crate::build::BuildTools::build_init_tree`] produces, guarded
/// present in the staging manifest AFTER build_init_tree + BEFORE the signer — turning the
/// "build-ok-but-boot-FATAL/degraded" class into a BUILD-time failure: `/sbin/init` (the relative
/// symlink to box-init), the `box-init` PID-1 binary (the signer must sign it), the four `.s6-svscan`
/// control handlers (a missing `finish` panics PID-1 on reboot; a missing SIG* silently falls through
                                                                                            
/// load-bearing service `run` scripts (so an emitter regression that drops a servicedir fails the
                                                                                                        
/// Checked separately from [`REQUIRED_COMPONENT_PATHS`] (I-3a): that check runs at step 6a BEFORE
/// build_init_tree (box-init + the tree aren't built yet), so requiring these there would fail
/// spuriously — this runs downstream.
pub const REQUIRED_INIT_PATHS: [&str; 9] = [
    "/sbin/init",
    "/usr/bin/box-init",
                                                                                                
    "/etc/box-svc/.s6-svscan/finish",
    "/etc/box-svc/.s6-svscan/SIGTERM",
    "/etc/box-svc/.s6-svscan/SIGUSR1",
    "/etc/box-svc/.s6-svscan/SIGUSR2",
                                                                                                   
                                                                                                 
                                                                                                          
                                                                                            
    "/etc/box-svc/haproxy/run",
    "/etc/box-svc/dropbear/run",
    "/etc/box-svc/rescue-dropbear/run",
];
                                                                                                          
                                                                                                
                                                                                    
                                                                                                       
                                                                                               

/// Assert every [`REQUIRED_INIT_PATHS`] entry is present (run AFTER build_init_tree, before the signer).
pub fn check_required_init_components<'a>(
    staged: impl IntoIterator<Item = &'a str>,
    tenant_service_runs: &[String],
) -> Result<(), ConfigError> {
    let paths: std::collections::HashSet<&str> = staged.into_iter().collect();
    for required in REQUIRED_INIT_PATHS {
        if !paths.contains(required) {
            return Err(ConfigError::MissingRequiredComponent(required.to_string()));
        }
    }
                                                                                                     
                                                                                                      
                                                                                                           
    for run in tenant_service_runs {
        if !paths.contains(run.as_str()) {
            return Err(ConfigError::MissingRequiredComponent(run.clone()));
        }
    }
    Ok(())
}

/// Validate an operator-provided domain as an RFC-1123 hostname BEFORE it is interpolated into the
/// generated `haproxy.cfg` (`haproxy_config`). Rejects anything outside the per-label allow-list —
/// closing the config-injection vector (a newline-bearing domain could otherwise inject arbitrary
/// haproxy directives into the load-bearing mTLS frontend; spec step 6 / line 1037). M-2.
pub fn validate_domain(domain: &str) -> Result<(), ConfigError> {
    let bad = |m: &str| Err(ConfigError::InvalidDomain(format!("{domain:?}: {m}")));
    if domain.is_empty() || domain.len() > 253 {
        return bad("must be 1..=253 characters");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return bad("no leading or trailing '.'");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return bad("each '.'-separated label must be 1..=63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return bad("a label must not start or end with '-'");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return bad("RFC-1123 label characters are [A-Za-z0-9-] only");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sample_fixture_loads_through_the_parse_gate() {
                                                                                                           
                                                                                                        
                                                                            
        let m = sample_manifest();
        assert!(m.manifest().identities.iter().any(|i| i.name == "blogd"));
    }

    #[test]
    fn load_manifest_refuses_a_malformed_supplied_manifest() {
                                                                                                 
                                                                                                      
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.toml");
        std::fs::write(&p, "schema_version = 1\nbackdoor = true\n").unwrap();
        assert!(matches!(load_manifest(&p), Err(ConfigError::Manifest(_))));
    }

    #[test]
    fn load_manifest_refuses_a_privilege_escalating_supplied_manifest() {
                                                                                                    
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("evil.toml");
        let sample = include_str!("../tests/fixtures/sample-tenant.toml");
        std::fs::write(&p, sample.replace("uid = 100", "uid = 0")).unwrap();
        assert!(matches!(load_manifest(&p), Err(ConfigError::Manifest(_))));
    }

    #[test]
    fn redacted_path_with_a_regex_metachar_is_escaped_on_the_match_side() {
                                                                                                     
                                                                                                    
        let mut edge = sample_manifest().manifest().edge.clone();
        edge.redacted_paths = vec!["/a.b+c/".to_string()];
        edge.redacted_query_params = vec![];
        let red = compose_redaction(&edge);
        assert!(
            red.contains("regsub(^/a\\.b\\+c/[^/?]+,/a.b+c/<redacted>)"),
            "match side must be regex-escaped, replacement literal: {red}"
        );
                                                                                              
        assert!(
            !compose_redaction(&sample_manifest().manifest().edge).contains('\\'),
            "no backslash in the sample redaction (its paths have no regex metachars)"
        );
    }

    #[test]
    fn no_pam_needed_accepts_clean_rejects_libpam() {
        let clean = vec![(
            "usr/sbin/dropbear".to_string(),
            vec!["libc.musl-x86_64.so.1".to_string()],
        )];
        assert_eq!(check_no_pam_needed(&clean), Ok(()));
        let pam = vec![(
            "usr/sbin/dropbear".to_string(),
            vec![
                "libc.musl-x86_64.so.1".to_string(),
                "libpam.so.0".to_string(),
            ],
        )];
        assert_eq!(check_no_pam_needed(&pam), Err(ConfigError::DropbearPam));
    }

    #[test]
    fn link_completeness_passes_when_all_resolve_and_fails_on_a_miss() {
        use std::collections::HashSet;
        let needed = vec![(
            "usr/sbin/haproxy".to_string(),
            vec![
                "libssl.so.3".to_string(),
                "libc.musl-x86_64.so.1".to_string(),
            ],
        )];
        let complete: HashSet<String> = ["libssl.so.3", "libc.musl-x86_64.so.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(check_link_completeness(&needed, &complete), Ok(()));
                                                                                                          
        let stripped: HashSet<String> = ["libc.musl-x86_64.so.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(
            check_link_completeness(&needed, &stripped),
            Err(ConfigError::UnresolvedLink { soname, .. }) if soname == "libssl.so.3"
        ));
    }

    #[test]
    fn forbidden_components_rejects_systemd_and_apk() {
        let ok = [
            "/sbin/init",
            "/usr/sbin/dropbear",
            "/usr/sbin/haproxy",
            "/bin/s6-svscan",
        ];
        assert_eq!(check_no_forbidden_components(ok), Ok(()));
        let bad = ["/sbin/init", "/usr/lib/systemd/systemd"];
        assert!(matches!(
            check_no_forbidden_components(bad),
            Err(ConfigError::ForbiddenComponent(_))
        ));
    }

    #[test]
    fn required_components_present_passes_missing_fails() {
        let full = [
            "/usr/sbin/dropbear",
            "/usr/sbin/haproxy",
            "/usr/bin/s6-svscan",
            "/usr/bin/s6-svscanctl",
            "/usr/sbin/nft",
            "/usr/bin/recipes",
            "/usr/bin/recipes-admin",
            "/usr/bin/fb-acme",
            "/usr/bin/fb-oneshots",
            "/usr/bin/fb-backup",
            "/usr/bin/fb-cert-check",
            "/sbin/e2fsck",
            "/etc/fstab",
        ];
        assert_eq!(check_required_components(full), Ok(()));
                                                                               
        let missing_dropbear: Vec<&str> = full
            .iter()
            .copied()
            .filter(|p| *p != "/usr/sbin/dropbear")
            .collect();
        assert!(matches!(
            check_required_components(missing_dropbear),
            Err(ConfigError::MissingRequiredComponent(_))
        ));
                                                                                                
        assert!(matches!(
            check_required_components(std::iter::empty()),
            Err(ConfigError::MissingRequiredComponent(_))
        ));
    }

    /// M-3: the busybox applet presence guard — a full applet set (as `busybox --install -s` symlinks)
    /// passes; dropping any one applet the box's scripts shell fails the build closed. Guards the H-1
    /// class (a busybox built without an applet boots but fails at script-run).
    #[test]
    fn required_applets_present_passes_missing_fails() {
                                                                                                        
                                                           
        let full: Vec<String> = REQUIRED_BUSYBOX_APPLETS
            .iter()
            .map(|a| format!("/bin/{a}"))
            .collect();
        assert_eq!(
            check_required_applets(full.iter().map(String::as_str)),
            Ok(())
        );
                                                                                                    
        let missing: Vec<String> = full
            .iter()
            .filter(|p| !p.ends_with("/reboot"))
            .cloned()
            .collect();
        assert!(matches!(
            check_required_applets(missing.iter().map(String::as_str)),
            Err(ConfigError::MissingRequiredComponent(ref m)) if m.contains("reboot")
        ));
                                                             
        assert!(check_required_applets(std::iter::empty()).is_err());
    }

    /// L-1: the bare-name s6 PATH tools (s6-envdir/s6-setuidgid) the run scripts shell. A full set (as
    /// apk-staged paths) passes by basename; dropping one fails the build closed, naming the command.
    #[test]
    fn required_path_commands_present_passes_missing_fails() {
        let full: Vec<String> = REQUIRED_PATH_COMMANDS
            .iter()
            .map(|c| format!("/usr/bin/{c}"))
            .collect();
        assert_eq!(
            check_required_path_commands(full.iter().map(String::as_str)),
            Ok(())
        );
                                                                                
        let missing: Vec<String> = full
            .iter()
            .filter(|p| !p.ends_with("/s6-envdir"))
            .cloned()
            .collect();
        assert!(matches!(
            check_required_path_commands(missing.iter().map(String::as_str)),
            Err(ConfigError::MissingRequiredComponent(ref m)) if m.contains("s6-envdir")
        ));
                                                             
        assert!(check_required_path_commands(std::iter::empty()).is_err());
    }

    #[test]
    fn persist_recovery_tools_are_guarded() {
                                                                                                    
                                                                                                          
                                                                                                 
                                                                                                      
                                                                                               
        assert!(REQUIRED_COMPONENT_PATHS.contains(&"/sbin/e2fsck"));
        assert!(REQUIRED_PATH_COMMANDS.contains(&"resize2fs"));
        assert!(REQUIRED_PATH_COMMANDS.contains(&"tune2fs"));
        assert!(REQUIRED_BUSYBOX_APPLETS.contains(&"findfs"));
        assert!(REQUIRED_BUSYBOX_APPLETS.contains(&"grep"));
    }

    #[test]
    fn dha_staged_script_applets_are_censused() {
                                                                                                           
                                                                                                          
                                                                                                           
                                                                                             
                                                                                                          
                                                                                                          
                           
        for applet in [
            "awk", "cut", "date", "mktemp", "pkill", "printf", "rm", "rmdir", "sed", "stat",
            "tail", "tr", "wc",
        ] {
            assert!(
                REQUIRED_BUSYBOX_APPLETS.contains(&applet),
                "dha staged-script applet {applet:?} must be censused into REQUIRED_BUSYBOX_APPLETS"
            );
        }
    }

    #[test]
    fn mv_is_censused() {
                                                                                                       
                                                                                                       
                                                                                                    
                                                                                                        
                                                                                                      
                                                                                                       
                                         
        assert!(REQUIRED_BUSYBOX_APPLETS.contains(&"mv"));
    }

    #[test]
    fn dha_staged_ac_i_selftest_path_commands_are_censused() {
                                                                                                    
                                                                                                              
                                                                                                           
                                                                                                         
        for cmd in ["s6-svc", "s6-svstat"] {
            assert!(
                REQUIRED_PATH_COMMANDS.contains(&cmd),
                "dha ac-i-selftest path command {cmd:?} must be censused into REQUIRED_PATH_COMMANDS"
            );
        }
    }

    #[test]
    fn validate_domain_accepts_hostnames_rejects_injection() {
        assert_eq!(validate_domain("recipes.example.org"), Ok(()));
        assert_eq!(validate_domain("a.b-c.example123.com"), Ok(()));
        for bad in [
            "",
            "bad domain",
            "has/slash",
            ".lead",
            "trail.",
            "a..b",
            "x\nbind *:80",
            "-lead.com",
        ] {
            assert!(
                matches!(validate_domain(bad), Err(ConfigError::InvalidDomain(_))),
                "should reject {bad:?}"
            );
        }
    }

                                                                                                  
    /// root as a member (so dropbear `-G ssh` admits the operator).
    #[test]
    fn passwd_and_group_bake_the_fr6_30_identities() {
        let ids = sample_manifest().manifest().identities.clone();
        let passwd_txt = passwd(&ids);
        let group_txt = group(&ids);
        assert!(
            passwd_txt.contains("root:x:0:0:root:/root:/bin/sh"),
            "root has a login shell"
        );
        for (name, uid) in [
            ("blogd", 100),
            ("fb-acme", 101),
            ("fb-backup", 102),
            ("fb-cert-check", 103),
            ("haproxy", 104),
            ("dropbear-rescue", 105),
        ] {
            assert!(
                passwd_txt.contains(&format!("{name}:x:{uid}:{uid}:")),
                "{name} must be uid {uid}"
            );
            assert!(
                passwd_txt.contains(&format!("{name}:/var/empty:/sbin/nologin")),
                "{name} is no-login"
            );
            assert!(
                group_txt.contains(&format!("{name}:x:{uid}:")),
                "{name} group gid {uid}"
            );
        }
                                                                               
        assert!(
            group_txt.contains("ssh:x:22:root"),
            "ssh group must contain root for dropbear -G ssh"
        );
    }

    /// I-3a: the init-path presence check (run downstream of build_init_tree) catches the
    /// build-ok-but-boot-FATAL class.
    #[test]
    fn required_init_components_catches_missing_init_or_finish() {
                                                                                              
        let full: Vec<&str> = REQUIRED_INIT_PATHS.to_vec();
        assert_eq!(
            check_required_init_components(full.iter().copied(), &[]),
            Ok(())
        );
                                                                                                          
                                                                                                      
                                                                                                     
        for missing in REQUIRED_INIT_PATHS {
            let partial: Vec<&str> = REQUIRED_INIT_PATHS
                .iter()
                .copied()
                .filter(|p| *p != missing)
                .collect();
            assert!(
                matches!(
                    check_required_init_components(partial, &[]),
                    Err(ConfigError::MissingRequiredComponent(p)) if p == missing
                ),
                "dropping {missing} must fail the init-presence guard"
            );
        }
    }

                                                                                                   
    /// have a staged run-script (not just the hardcoded `recipes` one), else the build fails closed.
    #[test]
    fn required_init_components_requires_each_manifest_service_run() {
        let staged: Vec<&str> = REQUIRED_INIT_PATHS.to_vec();
        let tenant = vec!["/etc/box-svc/widget/run".to_string()];
                                                                              
        assert!(matches!(
            check_required_init_components(staged.iter().copied(), &tenant),
            Err(ConfigError::MissingRequiredComponent(p)) if p == "/etc/box-svc/widget/run"
        ));
                         
        let mut staged2 = staged.clone();
        staged2.push("/etc/box-svc/widget/run");
        assert_eq!(
            check_required_init_components(staged2.iter().copied(), &tenant),
            Ok(())
        );
    }
}
