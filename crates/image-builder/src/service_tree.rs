                                                                             
//!
//! Emits, as STATIC Rust functions, the **servicedirs** that live on the SIGNED read-only rootfs at
//! `/etc/box-svc/<name>/` + the `s6-svscan` control **handlers** at `/etc/box-svc/.s6-svscan/`.
//! `box-init` (the PID-1) discovers these at boot, symlinks them into the tmpfs scandir, and execs
//! `s6-svscan` — so every `run` script + handler is appraised (it lives on the verity rootfs); only
                                                                                                     
//!
//! The bootstrap/rescue ONESHOTS moved to `box-init` (`crates/box-init/src/oneshots.rs`); this module
//! emits only the LONGRUN servicedirs + the handlers, plus the box env (`box_env`) + firewall
//! (`nftables_config`) config files (`render_configs` writes those). Spec:
                                                                               
//!
                                                                                    
//! The network-facing surface drops privilege: **recipes→uid 100, fb-acme→101** (via
//! `s6-setuidgid`), **haproxy workers→104** (its own `user`/`group` directive; the master reads certs
//! as root). dropbear + ntpd stay root by function (SSH auth / setting the clock); fb-backup +
//! fb-cert-check stay root because they read across all of `/persist`.
//!
//! ## CONTRACT with `box-init` (load-bearing)
//! - The servicedir set here must match what `box-init`'s `scandir::discover_servicedirs` expects:
//!   `rescue-*` → the rescue scandir, the rest → services. A stray dir would be supervised; a missing
//!   one would dangle. The boot-gate (plan Task 13) verifies.
//! - box-init builds each live servicedir as a WRITABLE tmpfs dir with `run` symlinked here; s6-supervise
//!   creates `supervise`/`event` there. The rootfs servicedir holds only the signed `run` (no symlinks).
//! - The `.s6-svscan/{finish,SIGTERM,SIGUSR1,SIGUSR2}` handler set must match `box-init`'s
                                                                                                      
//!
//! ## The C-1 sign-window invariant (load-bearing)
//! Everything here is written into the staging tree BEFORE the IMA/EVM signer (`build()` step 8), so
//! every `run` script + handler is a signed rootfs file. The run scripts are `#!/bin/sh`, so at
//! runtime the kernel BPRM-appraises the `busybox` interpreter + every service binary they `exec` —
//! all rootfs ELFs, signed. See `build_init_tree`.

use std::io;
use std::path::Path;

use fb_manifest::argv::{ArgvToken, KnownPlaceholder};
use fb_manifest::manifest::{
    DeathEvents, EnvKv, EnvSpec, NftSpec, OnExhaust, Priv, ProbeSpec, ResourceDomain, ServiceShape,
    ServiceSpec,
};
use fb_manifest::{render_env_value, PlaceholderCtx};

/// os-update A/B v1 (C-D): the OS-invariant `fb-mark-good` update health-probe longrun's binary + probe
/// cadence. The probe polls tenant health each cycle and commits-or-rolls-back an update in probation;
/// 10 s bounds the rollback latency (a bad update reboots within a few cycles) without busy-spinning.
const MARK_GOOD_BIN: &str = "/usr/bin/fb-mark-good";
const MARK_GOOD_CADENCE_SECS: u64 = 10;

                                                                                            
/// `fb-oneshots cert-reload-check` per cycle content-hash-polls the tenant cert and `s6-svc -2`s
/// HAProxy on change (hitless SIGUSR2 reload). 10 s matches fb-mark-good: bounds the
/// stale-cert window after a rotation without busy-spinning. The `/run/service/haproxy` reload
                                                                                   
const CERT_RELOAD_BIN: &str = "/usr/bin/fb-oneshots";
const CERT_RELOAD_CADENCE_SECS: u64 = 10;

/// The pinned NTP server for busybox `ntpd`: Infomaniak's FIRST-PARTY stratum-1 (the settled
                                                                                                    
/// this had drifted to the public `ch.pool.ntp.org`, voiding the decision's rationale for dropping
/// NTS — plain NTP to a first-party server already IN the box's TCB needs no MITM protection (an
/// attacker on that path already owns the substrate), but plain NTP across the open internet to
/// arbitrary public-pool servers reintroduces exactly the time-MITM surface NTS would have guarded.
/// kvm-clock is the PRIMARY source (ntpd is the best-effort wall-clock self-heal; cert validity is
/// independently floor-gated by fb-acme `--min-epoch`). SUBSTRATE-COUPLED: a move off Infomaniak
/// resurfaces the NTS question (see the memory's revisit trigger).
pub const NTP_SERVER: &str = "pool.ntp.infomaniak.ch";

/// The rescue dropbear banner (spec L765), baked at `/etc/dropbear/rescue-banner`.
pub const RESCUE_BANNER: &str =
    "RESCUE MODE — /persist mount failed. Recovery pubkey only. See operator runbook for diagnosis steps.\n";

/// The box environment, baked as the `/etc/recipes/env` envdir (one file per var; `render_configs`
/// writes them) and applied via an `s6-envdir /etc/recipes/env` prefix on the run scripts that read
/// it (recipes, fb-acme-serve; bootstrap-ca, a box-init oneshot, also uses it).
pub fn box_env(env: &EnvSpec, ctx: &PlaceholderCtx) -> Vec<(String, String)> {
    env.vars
        .iter()
        .map(|(k, frags)| (k.clone(), render_env_value(frags, ctx)))
        .collect()
}

/// Build-time network mode for the firewall generator (seam 4). build-A passes [`NetMode::Static`]; the
/// DHCP build (a documented seam) passes `Dhcp`, which appends the lease rules. NO parameterless overload
                                                                                                             
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Static,
    Dhcp,
}

                                                                                                         
/// ICMP, and the three public ports (22 dropbear, 80 ACME-challenge, 443 mTLS). OUTPUT: default-drop with
/// the box's fixed egress (DNS/NTP/ACME+OCSP) + replies (`established,related`) + loopback — defense-in-depth
/// against post-compromise exfil (R1-8; bypassable over 443, so a speed-bump not a wall). `mode=Dhcp` adds
/// the broadcast lease rules. The `nftables-load` box-init oneshot applies it before any longrun binds.
pub fn nftables_config(nft: &NftSpec, mode: NetMode) -> String {
    let dhcp_in = match mode {
        NetMode::Dhcp => "        udp sport 67 dport 68 accept\n",
        NetMode::Static => "",
    };
    let dhcp_out = match mode {
        NetMode::Dhcp => "        udp dport 67 accept\n",
        NetMode::Static => "",
    };
                                                                                                    
                                                                                          
    let input_ports: String = nft
        .tcp_ports
        .iter()
        .map(|p| format!("        tcp dport {p} accept\n"))
        .collect();
    format!(
        "\
#!/usr/sbin/nft -f
# /etc/nftables.conf — generated statically by recipes-image-builder (no operator-mutable firewall).
flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif \"lo\" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
{input_ports}{dhcp_in}    }}
    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}
    chain output {{
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oif \"lo\" accept
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        tcp dport 443 accept
        tcp dport 80 accept
{dhcp_out}    }}
}}
"
    )
}

                                                                                                    

/// One longrun servicedir emitted to `/etc/box-svc/<name>/`. `run` is the `#!/bin/sh` supervised
/// script (mode 0755). `box-init` partitions services vs rescue by the `rescue-` name prefix.
pub struct ServiceDir {
    pub name: String,
    pub run: String,
    /// The optional per-service `finish` (§4.3b): an `s6-permafailon` restart-cap. `None` = no cap
    /// (the box's existing no-throttle behaviour). Written mode 0755 alongside `run`.
    pub finish: Option<String>,
}

/// Every longrun servicedir: the 8 services + `rescue-dropbear`. Run-script content is unchanged from
/// the prior s6-rc longrun definitions. The bootstrap/rescue oneshots are NOT here (they run in
/// box-init); the dependency *ordering* the old `dependencies` files encoded is now enforced by
/// box-init running all bootstrap oneshots before any longrun starts (oneshot→longrun edges) + the
/// services' own backoff loops (the `fb-acme-renew` ← serve/haproxy availability edge).
/// Whether the ENGINE leaf's run script verifies + mounts the model volume at service start
/// (hotswap v4 §3, Task 4). `Runtime` renders the `/usr/bin/fb-weights setup || exit 1` prelude —
/// root, between the §4.3a cgroup placement and the uid-drop `exec`, fail-closed and s6-SCOPED (a
/// failure downs only the engine via its restart-cap; NEVER a box-init oneshot Rescue/Reboot).
/// `None` = the boot-anchored shape (the dha box) — every run script byte-identical to before.
/// This is a BUILD-shape property (the Task-7 `weights_partition`/no-boot-triple decouple), not a
/// tenant-manifest field, so it threads as a renderer parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineWeightsSetup {
    /// No runtime weights setup (boot-anchored or weight-less boxes). The pre-hotswap render.
    None,
    /// Render the fail-closed `fb-weights setup` prelude on the engine leaf.
    Runtime,
}

/// The engine-leaf run-script prelude `EngineWeightsSetup::Runtime` renders (hotswap v4 §3): the
/// signed `fb-weights` helper reads the persisted signed weights record, quince-verifies it
/// (`Purpose::Weights`, clock-free at boot — Rider 1), resolves the weights partition, sets up
/// runtime dm-verity (EIO mode) and mounts `/models` RO — then the engine execs. Root (the run
/// script has not dropped uid yet); `|| exit 1` fails the run, which the engine's s6 restart-cap
/// turns into a service-scoped `down`.
const WEIGHTS_SETUP_LINE: &str = "/usr/bin/fb-weights setup || exit 1\n";

pub fn servicedirs(
    services: &[ServiceSpec],
    rd: Option<&ResourceDomain>,
    ctx: &PlaceholderCtx,
    probe: &ProbeSpec,
    weights: EngineWeightsSetup,
) -> Vec<ServiceDir> {
    let mut dirs = vec![
                                                                                                      
                                                                                        
        ServiceDir {
            name: "ntpd".to_string(),
            run: format!("#!/bin/sh\nexec /usr/sbin/ntpd -n -p {NTP_SERVER}\n"),
            finish: None,
        },
                                                                             
        ServiceDir {
            name: "dropbear".to_string(),
            run: crate::config::dropbear_run_script(),
            finish: None,
        },
                                                                                                 
                                                                                         
        ServiceDir {
            name: "haproxy".to_string(),
            run: "#!/bin/sh\nexec /usr/sbin/haproxy -db -f /etc/haproxy/haproxy.cfg\n".to_string(),
            finish: None,
        },
                                                                                                           
                                                                                                        
                                                                                            
                                                                                                          
                                                                                                         
                                                                                                         
                                                                                                         
                                                                                                          
                                                                                                        
                                                              
        ServiceDir {
            name: "fb-mark-good".to_string(),
            run: render_run_script(
                &ServiceShape::PeriodicLoop {
                    binary: MARK_GOOD_BIN.to_string(),
                                                                                            
                                                                                                 
                                                                                             
                                                                                             
                                                                                                
                                                                                          
                                                                                      
                    argv: vec![
                        ArgvToken::Literal {
                            value: "--probe-port".to_string(),
                        },
                        ArgvToken::Literal {
                            value: probe.port.to_string(),
                        },
                        ArgvToken::Literal {
                            value: "--probe-path".to_string(),
                        },
                        ArgvToken::Literal {
                            value: probe.path.clone(),
                        },
                        ArgvToken::Literal {
                            value: "--probe-host".to_string(),
                        },
                        ArgvToken::Placeholder {
                            name: KnownPlaceholder::Domain,
                        },
                    ],
                    interval_secs: MARK_GOOD_CADENCE_SECS,
                    privilege: Priv::Root {},
                },
                None,
                false,
                ctx,
            ),
            finish: None,
        },
                                                                                           
                                                                                                     
                                                                                                   
                                                                                               
                                                                                                     
                                                                                                    
                                                                                                 
                                                                                             
                                                                                                 
                                                                                               
                                                                                                     
        ServiceDir {
            name: "fb-cert-reload".to_string(),
            run: render_run_script(
                &ServiceShape::PeriodicLoop {
                    binary: CERT_RELOAD_BIN.to_string(),
                    argv: vec![
                        ArgvToken::Literal {
                            value: "cert-reload-check".to_string(),
                        },
                        ArgvToken::Literal {
                            value: "--domain".to_string(),
                        },
                        ArgvToken::Placeholder {
                            name: KnownPlaceholder::Domain,
                        },
                    ],
                    interval_secs: CERT_RELOAD_CADENCE_SECS,
                    privilege: Priv::Root {},
                },
                None,
                false,                                                                                
                ctx,
            ),
            finish: None,
        },
    ];
                                                                                                         
                                                                                                     
                                                                                                           
    for svc in services {
                                                                                                     
                                                                                                       
        let cgroup = rd.and_then(|rd| dha_leaf_cgroup(rd, &svc.name));
                                                                                                
                                                                                        
        let weights_setup = weights == EngineWeightsSetup::Runtime
            && rd
                .and_then(|rd| rd.engine.as_ref())
                .is_some_and(|e| e.service == svc.name);
        dirs.push(ServiceDir {
            name: svc.name.clone(),
            run: render_run_script(&svc.shape, cgroup.as_deref(), weights_setup, ctx),
            finish: render_finish(&svc.shape),
        });
    }
                                                                                      
    dirs.push(ServiceDir {
        name: "rescue-dropbear".to_string(),
        run: rescue_dropbear_run(),
        finish: None,
    });
    dirs
}

/// The cgroup a dha leaf-assigned service places its PID into (§4.3a): the engine (creatine) →
/// `<name>/creatine`; the orchestrator → `<name>/work/orch`. `None` for any non-leaf service — it
/// renders no placement prologue. Names come from the validated `ResourceDomain` (`engine.service` /
/// `work.orchestrator`); a non-dha box passes `rd = None` and never reaches here.
fn dha_leaf_cgroup(rd: &ResourceDomain, service_name: &str) -> Option<String> {
    let leaf = if rd
        .engine
        .as_ref()
        .is_some_and(|e| e.service == service_name)
    {
        "creatine"
    } else if rd.work.orchestrator == service_name {
        "work/orch"
    } else {
        return None;
    };
    Some(format!("/sys/fs/cgroup/{}/{}", rd.name, leaf))
}

/// Render one longrun `run` script from its typed [`ServiceShape`] (§5.1c). The `#!/bin/sh` shebang, the
/// `exec` / `while … sleep … done` loop, and the `s6-envdir`/`s6-setuidgid` privilege prefix are
/// OS-invariant templates; only the binary + the (gate-charset-validated) argv tokens + the loop interval
/// are tenant data.
fn render_run_script(
    shape: &ServiceShape,
    cgroup: Option<&str>,
    weights_setup: bool,
    ctx: &PlaceholderCtx,
) -> String {
    let (binary, argv, privilege, interval, env) = match shape {
        ServiceShape::Exec {
            binary,
            argv,
            privilege,
            env,
            restart_cap: _,                                                                         
        } => (binary, argv, privilege, None, env.as_deref()),
        ServiceShape::PeriodicLoop {
            binary,
            argv,
            interval_secs,
            privilege,
        } => (binary, argv, privilege, Some(*interval_secs), None),
    };
    let cmd = fb_manifest::render_command(binary, argv, privilege, ctx);
                                                                                                       
                                                                                                       
                                                                                                       
                                                                                                      
                                                                                                         
                                                                                                        
                                                                                                         
                                                                                                           
                                                                                                         
                                                                                                  
    let prologue = cgroup
        .map(|cg| {
            format!(
                "echo $$ > \"{cg}/cgroup.procs\" || exit 1\n\
                 grep -qx \"$$\" \"{cg}/cgroup.procs\" || exit 1\n"
            )
        })
        .unwrap_or_default();
                                                                                                       
                                                                                                      
                                                                                                      
                                                                                                           
                                                                 
    let env_prologue = env.map(render_env_prologue).unwrap_or_default();
                                                                                                     
                                                                                                   
                                                                                          
    let weights_prologue = if weights_setup {
        WEIGHTS_SETUP_LINE
    } else {
        ""
    };
    match interval {
        None => format!("#!/bin/sh\n{prologue}{weights_prologue}{env_prologue}exec {cmd}\n"),
        Some(secs) => format!(
            "#!/bin/sh\n{prologue}{weights_prologue}{env_prologue}while : ; do {cmd} ; sleep {secs} ; done\n"
        ),
    }
}

/// Render a [`ServiceShape::Exec`]'s inline env as `export KEY='VAL'` lines (§4.5). The KEY is a
/// gate-validated POSIX env name (`[A-Z_][A-Z0-9_]*` — no quoting needed); the VALUE is single-quoted
/// via [`shell_sq`].
fn render_env_prologue(env: &[EnvKv]) -> String {
    env.iter()
        .map(|kv| format!("export {}={}\n", kv.key, shell_sq(&kv.value)))
        .collect()
}

                                                                                                        
/// Inside `'…'` every byte is literal to the shell; an embedded `'` is POSIX-escaped `'\''`. The §5.3
/// env-value gate rejects NUL/newline but permits arbitrary other bytes, so this quoting is load-bearing.
fn shell_sq(value: &str) -> String {
    if value.contains('\'') {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        format!("'{value}'")
    }
}

/// The per-service `finish` (§4.3b) for an Exec longrun that declares a `RestartCap`: an
/// `s6-permafailon <window_secs> <max_restarts> <events> true`. On ≥`max_restarts` deaths whose cause is
/// in `<events>` within `<window_secs>` seconds, s6-permafailon **`exit 125`s** → s6-supervise stops
/// respawning (permanent-down; operator rearm via `s6-svc -u`). The `true` prog is the UNDER-cap path
/// (the death didn't permafail → `exec true` → the finish completes → s6 restarts); the typed failure is
/// the orchestrator's RPC concern (observed out-of-band via `s6-svstat` + `memory.events`), NOT the
/// finish (dha-confirmed). `None` for a service without a cap. `OnExhaust::Rescue` is rejected upstream
/// ([`reject_unsupported_restart_caps`]) — v1 implements `Down` only, so the finish shape is identical
/// for every capped service (cap-exhaustion is s6's `exit 125`, not a finish-script branch).
fn render_finish(shape: &ServiceShape) -> Option<String> {
    let ServiceShape::Exec {
        restart_cap: Some(cap),
        ..
    } = shape
    else {
        return None;
    };
    let events = render_death_events(&cap.events);
    Some(format!(
        "#!/bin/sh\nexec s6-permafailon {} {} {} true\n",
        cap.window_secs, cap.max_restarts, events
    ))
}

/// Render `DeathEvents` to s6-permafailon's comma-separated `events` list (§4.3b, dha-confirmed).
/// `on_nonzero_exit` → `1-255` (every non-zero exit; a clean `exit 0`, e.g. a cold model reload, is NOT
/// a failure). `on_signal` → the verified CRASH-signal list: the fault signals + **`SIGKILL`** (the OOM
/// killer's signal — the reload-aware cap exists to bound a creatine that OOM-bounces), but NOT the
/// operator-control signals (`HUP`/`INT`/`QUIT`/`TERM` — an operator `s6-svc` bounce raises those and
/// must not permafail the service). s6-permafailon supports neither a signal range nor an "any-signal"
/// token (verified skarnet), so the crash set is enumerated explicitly.
fn render_death_events(events: &DeathEvents) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if events.on_nonzero_exit {
        parts.push("1-255");
    }
    if events.on_signal {
        parts.push("SIGILL,SIGABRT,SIGBUS,SIGFPE,SIGKILL,SIGSEGV,SIGSYS");
    }
    parts.join(",")
}

/// v1 implements only `OnExhaust::Down` (s6-permafailon's `exit 125` permanent-down; operator rearm via
/// `s6-svc -u`). `OnExhaust::Rescue` (a divert to the rescue surface on cap-exhaustion) is NOT built —
/// reject it **fail-closed at the bake** (dha-confirmed: NEVER silently downgrade to `Down`). A pure
/// check so the bake refuses a Rescue-requesting manifest before rendering any servicedir.
fn reject_unsupported_restart_caps(services: &[ServiceSpec]) -> Result<(), String> {
    for svc in services {
        if let ServiceShape::Exec {
            restart_cap: Some(cap),
            ..
        } = &svc.shape
        {
            if matches!(cap.on_exhaust, OnExhaust::Rescue {}) {
                return Err(format!(
                    "service {:?}: RestartCap on_exhaust=Rescue is unsupported in v1 (only Down)",
                    svc.name
                ));
            }
        }
    }
    Ok(())
}

/// The rescue dropbear run script (spec L760-766): the services-dropbear flags MINUS `-R` (host keys
/// are pre-derived by the rescue-keys-stage box-init oneshot), the rescue tmpfs host-key path, + the
/// `-b` banner.
fn rescue_dropbear_run() -> String {
    "#!/bin/sh\nexec /usr/sbin/dropbear -F -E \
-r /run/dropbear-rescue/dropbear_ed25519_host_key \
-s -G ssh -I 1800 -K 300 -T 3 \
-b /etc/dropbear/rescue-banner\n"
        .to_string()
}

                                                                                                    

/// One `.s6-svscan/<name>` handler script emitted to `/etc/box-svc/.s6-svscan/` (mode 0755).
pub struct HandlerScript {
    pub name: &'static str,
    pub body: String,
}

                                                                                                     
/// REPLACES the builtin, so each shutdown-signal handler drives the ORDERLY stop via `s6-svscanctl -t`
/// (which stops the supervision tree, then execs `.s6-svscan/finish`) — NOT a direct mid-supervision
/// reboot. `finish` reads the action marker, syncs, *tolerantly* unmounts `/persist` (it is NOT
/// mounted in rescue mode — guard + no `set -e`), then performs the action and NEVER returns (it is
/// PID-1 after svscan execs into it; a return/missing-finish panics the kernel). MUST match
/// `box-init`'s `scandir::HANDLERS`.
pub fn svscan_handlers() -> Vec<HandlerScript> {
    let sig = |verb: &str| -> String {
                                                                                                    
        format!(
            "#!/bin/sh\necho {verb} > /run/shutdown-action\nexec s6-svscanctl -t /run/service\n"
        )
    };
    vec![
        HandlerScript {
            name: "SIGTERM",
            body: sig("reboot"),
        },                                     
        HandlerScript {
            name: "SIGUSR1",
            body: sig("halt"),
        },                           
        HandlerScript {
            name: "SIGUSR2",
            body: sig("poweroff"),
        },                               
        HandlerScript {
            name: "finish",
                                                                                                     
                                                                                                  
            body: "#!/bin/sh\n\
action=$(cat /run/shutdown-action 2>/dev/null || echo reboot)\n\
sync\n\
mountpoint -q /persist && umount /persist\n\
case \"$action\" in\n\
  halt) halt -f ;;\n\
  poweroff) poweroff -f ;;\n\
  *) reboot -f ;;\n\
esac\n"
                .to_string(),
        },
    ]
}

                                                                                                    

/// Write the servicedir tree + the `.s6-svscan` handlers into `staging/etc/box-svc/`. Called
/// host-side BEFORE the IMA/EVM signer (in `build_init_tree`). Each rootfs servicedir holds ONLY the
/// signed `run` (mode 0755); the `.s6-svscan` dir holds the handler scripts (also 0755). NO
/// `supervise`/`event` is written here: box-init builds each LIVE servicedir as a writable tmpfs dir
/// (its `run` symlinked to this signed rootfs `run`) and s6-supervise creates `supervise`/`event`
/// THERE at boot (s6 servicedir.html). There is no `/run/service-state` layout — the earlier
/// supervise/event-as-dangling-symlink design was REMOVED (it FATALed: s6-supervise `mkdir`s `event`,
                                                                          
pub fn write_servicedir_tree(
    staging: &Path,
    domain: &str,
    source_date_epoch: u64,
    manifest: &fb_manifest::ValidatedManifest,
    weights: EngineWeightsSetup,
) -> io::Result<()> {
    let root = staging.join("etc/box-svc");
                                                                                                       
                                                                                               
    reject_unsupported_restart_caps(&manifest.manifest().services).map_err(io::Error::other)?;
                                                                                                       
                                                                                           
    let ctx = PlaceholderCtx {
        domain: domain.to_string(),
        source_date_epoch,
    };
    for sd in servicedirs(
        &manifest.manifest().services,
        manifest.manifest().resource_domain.as_ref(),
        &ctx,
        &manifest.manifest().probe,
        weights,
    ) {
        let dir = root.join(sd.name);
        std::fs::create_dir_all(&dir)?;
        let run = dir.join("run");
        std::fs::write(&run, &sd.run)?;
        set_mode(&run, 0o755)?;
                                                                                                   
                                                                                                      
        if let Some(finish) = &sd.finish {
            let fin = dir.join("finish");
            std::fs::write(&fin, finish)?;
            set_mode(&fin, 0o755)?;
        }
                                                                                                         
                                                                                                  
    }
    let ctrl = root.join(".s6-svscan");
    std::fs::create_dir_all(&ctrl)?;
    for h in svscan_handlers() {
        let p = ctrl.join(h.name);
        std::fs::write(&p, &h.body)?;
        set_mode(&p, 0o755)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The synthetic sample tenant's longruns / env, from the parsed sample manifest — test helpers
    /// that prove the threaded renderers work for a COMPLETE (non-recipes) tenant. Post-shed orchard
    /// holds no recipes manifest; the recipes-specific render is sealed by the boot-gate.
    fn sample_services() -> Vec<ServiceSpec> {
        crate::config::sample_manifest().manifest().services.clone()
    }
    /// The reference-shaped health probe (§5.1f: 443 + `/`) the fb-mark-good render wires.
    fn probe443() -> ProbeSpec {
        ProbeSpec {
            port: 443,
            path: "/".to_string(),
        }
    }
    fn sample_env_spec() -> EnvSpec {
        crate::config::sample_manifest().manifest().env.clone()
    }

    /// A representative nftables ingress set (the OS default 22/80/443) — feeding these proves the
    /// threaded `nftables_config` renders the allowlist + keeps the OS-invariant default-deny.
    fn ref_nft() -> NftSpec {
        NftSpec {
            tcp_ports: vec![22, 80, 443],
        }
    }

    /// Index the longrun servicedirs by name → run-script content.
    fn runs(domain: &str, epoch: u64) -> HashMap<String, String> {
        let ctx = PlaceholderCtx {
            domain: domain.to_string(),
            source_date_epoch: epoch,
        };
        servicedirs(
            &sample_services(),
            None,
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        )
        .into_iter()
        .map(|s| (s.name, s.run))
        .collect()
    }

    /// The servicedir set is EXACTLY the OS longruns (ntpd/dropbear/haproxy) + the tenant services in
    /// manifest order + rescue-dropbear (guards box-init's discovery against a stray/missing servicedir).
    #[test]
    fn servicedirs_cover_exactly_the_expected_set() {
        let ctx = PlaceholderCtx {
            domain: "box.example.org".to_string(),
            source_date_epoch: 1_700_000_000,
        };
        let names: Vec<_> = servicedirs(
            &sample_services(),
            None,
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        )
        .into_iter()
        .map(|s| s.name)
        .collect();
        assert_eq!(
            names,
            [
                "ntpd",
                "dropbear",
                "haproxy",
                                                                                                     
                                                                                         
                "fb-mark-good",
                                                                                                       
                                                                                                
                "fb-cert-reload",
                "blogd",
                "blogd-worker",
                "fb-backup",
                "rescue-dropbear",
            ]
        );
    }

                                                                                             
    /// (10 s), byte-identical to the shared template — literals single-quoted, the domain
    /// placeholder BARE (the build-time-baked literal, like fb-mark-good's --probe-host), the
    /// `/run/service/haproxy` target NOT in the argv (a fixed const inside fb-oneshots) — and is
                                                                         
    #[test]
    fn fb_cert_reload_renders_root_periodic_loop() {
        let ctx = PlaceholderCtx {
            domain: "box.example.org".to_string(),
            source_date_epoch: 1_700_000_000,
        };
        let dirs = servicedirs(
            &sample_services(),
            None,
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        );
        let cr = dirs
            .iter()
            .find(|d| d.name == "fb-cert-reload")
            .expect("fb-cert-reload must be an OS-invariant servicedir");

                                                                             
                                                                            
                                                              
        assert_eq!(
            cr.run,
            format!(
                "#!/bin/sh\nwhile : ; do '{CERT_RELOAD_BIN}' 'cert-reload-check' '--domain' \
                 box.example.org ; sleep 10 ; done\n"
            )
        );
        assert!(cr.run.contains("sleep 10 ;"), "10 s cadence: {}", cr.run);
        assert!(
            !cr.run.contains("/run/service/haproxy"),
            "the reload target lives inside fb-oneshots, never rendered argv: {}",
            cr.run
        );
                                                                                          
                                                                                              
        assert!(
            !cr.run.contains("s6-setuidgid"),
            "fb-cert-reload runs as root: {}",
            cr.run
        );
        assert!(
            !cr.name.starts_with("rescue-")
                && !dirs.iter().any(|d| d.name == "rescue-fb-cert-reload"),
            "services scandir only, never rescue"
        );
        assert!(
            cr.finish.is_none(),
            "the watcher loop needs no finish handler"
        );
    }

    /// T19 (os-update A/B v1): fb-mark-good renders as a Services-scandir PeriodicLoop (10 s cadence),
    /// root (no uid-drop — N1), and is NEVER in the rescue scandir (a rescue boot must not commit
    /// an update). Its byte shape matches the shared PeriodicLoop template (no drift from the tenant loops).
    #[test]
    fn service_tree_has_mark_good_services_only() {
        let ctx = PlaceholderCtx {
            domain: "box.example.org".to_string(),
            source_date_epoch: 1_700_000_000,
        };
        let dirs = servicedirs(
            &sample_services(),
            None,
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        );
        let mg = dirs
            .iter()
            .find(|d| d.name == "fb-mark-good")
            .expect("fb-mark-good must be an OS-invariant servicedir");

                                                                                                      
                                                     
        assert!(
            !mg.name.starts_with("rescue-"),
            "fb-mark-good must be Services-only, never rescue-prefixed"
        );
        assert!(
            !dirs.iter().any(|d| d.name == "rescue-fb-mark-good"),
            "no rescue variant of fb-mark-good may exist"
        );

                                                                                                  
                                                                                                    
                                                                                                    
                                                                                            
                                                                
        assert_eq!(
            mg.run,
            format!(
                "#!/bin/sh\nwhile : ; do '{MARK_GOOD_BIN}' '--probe-port' '443' '--probe-path' '/' \
                 '--probe-host' box.example.org ; sleep {MARK_GOOD_CADENCE_SECS} ; done\n"
            )
        );
        assert!(mg.run.contains("sleep 10 ;"), "10 s cadence: {}", mg.run);
        assert!(
            !mg.run.contains("--boot-dev"),
            "no baked device literal — the bin self-resolves: {}",
            mg.run
        );

                                                                                          
        assert!(
            !mg.run.contains("s6-setuidgid"),
            "fb-mark-good runs as root (no uid-drop): {}",
            mg.run
        );
        assert!(
            mg.finish.is_none(),
            "the probe loop needs no finish handler"
        );
    }

    /// D1 (§4.3a) — a dha engine/orchestrator service renders the FAIL-CLOSED cgroup placement
    /// prologue (`echo $$ > .../cgroup.procs || exit 1` before `exec`); NO `oom_score_adj` line (both
    /// leaves are the default 0 — O5); a non-leaf service is byte-unchanged.
    #[test]
    fn dha_leaves_render_the_fail_closed_placement_prologue() {
        use fb_manifest::manifest::{
            ByteSize, EngineLeaf, Priv, ServiceShape, ServiceSpec, Uid, WorkSubtree,
        };
        let exec = |name: &str, bin: &str, user: Option<&str>| ServiceSpec {
            name: name.to_string(),
            shape: ServiceShape::Exec {
                binary: bin.to_string(),
                argv: vec![],
                privilege: match user {
                    Some(u) => Priv::Setuidgid {
                        user: u.to_string(),
                        envdir: None,
                    },
                    None => Priv::Root {},
                },
                restart_cap: None,
                env: None,
            },
        };
        let services = vec![
            exec("dha-creatine", "/usr/bin/dha-creatine", Some("dha")),
            exec("dha-orchestrator", "/usr/bin/dha-orchestrator", Some("dha")),
            exec("ntpd-ish", "/usr/sbin/ntpd", None),                      
        ];
        let rd = ResourceDomain {
            name: "dha".into(),
            memory_max: ByteSize(8_000_000_000),
            delegate_uid: Uid(110),
            engine: Some(EngineLeaf {
                service: "dha-creatine".into(),
                memory_max: ByteSize(6_000_000_000),
                memory_min: None,
                oom_group: true,
            }),
            work: WorkSubtree {
                orchestrator: "dha-orchestrator".into(),
                orch_memory_min: None,
                job_memory_max: ByteSize(512_000_000),
                job_pids_max: Some(64),
                max_descendants: 16,
                max_depth: 2,
                work_pids_max: 1024,
            },
        };
        let ctx = PlaceholderCtx {
            domain: "box.example.org".into(),
            source_date_epoch: 1_700_000_000,
        };
        let r: HashMap<String, String> = servicedirs(
            &services,
            Some(&rd),
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        )
        .into_iter()
        .map(|s| (s.name, s.run))
        .collect();

                                                                                                  
        assert_eq!(
            r["dha-creatine"],
            "#!/bin/sh\n\
             echo $$ > \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             grep -qx \"$$\" \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             exec s6-setuidgid 'dha' '/usr/bin/dha-creatine'\n"
        );
                                                                                            
        assert!(
            r["dha-orchestrator"].contains(
                "echo $$ > \"/sys/fs/cgroup/dha/work/orch/cgroup.procs\" || exit 1\n\
                 grep -qx \"$$\" \"/sys/fs/cgroup/dha/work/orch/cgroup.procs\" || exit 1\n"
            ),
            "{}",
            r["dha-orchestrator"]
        );
                                                                                    
        assert!(!r["dha-creatine"].contains("oom_score_adj"));
        assert!(!r["dha-orchestrator"].contains("oom_score_adj"));
                                                                                       
        assert!(!r["ntpd-ish"].contains("cgroup.procs"));
        assert!(r["ntpd-ish"].starts_with("#!/bin/sh\nexec "));
    }

    /// Hotswap v4 §3 (Task 4) — `EngineWeightsSetup::Runtime` renders the weights-verity-setup
    /// prelude on the ENGINE leaf ONLY: root, BETWEEN the cgroup placement and the uid-drop exec
    /// (the §4.3a precondition-then-exec pattern), fail-closed `|| exit 1` — a failure downs only
                                                                                                 
    /// The orchestrator + the OS services render byte-unchanged, and `None` (the dha boot-anchored
    /// box) is byte-identical to the pre-hotswap render (Task 7's regression invariant).
    #[test]
    fn runtime_weights_renders_the_engine_setup_prelude_only() {
        use fb_manifest::manifest::{
            ByteSize, EngineLeaf, Priv, ServiceShape, ServiceSpec, Uid, WorkSubtree,
        };
        let exec = |name: &str, binary: &str, uid: Option<&str>| ServiceSpec {
            name: name.into(),
            shape: ServiceShape::Exec {
                binary: binary.into(),
                argv: vec![],
                privilege: match uid {
                    Some(u) => Priv::Setuidgid {
                        user: u.into(),
                        envdir: None,
                    },
                    None => Priv::Root {},
                },
                restart_cap: None,
                env: None,
            },
        };
        let services = vec![
            exec("dha-creatine", "/usr/bin/dha-creatine", Some("dha")),
            exec("dha-orchestrator", "/usr/bin/dha-orchestrator", Some("dha")),
        ];
        let rd = ResourceDomain {
            name: "dha".into(),
            memory_max: ByteSize(8_000_000_000),
            delegate_uid: Uid(110),
            engine: Some(EngineLeaf {
                service: "dha-creatine".into(),
                memory_max: ByteSize(6_000_000_000),
                memory_min: None,
                oom_group: true,
            }),
            work: WorkSubtree {
                orchestrator: "dha-orchestrator".into(),
                orch_memory_min: None,
                job_memory_max: ByteSize(512_000_000),
                job_pids_max: Some(64),
                max_descendants: 16,
                max_depth: 2,
                work_pids_max: 1024,
            },
        };
        let ctx = PlaceholderCtx {
            domain: "box.example.org".into(),
            source_date_epoch: 1_700_000_000,
        };
        let render = |mode: EngineWeightsSetup| -> HashMap<String, String> {
            servicedirs(&services, Some(&rd), &ctx, &probe443(), mode)
                .into_iter()
                .map(|s| (s.name, s.run))
                .collect()
        };

        let runtime = render(EngineWeightsSetup::Runtime);
                                                                                                     
        assert_eq!(
            runtime["dha-creatine"],
            "#!/bin/sh\n\
             echo $$ > \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             grep -qx \"$$\" \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             /usr/bin/fb-weights setup || exit 1\n\
             exec s6-setuidgid 'dha' '/usr/bin/dha-creatine'\n"
        );
                                                                                       
        for (name, run) in &runtime {
            if name != "dha-creatine" {
                assert!(!run.contains("fb-weights"), "{name} must not setup weights");
            }
        }
                                                                                      
        let none = render(EngineWeightsSetup::None);
        assert_eq!(
            none["dha-creatine"],
            "#!/bin/sh\n\
             echo $$ > \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             grep -qx \"$$\" \"/sys/fs/cgroup/dha/creatine/cgroup.procs\" || exit 1\n\
             exec s6-setuidgid 'dha' '/usr/bin/dha-creatine'\n"
        );
    }

    /// I-3 (D-audit R1) — a complete NON-dha service run-script renders BYTE-EXACTLY (not just
                                                                                                     
    /// (no-resource_domain) path fails the build. blogd is the sample tenant's setuidgid longrun
    /// (s6-envdir + s6-setuidgid + binary, all single-quoted; NO cgroup placement prologue).
    #[test]
    fn a_non_dha_service_run_script_is_byte_exact() {
        let r = runs("box.example.org", 1_700_000_000);
        assert_eq!(
            r["blogd"],
            "#!/bin/sh\nexec s6-envdir '/etc/blogd/env' s6-setuidgid 'blogd' '/usr/bin/blogd'\n"
        );
    }

    /// D2 (§4.3b) — a service with a RestartCap emits an `s6-permafailon` finish; one without → None.
    #[test]
    fn restart_cap_renders_an_s6_permafailon_finish() {
        use fb_manifest::manifest::{
            DeathEvents, OnExhaust, Priv, RestartCap, ServiceShape, ServiceSpec,
        };
        let capped = ServiceSpec {
            name: "dha-creatine".into(),
            shape: ServiceShape::Exec {
                binary: "/usr/bin/dha-creatine".into(),
                argv: vec![],
                privilege: Priv::Setuidgid {
                    user: "dha".into(),
                    envdir: None,
                },
                restart_cap: Some(RestartCap {
                    max_restarts: 5,
                    window_secs: 3600,
                    events: DeathEvents {
                        on_signal: true,
                        on_nonzero_exit: true,
                    },
                    on_exhaust: OnExhaust::Down {},
                }),
                env: None,
            },
        };
        let uncapped = ServiceSpec {
            name: "ntpd".into(),
            shape: ServiceShape::Exec {
                binary: "/usr/sbin/ntpd".into(),
                argv: vec![],
                privilege: Priv::Root {},
                restart_cap: None,
                env: None,
            },
        };
                                                                                                      
        assert_eq!(
            render_finish(&capped.shape).as_deref(),
            Some("#!/bin/sh\nexec s6-permafailon 3600 5 1-255,SIGILL,SIGABRT,SIGBUS,SIGFPE,SIGKILL,SIGSEGV,SIGSYS true\n")
        );
        assert_eq!(render_finish(&uncapped.shape), None);
    }

    /// D2 — the `DeathEvents` → s6-permafailon `events` mapping (dha-confirmed): non-zero exits `1-255`;
    /// the crash signals INCL. `SIGKILL` (OOM); operator-control signals EXCLUDED.
    #[test]
    fn death_events_render_the_confirmed_event_list() {
        use fb_manifest::manifest::DeathEvents;
        let both = DeathEvents {
            on_signal: true,
            on_nonzero_exit: true,
        };
        assert_eq!(
            render_death_events(&both),
            "1-255,SIGILL,SIGABRT,SIGBUS,SIGFPE,SIGKILL,SIGSEGV,SIGSYS"
        );
        assert_eq!(
            render_death_events(&DeathEvents {
                on_signal: false,
                on_nonzero_exit: true
            }),
            "1-255"
        );
        assert_eq!(
            render_death_events(&DeathEvents {
                on_signal: true,
                on_nonzero_exit: false
            }),
            "SIGILL,SIGABRT,SIGBUS,SIGFPE,SIGKILL,SIGSEGV,SIGSYS"
        );
                                                                                                            
        assert!(render_death_events(&both).contains("SIGKILL"));
        for op in ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"] {
            assert!(
                !render_death_events(&both).contains(op),
                "{op} must be excluded"
            );
        }
    }

    /// D2 — `OnExhaust::Rescue` is rejected FAIL-CLOSED at the bake (v1 = `Down` only); `Down` is accepted.
    #[test]
    fn rescue_on_exhaust_is_rejected_down_is_accepted() {
        use fb_manifest::manifest::{
            DeathEvents, OnExhaust, Priv, RestartCap, ServiceShape, ServiceSpec,
        };
        let svc = |on_exhaust: OnExhaust| ServiceSpec {
            name: "dha-creatine".into(),
            shape: ServiceShape::Exec {
                binary: "/usr/bin/dha-creatine".into(),
                argv: vec![],
                privilege: Priv::Setuidgid {
                    user: "dha".into(),
                    envdir: None,
                },
                restart_cap: Some(RestartCap {
                    max_restarts: 5,
                    window_secs: 3600,
                    events: DeathEvents {
                        on_signal: true,
                        on_nonzero_exit: true,
                    },
                    on_exhaust,
                }),
                env: None,
            },
        };
        assert!(reject_unsupported_restart_caps(&[svc(OnExhaust::Down {})]).is_ok());
        assert!(reject_unsupported_restart_caps(&[svc(OnExhaust::Rescue {})]).is_err());
        assert!(reject_unsupported_restart_caps(&[]).is_ok());                          
    }

                                                                                          
    /// inherently-root / read-all services do NOT.
    #[test]
    fn privilege_drops_match_the_threat_boundary() {
        let r = runs("box.example.org", 1_700_000_000);
                                                                                                
                                                                                             
        assert!(r["blogd"].contains("s6-setuidgid 'blogd' '/usr/bin/blogd'"));
        assert!(r["blogd-worker"].contains("s6-setuidgid 'blogd'"));
                                                  
        assert!(
            !r["dropbear"].contains("s6-setuidgid"),
            "dropbear stays root (SSH auth)"
        );
        assert!(
            !r["ntpd"].contains("s6-setuidgid"),
            "ntpd stays root (sets the clock)"
        );
        assert!(
            !r["fb-backup"].contains("s6-setuidgid"),
            "backup stays root (reads all /persist)"
        );
                                                                                                     
        assert!(!r["haproxy"].contains("s6-setuidgid"));
    }

    /// The rescue dropbear must NOT carry `-R` and MUST carry the banner + the tmpfs host-key path +
    /// the hardening flags (spec L760-766).
    #[test]
    fn rescue_dropbear_flags_are_correct() {
        let r = runs("box.example.org", 1_700_000_000);
        let run = &r["rescue-dropbear"];
        assert!(
            !run.contains(" -R"),
            "rescue dropbear must NOT auto-generate host keys"
        );
        assert!(
            run.contains("-b /etc/dropbear/rescue-banner"),
            "rescue banner required"
        );
        assert!(run.contains("/run/dropbear-rescue/dropbear_ed25519_host_key"));
        for flag in ["-s", "-G ssh", "-I 1800", "-K 300", "-T 3"] {
            assert!(run.contains(flag), "rescue dropbear missing {flag}");
        }
    }

    /// A service argv with a `source_date_epoch` Placeholder bakes the build epoch into the run-script,
    /// and a setuidgid service reads its env via `s6-envdir`. (The recipes fb-acme-renew `--min-epoch`
    /// clock-floor render is sealed by the boot-gate; this proves the same placeholder/envdir mechanism.)
    #[test]
    fn a_placeholder_epoch_and_envdir_bake_into_the_run_script() {
        let r = runs("box.example.org", 1_700_123_456);
                                                                                                     
                                                                                     
        assert!(r["blogd-worker"].contains("'--since' 1700123456"));
                                                                                                     
        assert!(
            r["blogd-worker"].contains("s6-envdir '/etc/blogd/env'"),
            "a setuidgid service must read the env via s6-envdir"
        );
        assert!(r["blogd"].contains("s6-envdir '/etc/blogd/env'"));
    }

    /// No longrun run script writes an `authorized_keys` file (no bypass write channel — the sole
    /// source is the operator-staged key via the rootfs symlink). The rescue tmpfs shadow is a
    /// box-init oneshot (`rescue-keys-stage`), not a longrun.
    #[test]
    fn no_longrun_writes_authorized_keys() {
        let ctx = PlaceholderCtx {
            domain: "box.example.org".to_string(),
            source_date_epoch: 1_700_000_000,
        };
        for sd in servicedirs(
            &sample_services(),
            None,
            &ctx,
            &probe443(),
            EngineWeightsSetup::None,
        ) {
            assert!(
                !sd.run.contains("authorized_keys"),
                "{} run must not touch authorized_keys",
                sd.name
            );
        }
    }

                                                                                                  
    /// marker BEFORE `s6-svscanctl -t` (orderly stop, not a mid-supervision reboot); finish has no
    /// `set -e`, guards the umount, and ends in a never-returning action.
    #[test]
    fn svscan_handlers_are_correct() {
        let h: HashMap<&str, String> = svscan_handlers()
            .into_iter()
            .map(|x| (x.name, x.body))
            .collect();
        assert_eq!(h.len(), 4);
        for (sig, verb) in [
            ("SIGTERM", "reboot"),
            ("SIGUSR1", "halt"),
            ("SIGUSR2", "poweroff"),
        ] {
            let b = &h[sig];
            let marker = b.find("shutdown-action").expect("writes the marker");
            let ctl = b
                .find("s6-svscanctl -t")
                .expect("triggers the orderly stop");
            assert!(
                marker < ctl,
                "{sig} must write the marker before s6-svscanctl -t"
            );
            assert!(
                b.contains(&format!("echo {verb}")),
                "{sig} records '{verb}'"
            );
        }
        let finish = &h["finish"];
        assert!(
            !finish.contains("set -e"),
            "finish must tolerate a failed umount"
        );
        assert!(
            finish.contains("mountpoint -q /persist && umount /persist"),
            "guarded umount"
        );
        assert!(
            finish.trim_end().ends_with("esac"),
            "finish ends in the action case (never returns)"
        );
        for f in ["reboot -f", "halt -f", "poweroff -f"] {
            assert!(finish.contains(f), "finish must handle {f}");
        }
    }

    /// The firewall is default-drop with exactly the three public ports + loopback (spec L1043).
    #[test]
    fn nftables_is_default_drop_with_the_three_ports() {
        let nft = nftables_config(&ref_nft(), NetMode::Static);
        assert!(
            nft.contains("policy drop;"),
            "input chain must default-drop"
        );
        assert!(nft.contains("iif \"lo\" accept"));
        assert!(nft.contains("ct state established,related accept"));
        for port in [
            "tcp dport 22 accept",
            "tcp dport 80 accept",
            "tcp dport 443 accept",
        ] {
            assert!(nft.contains(port), "missing {port}");
        }
    }

                                                                                                       
    /// over-permissive addition (e.g. a stray `tcp dport 25 accept` opening SMTP exfil) — this pins the
    /// EXACT output for BOTH modes, so any rule add/remove/reorder on this load-bearing control fails the
    /// build. OUTPUT is default-drop with the box's fixed egress (DNS/NTP/ACME+OCSP) + replies
    /// (established,related) + loopback (R1-8); the Dhcp arm appends the broadcast lease rules (seam 4).
    #[test]
    fn nftables_config_is_byte_identical_golden() {
        let expected_static = r#"#!/usr/sbin/nft -f
# /etc/nftables.conf — generated statically by recipes-image-builder (no operator-mutable firewall).
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport 443 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oif "lo" accept
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        tcp dport 443 accept
        tcp dport 80 accept
    }
}
"#;
        assert_eq!(
            nftables_config(&ref_nft(), NetMode::Static),
            expected_static
        );

        let expected_dhcp = r#"#!/usr/sbin/nft -f
# /etc/nftables.conf — generated statically by recipes-image-builder (no operator-mutable firewall).
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport 443 accept
        udp sport 67 dport 68 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oif "lo" accept
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        tcp dport 443 accept
        tcp dport 80 accept
        udp dport 67 accept
    }
}
"#;
        assert_eq!(nftables_config(&ref_nft(), NetMode::Dhcp), expected_dhcp);
    }

    /// The box env points the app at /persist + loopback, and PUBLIC_URL templates the box domain.
    #[test]
    fn box_env_targets_persist_and_loopback() {
        let env: HashMap<String, String> = box_env(
            &sample_env_spec(),
            &PlaceholderCtx {
                domain: "box.example.org".into(),
                source_date_epoch: 0,
            },
        )
        .into_iter()
        .collect();
        assert_eq!(env["STATE_DIR"], "/persist/blogd");
        assert_eq!(env["LISTEN_ADDR"], "127.0.0.1");
        assert_eq!(env["PUBLIC_URL"], "https://box.example.org");
    }

    /// The emitter writes the 0755 signed `run` scripts + the `.s6-svscan` handler scripts, and NO
    /// `supervise`/`event` on the rootfs — box-init's live tmpfs servicedir holds those and
                                                                                  
    #[test]
    fn write_servicedir_tree_emits_signed_runs_and_handlers() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        write_servicedir_tree(
            tmp.path(),
            "box.example.org",
            1_700_000_000,
            &crate::config::sample_manifest(),
            EngineWeightsSetup::None,
        )
        .unwrap();
        let box_svc = tmp.path().join("etc/box-svc");
                                                                                                       
                                                                                                    
        let app = box_svc.join("blogd");
        assert!(app.join("run").is_file());
        assert_eq!(
            std::fs::metadata(app.join("run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!app.join("supervise").is_symlink() && !app.join("supervise").exists());
        assert!(!app.join("event").is_symlink() && !app.join("event").exists());
                       
        for h in ["finish", "SIGTERM", "SIGUSR1", "SIGUSR2"] {
            let p = box_svc.join(".s6-svscan").join(h);
            assert!(p.is_file(), "{h} handler emitted");
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}
