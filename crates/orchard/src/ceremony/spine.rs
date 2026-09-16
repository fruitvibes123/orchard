                                                                                       
//! code-resident DATA. Every datum a contract clause consumes is a declared field here; C2
//! (guide), C3 (run) and C7 (derived surfaces) consume this table and never restate step
//! knowledge. Per-step facts follow plan-inputs §Step-data, re-anchored at the cut
                                                                                  
//!
//! Interface notes vs the plan sketch (recorded in the dev log): `compose` returns a LIST of
//! [`Invocation`]s (S6 re-pins one artifact per `market upgrade` invocation — the tool has no
//! whole-repo target — and S1/S8 invoke external programs (docker/make), so a single
//! `Vec<String>` argv cannot carry a step); `Step` gains `verb: Option<VerbId>` binding a step
//! to its clap surface for the composition self-tests.

use super::classify::VerbId;
use super::param::{
    DefaultWithSource, Derivation, DerivationInputs, ParamClass, ParamRecord, ParamValues,
};
use super::probes::{DoneProbe, DoneResult, Probe, ProbeCtx, ProbeResult, SubjectOrigin};
use super::records::RunRecords;

/// The 11 ceremony steps (spec §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StepId {
    S1BuildContainer,
    S2OperatorKeys,
    S3Prime,
    S4StoreVendor,
    S5TenantPublish,
    S6TenantRepin,
    S7ImageBuild,
    S8BootGate,
    S9BoxPreflight,
    S10ProdInstall,
    S11PostBoot,
}

impl StepId {
                                                                                                 
    /// new step is a compile error here rather than an unrecorded step. The tokens are part of
    /// the on-disk record format: renaming one orphans every existing record, so they never
    /// change once written.
    pub fn token(self) -> &'static str {
        match self {
            StepId::S1BuildContainer => "s1-build-container",
            StepId::S2OperatorKeys => "s2-operator-keys",
            StepId::S3Prime => "s3-prime",
            StepId::S4StoreVendor => "s4-store-vendor",
            StepId::S5TenantPublish => "s5-tenant-publish",
            StepId::S6TenantRepin => "s6-tenant-repin",
            StepId::S7ImageBuild => "s7-image-build",
            StepId::S8BootGate => "s8-boot-gate",
            StepId::S9BoxPreflight => "s9-box-preflight",
            StepId::S10ProdInstall => "s10-prod-install",
            StepId::S11PostBoot => "s11-post-boot",
        }
    }
}

                                                                                         
/// non-observable-by-another-invocation; `Record` IS observed by a later run's done-probes and
/// classifies WRITING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteClass {
    None,
    RunLocal,
    Record,
    HostShared,
    RepoTree,
    Store,
    TargetBox,
}

impl WriteClass {
                                                           
    pub fn observable(self) -> bool {
        !matches!(self, WriteClass::None | WriteClass::RunLocal)
    }
}

                                                                                         
/// branches on this). A sibling is a SYMBOLIC name resolved against context/profile at
/// admission, so a `'static` spine row composes with the runtime root at resolution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutRef {
    Executing,
    Sibling(SiblingId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingId {
    /// The tenant repo (resolved via the repo-manifest's owner entry, e.g. `recipes`).
    TenantRepo,
}

impl SiblingId {
    /// The checkout-id token naming this sibling's declared-space file (§1.1).
    pub fn token(self) -> &'static str {
        match self {
            SiblingId::TenantRepo => "tenant-repo",
        }
    }
}

                                                                              
/// pathspec is the descriptive token of what is written (a docker tag, a /tmp tree, a store).
#[derive(Debug, Clone, Copy)]
pub struct WriteDecl {
    pub class: WriteClass,
    pub checkout: CheckoutRef,
    pub pathspec: &'static str,
}

/// Who executes the step (spec §3): `Internal` = the runner composes and spawns it;
/// `InternalWhere` = internal iff the named precondition set holds, else the operator runs the
/// checklist; `ExternalChecklist` = always the operator's own action, probe-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorClass {
    Internal,
    InternalWhere(PreconditionSetId),
    ExternalChecklist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionSetId {
    /// S8: the gate composition's FULL precondition set (docker + /dev/kvm +
    /// `RECIPES_{DRYRUN,PROD,RESCUE}_IMG` (+privkeys) + the restore/e2e extras where composed;
                                             
    S8GateComposition,
}

/// The commit-gate model per step (D15: verb-owned or spine-supplied; R6 I-3 made it a field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateClass {
    None,
    /// The underlying verb owns its consent gate (market upgrade's y/e/N + `--commit`).
    VerbOwned,
                                                                                     
    SpineSupplied,
}

                           
#[derive(Debug, Clone, Copy)]
pub struct InputIdentity {
    pub id: &'static str,
    pub explain: &'static str,
}

/// What a composed step invocation runs (see the module note: S1/S8 run external programs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// A child invocation of the orchard binary itself (D13: every verb-owned gate executes
    /// exactly as the verb defines it).
    SelfExe,
                                                                              
    External(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub program: Program,
    pub args: Vec<String>,
}

                                                                        
pub struct Step {
    pub id: StepId,
    pub title: &'static str,
    pub explain: &'static str,
    pub params: &'static [ParamRecord],
    pub input_identities: &'static [InputIdentity],
    pub preconditions: &'static [Probe],
                                                                                          
    /// mechanism cannot see. The general mechanism is the step record's `produced` set, which
    /// `ceremony::admission::step_done` re-checks (path present + recorded hash) for every step;
    /// this field covers products that are not recorded files — S1's docker image TAG, S3's
    /// staged tarballs. `None` = the records decide alone. There is no vacuously-`Done` body:
    /// the absence of a probe is the `None`.
    pub artifact_present: Option<DoneProbe>,
    pub compose: fn(&ParamValues) -> Vec<Invocation>,
    /// The child ENV additions this step composes, the env analogue of `compose`. A
    /// mandatory field, so a new step must decide its child env. S8 supplies the gate legs' image
    /// and privkey env; every other step composes none (`no_env`).
    pub compose_env: fn(&RunRecords, &ParamValues) -> Vec<(String, String)>,
    pub produces: &'static str,
    pub writes: &'static [WriteDecl],
    pub gate: GateClass,
    pub executor: ExecutorClass,
    /// The clap surface this step's SelfExe invocations target (composition self-tests); None
    /// for external-program and probe-only steps.
    pub verb: Option<VerbId>,
    /// Does this step's underlying verb refuse a dirty executing checkout? True exactly for the
    /// verbs that carry an `--allow-dirty` escape hatch — the GuardDisabling flag the ceremony
                                                                                                   
    /// immediately before the FIRST such step, so the steps that dirty the tree have run and the
    /// step that needs it clean has not. Checked against the flag classification by
    /// `ceremony_selftests::clean_tree_steps_are_exactly_the_allow_dirty_verbs`.
    pub requires_clean_tree: bool,
}

impl Step {
                                                                                                 
                                                                                                   
    /// requirement both quantify over this set.
    pub fn destructive(&self) -> bool {
        self.writes.iter().any(|w| w.class == WriteClass::TargetBox)
    }

                                                              
    pub fn sibling_writes(&self) -> impl Iterator<Item = (SiblingId, &'static str)> {
        self.writes.iter().filter_map(|w| match w.checkout {
            CheckoutRef::Sibling(id) if w.class == WriteClass::RepoTree => Some((id, w.pathspec)),
            _ => None,
        })
    }

    /// The step's declared EXECUTING-checkout repo-tree writes.
    pub fn executing_repo_writes(&self) -> impl Iterator<Item = &'static str> {
        self.writes.iter().filter_map(|w| {
            (w.class == WriteClass::RepoTree && w.checkout == CheckoutRef::Executing)
                .then_some(w.pathspec)
        })
    }

                                                
    pub fn judgment_params(&self) -> impl Iterator<Item = &'static ParamRecord> {
        self.params
            .iter()
            .filter(|p| p.class == ParamClass::Judgment)
    }
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Step").field("id", &self.id).finish()
    }
}

                                                                                                   

use super::param::{
    argv_positional_safe, probe_argv_positional, probe_creatable_dir, probe_existing_file,
    probe_firmware, probe_key_file, probe_net, probe_non_empty, probe_out_dir, probe_u64,
};

const P_CONTAINER_IMAGE: ParamRecord = ParamRecord {
    name: "container_image",
    explain: "the pinned build-container tag every containerized step runs in",
    default: DefaultWithSource::Builtin("recipes-imgbuild:dev"),
                                                                                                  
    probe: probe_argv_positional,
    class: ParamClass::Identity,
};
const P_KEYS_DIR: ParamRecord = ParamRecord {
    name: "keys_dir",
    explain: "the operator key-set directory (created by S2 when absent)",
    default: DefaultWithSource::Builtin("<XDG config>/recipes-deploy/keys"),
    probe: probe_creatable_dir,
    class: ParamClass::Identity,
};
const P_TENANT_SOURCE_REF: ParamRecord = ParamRecord {
    name: "tenant_source_ref",
    explain: "the tenant source ref (commit) the publish was built from — the S5 input identity",
    default: DefaultWithSource::Required,
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
pub const CEREMONY_TENANT_REPO: &str = "recipes";

const P_TENANT_REPO: ParamRecord = ParamRecord {
    name: "tenant_repo",
    explain: "the tenant repo name in the repo-manifest whose artifacts S6 re-pins",
    default: DefaultWithSource::Builtin(CEREMONY_TENANT_REPO),
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
const P_TENANT_ARTIFACTS: ParamRecord = ParamRecord {
    name: "tenant_artifacts",
    explain: "the tenant's published artifacts to re-pin, as kind:key pairs (comma-joined)",
                                                                                                    
                                                                                                     
                                                                                                    
                                                                                                  
                                                       
    default: DefaultWithSource::Required,
    probe: probe_tenant_artifacts,
    class: ParamClass::Identity,
};
const P_DOMAIN: ParamRecord = ParamRecord {
    name: "domain",
    explain: "the deployment domain baked into the image (haproxy cert path + ACME)",
    default: DefaultWithSource::Required,
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
const P_NET: ParamRecord = ParamRecord {
    name: "net",
    explain: "the box network config baked as fb.net= (one whitespace-free token)",
    default: DefaultWithSource::Required,
    probe: probe_net,
    class: ParamClass::Identity,
};
const P_FIRMWARE: ParamRecord = ParamRecord {
    name: "firmware",
    explain: "the boot firmware target (v1: seabios | seabios-gpt; uefi routes to the USB ceremony)",
    default: DefaultWithSource::Builtin("seabios"),
    probe: probe_firmware,
    class: ParamClass::Identity,
};
const P_IMAGE_VERSION: ParamRecord = ParamRecord {
    name: "image_version",
    explain: "the per-stream monotonic image serial (the box's anti-rollback floor input)",
    default: DefaultWithSource::Builtin("0"),
    probe: probe_u64,
    class: ParamClass::Judgment,
};
const P_OUT_DIR: ParamRecord = ParamRecord {
    name: "out_dir",
    explain: "where the image triple lands (never under the repo root)",
    default: DefaultWithSource::Builtin(crate::deploy::build_image::DEFAULT_OUT_DIR),
    probe: probe_out_dir,
    class: ParamClass::Identity,
};
const P_OPERATOR_PUBKEY: ParamRecord = ParamRecord {
    name: "operator_pubkey",
    explain: "the operator's everyday box-login pubkey (baked into the persist skeleton)",
    default: DefaultWithSource::Required,
    probe: probe_key_file,
    class: ParamClass::Identity,
};
const P_RECOVERY_PUBKEY: ParamRecord = ParamRecord {
    name: "recovery_pubkey",
    explain: "the rescue dropbear's sole authorized pubkey (in-rootfs)",
    default: DefaultWithSource::Required,
    probe: probe_key_file,
    class: ParamClass::Identity,
};
const P_MANIFEST: ParamRecord = ParamRecord {
    name: "manifest",
    explain: "an operator service manifest (absent = the pinned reference tenant)",
    default: DefaultWithSource::Builtin("(pinned reference tenant)"),
    probe: probe_existing_file,
    class: ParamClass::Identity,
};
const P_DHA_WEIGHTS: ParamRecord = ParamRecord {
    name: "dha_weights_gguf",
    explain: "the dha weights GGUF",
    default: DefaultWithSource::Builtin("(absent — a non-dha build)"),
    probe: probe_existing_file,
    class: ParamClass::Identity,
};
                                                                                             
                                                                                                
/// would recurse. Every consumer reads this const — the interview default, S8's composer fallback,
/// S10's precondition fallback, the post-build hint — so no two drift onto a divergent literal, and
/// the value is never the unsatisfiable `boot-gate` (emits no record, `composition_of` is Err).
pub const CEREMONY_GATE_TARGET: &str = "boot-gate-ceremony-legs";

const P_GATE_TARGET: ParamRecord = ParamRecord {
    name: "gate_target",
    explain: "the make target whose leg composition is this ceremony's S8 gate",
    default: DefaultWithSource::Builtin(CEREMONY_GATE_TARGET),
                                                                                                
                                                                              
    probe: probe_argv_positional,
    class: ParamClass::Identity,
};
const P_IP: ParamRecord = ParamRecord {
    name: "ip",
    explain: "the target box (IP or lowercase hostname); confirmed every run",
    default: DefaultWithSource::Required,
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
const P_PORT: ParamRecord = ParamRecord {
    name: "port",
    explain: "the target sshd port (both legs ride it)",
    default: DefaultWithSource::Builtin("22"),
    probe: probe_u64,
    class: ParamClass::Identity,
};
const P_PROVISIONING_USER: ParamRecord = ParamRecord {
    name: "provisioning_user",
    explain: "the PRE-KEXEC login user; the ceremony sudos the privileged steps as it",
    default: DefaultWithSource::Builtin(crate::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER),
                                                                                          
    probe: probe_argv_positional,
    class: ParamClass::Identity,
};
const P_SSH_IDENTITY: ParamRecord = ParamRecord {
    name: "ssh_identity",
    explain: "the provisioning-leg ssh PRIVATE key path (the cloud-injected key)",
    default: DefaultWithSource::Required,
    probe: probe_key_file,
    class: ParamClass::Identity,
};
const P_HOST_FINGERPRINT: ParamRecord = ParamRecord {
    name: "host_fingerprint",
    explain: "the provisioning host key fingerprint pin (Leg A)",
    default: DefaultWithSource::Required,
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
const P_RUNTIME_HOSTKEY_FINGERPRINT: ParamRecord = ParamRecord {
    name: "runtime_hostkey_fingerprint",
    explain: "the installed box's runtime host key pin (Leg B); prod aborts before the wipe if it \
              does not match the fingerprint derived from the image",
    default: DefaultWithSource::Builtin("(absent — verified against the image at install)"),
    probe: probe_non_empty,
    class: ParamClass::Identity,
};
const P_BOX_LOGIN_IDENTITY: ParamRecord = ParamRecord {
    name: "box_login_identity",
    explain: "the reconnect-leg ssh PRIVATE key path (default: operator pubkey minus .pub)",
    default: DefaultWithSource::Derived(
        "operator_pubkey minus its .pub suffix",
        Derivation {
            reads: &["operator_pubkey"],
            f: derive_box_login_identity,
        },
    ),
    probe: probe_key_file,
    class: ParamClass::Identity,
};

/// FAC-GC-3 producer for `box_login_identity`: the declared `operator_pubkey` path minus its
/// `.pub` suffix. Backs the `Derived` default's promise with code, so the interview never shows a
/// derivation that does not happen.
fn derive_box_login_identity(inp: &DerivationInputs) -> Option<String> {
    let pubkey = inp.value("operator_pubkey")?;
    Some(pubkey.strip_suffix(".pub").unwrap_or(pubkey).to_string())
}

fn probe_tenant_artifacts(_ctx: &ProbeCtx, value: &str) -> ProbeResult {
    for pair in value.split(',') {
        match pair.split_once(':') {
            Some((k, name)) if !name.is_empty() => match k {
                "source" | "binary" | "config" => {}
                other => {
                    return ProbeResult::Unmet(format!(
                        "artifact kind {other:?} is not one of source|binary|config"
                    ));
                }
            },
            _ => {
                return ProbeResult::Unmet(format!(
                    "{pair:?} is not a kind:key pair (e.g. binary:recipes-app)"
                ));
            }
        }
    }
    ProbeResult::Met
}

                                                                                                   

const PR_CONTAINER_PRESENT: Probe = Probe {
    id: "build-container-present",
    explain: "the pinned build container image exists on this host",
    subject: SubjectOrigin::StepProduct(StepId::S1BuildContainer),
                                                                                                   
                                                                                                  
                                                                      
    run: |ctx| {
                                                                                                
                                                                                                
                                                                                 
        let tag = ctx
            .value("container_image")
            .map(str::to_string)
            .or_else(|| ctx.profile().and_then(|p| p.container_image.clone()))
            .unwrap_or_else(|| "recipes-imgbuild:dev".to_string());
                                                                                              
                                                                              
        if !argv_positional_safe(&tag) {
            return ProbeResult::Unmet(format!(
                "container tag {tag:?} is not a safe image ref"
            ));
        }
        match std::process::Command::new("docker")
            .args(["image", "inspect", "--", &tag])
            .output()
        {
            Ok(o) if o.status.success() => ProbeResult::Met,
            Ok(_) => ProbeResult::Unmet(format!(
                "the pinned build container {tag} is absent — run S1 (docker build … \
                 crates/image-builder)"
            )),
            Err(e) => ProbeResult::Unevaluable(format!("docker not invokable: {e}")),
        }
    },
};

const PR_PRIMED_SOURCES: Probe = Probe {
    id: "primed-sources-staged",
    explain: "the pinned kernel + syslinux tarballs are staged under /tmp",
    subject: SubjectOrigin::StepProduct(StepId::S3Prime),
    run: |ctx| {
        let (k, s) = (
            crate::deploy::build_image::default_kernel_xz(ctx.repo_root()),
            crate::deploy::build_image::default_syslinux_src(ctx.repo_root()),
        );
        match (k, s) {
            (Ok(k), Ok(s)) if k.is_file() && s.is_file() => ProbeResult::Met,
            (Ok(_), Ok(_)) => {
                ProbeResult::Unmet("staged sources missing — run S3 (orchard prime)".into())
            }
            (Err(e), _) | (_, Err(e)) => {
                ProbeResult::Unevaluable(format!("cannot resolve pinned source names: {e}"))
            }
        }
    },
};

const PR_STORE_PRESENT: Probe = Probe {
    id: "artifact-store-present",
    explain: "the resolved artifact store exists",
    subject: SubjectOrigin::CeremonyImmutable,
    run: |ctx| {
        if ctx.artifact_store().is_dir() {
            ProbeResult::Met
        } else {
            ProbeResult::Unmet(format!(
                "artifact store {} is not a directory — populate it (tenant publish / grocer) or \
                 point the context at the real store",
                ctx.artifact_store().display()
            ))
        }
    },
};

const PR_HANDOFF_TREE: Probe = Probe {
    id: "tenant-handoff-tree",
    explain: "the tenant publish handoff tree exists and matches the publish layout",
    subject: SubjectOrigin::StepProduct(StepId::S5TenantPublish),
                                                                                               
                                                                                              
                                                                                                  
                          
    run: |_ctx| super::handoff::shape(std::path::Path::new(HANDOFF_ROOT)),
};

/// The tenant publish handoff tree (`recipes/build-only.sh`'s default). One home; a `&str`
/// because `Path::new` is not const, and a pointer cast to fake one would be unsafe code for a
/// string literal.
pub const HANDOFF_ROOT: &str = "/tmp/recipes-build-handoff";

const PR_SSH_PREFLIGHT: Probe = Probe {
    id: "target-ssh-preflight",
    explain: "the target is reachable as the cloud user with passwordless sudo (pre-kexec leg)",
    subject: SubjectOrigin::StepProduct(StepId::S9BoxPreflight),
                                                                                              
                                                                                               
                                                                                             
                                                   
    run: |ctx| match ctx.value("ip") {
        Some(target) => {
                                                                                                    
                                                                     
            let user = ctx
                .value("provisioning_user")
                .unwrap_or(crate::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER);
            let port = ctx.value("port");
            let identity = ctx.value("ssh_identity");
            if ctx.network_seamed() {
                ProbeResult::Unevaluable("network seamed".into())
            } else {
                super::preflight::probe(user, target, port, identity)
            }
        }
        None => ProbeResult::Unevaluable(
            "no target resolved for the preflight probe — the runner attaches the parameter set"
                .into(),
        ),
    },
};

const PR_GATE_RECORD: Probe = Probe {
    id: "gate-record-present",
    explain: "S10 requires the gate-run-emitted record binding the staged set",
    subject: SubjectOrigin::StepProduct(StepId::S8BootGate),
                                                                                              
                                                                                                 
                                                                                        
                                                                                        
    run: |ctx| {
        super::gate_record::s10_precondition(
            ctx.staged_image(),
            ctx.records_dir(),
            ctx.repo_root(),
            ctx.value("gate_target").unwrap_or(CEREMONY_GATE_TARGET),
        )
    },
};

                                                                                                   

                                                                                               
                                                                                  
                                                                                                 
                                                                              

const DONE_S1: DoneProbe = DoneProbe {
    id: "done-build-container",
                                                                                              
                                                                                  
    run: |_ctx, values| {
        let tag = s1_container_tag(values);
                                                                                                   
        if !argv_positional_safe(&tag) {
            return DoneResult::NotDone(format!("container tag {tag:?} is not a safe image ref"));
        }
        match std::process::Command::new("docker")
            .args(["image", "inspect", "--", &tag])
            .output()
        {
            Ok(o) if o.status.success() => DoneResult::Done,
            Ok(_) => DoneResult::NotDone(format!("container image {tag} absent")),
            Err(e) => DoneResult::Unevaluable(format!("docker not invokable: {e}")),
        }
    },
};
const DONE_S3: DoneProbe = DoneProbe {
    id: "done-prime",
    run: |ctx, _values| match (
        crate::deploy::build_image::default_kernel_xz(ctx.repo_root()),
        crate::deploy::build_image::default_syslinux_src(ctx.repo_root()),
    ) {
        (Ok(k), Ok(s)) if k.is_file() && s.is_file() => DoneResult::Done,
        (Ok(_), Ok(_)) => DoneResult::NotDone("staged tarballs missing".into()),
        (Err(e), _) | (_, Err(e)) => DoneResult::Unevaluable(e.to_string()),
    },
};

                                                                                                   

fn flagged(values: &ParamValues, flag: &str, name: &str, args: &mut Vec<String>) {
    if let Some(v) = values.get(name) {
        args.push(format!("--{flag}"));
        args.push(v.to_string());
    }
}

/// S1's build container tag: the declared `container_image` parameter, else the builtin default
                                                                                            
/// declared parameter, so a ceremony declaring a different tag SKIPped S1 on a tag it did not
/// build).
fn s1_container_tag(values: &ParamValues) -> String {
    values
        .get("container_image")
        .unwrap_or("recipes-imgbuild:dev")
        .to_string()
}

/// The empty child-env composer: a step adds nothing to its children's environment.
fn no_env(_records: &RunRecords, _values: &ParamValues) -> Vec<(String, String)> {
    Vec::new()
}

fn compose_s1(values: &ParamValues) -> Vec<Invocation> {
    let tag = s1_container_tag(values);
    vec![Invocation {
        program: Program::External("docker"),
        args: vec![
            "build".into(),
            "-t".into(),
            tag,
            "-f".into(),
            "crates/image-builder/Containerfile".into(),
            "crates/image-builder".into(),
        ],
    }]
}

fn compose_s2(values: &ParamValues) -> Vec<Invocation> {
    let mut args = vec!["generate-keys".to_string()];
                                                                                         
                                                                               
    flagged(values, "output-dir", "keys_dir", &mut args);
    vec![Invocation {
        program: Program::SelfExe,
        args,
    }]
}

fn compose_s3(_values: &ParamValues) -> Vec<Invocation> {
    vec![Invocation {
        program: Program::SelfExe,
        args: vec![
            "prime".to_string(),
            "--kbuild-dir".to_string(),
            "/tmp/recipes-kbuild".to_string(),
            "--syslinux-dir".to_string(),
            "/tmp/recipes-syslinux".to_string(),
        ],
    }]
}

fn compose_s4(_values: &ParamValues) -> Vec<Invocation> {
    vec![Invocation {
        program: Program::SelfExe,
        args: vec!["vendor".to_string()],
    }]
}

fn compose_s5(_values: &ParamValues) -> Vec<Invocation> {
                                                                                            
    Vec::new()
}

                                                                                          
/// swaps in a variant that additionally composes the consent alias `--yes`; the
/// forbidden-composition arm must redden under it.
#[cfg(not(feature = "ceremony-seed-compose-yes"))]
fn compose_s6_entry(values: &ParamValues) -> Vec<Invocation> {
    compose_s6(values)
}
#[cfg(feature = "ceremony-seed-compose-yes")]
fn compose_s6_entry(values: &ParamValues) -> Vec<Invocation> {
    let mut v = compose_s6(values);
    for inv in &mut v {
        inv.args.push("--yes".to_string());
    }
    v
}

/// The artifact kinds S6 may compose into a `market upgrade --<kind>` flag. The kind is the FLAG
                                                                                                
/// would otherwise compose `market upgrade --rust 1.99`, the whole-toolchain re-pin the operator
                                                                                            
/// three kinds map to a flag; anything else composes NOTHING (the invalid value is caught
                                                                
const S6_ARTIFACT_KINDS: &[&str] = &["source", "binary", "config"];

fn compose_s6(values: &ParamValues) -> Vec<Invocation> {
                                                                                         
                                                                        
    let Some(artifacts) = values.get("tenant_artifacts") else {
        return Vec::new();
    };
    artifacts
        .split(',')
        .filter_map(|pair| pair.split_once(':'))
                                                                                         
        .filter(|(kind, _)| S6_ARTIFACT_KINDS.contains(kind))
        .map(|(kind, key)| Invocation {
            program: Program::SelfExe,
            args: vec![
                "market".to_string(),
                "upgrade".to_string(),
                format!("--{kind}"),
                key.to_string(),
            ],
        })
        .collect()
}

fn compose_s7(values: &ParamValues) -> Vec<Invocation> {
    let mut args = vec!["build".to_string()];
    flagged(values, "domain", "domain", &mut args);
    flagged(values, "net", "net", &mut args);
    flagged(values, "firmware", "firmware", &mut args);
    flagged(values, "image-version", "image_version", &mut args);
    flagged(values, "out-dir", "out_dir", &mut args);
    flagged(values, "keys-dir", "keys_dir", &mut args);
    flagged(values, "operator-pubkey", "operator_pubkey", &mut args);
    flagged(values, "recovery-pubkey", "recovery_pubkey", &mut args);
    flagged(values, "manifest", "manifest", &mut args);
    flagged(values, "container-image", "container_image", &mut args);
    flagged(values, "dha-weights-gguf", "dha_weights_gguf", &mut args);
    vec![Invocation {
        program: Program::SelfExe,
        args,
    }]
}

fn compose_s8(values: &ParamValues) -> Vec<Invocation> {
                                                                                            
                                                                                           
                                                                                                  
                                                                                                 
                                                                                                 
                                                                                                
    let raw = values.get("gate_target").unwrap_or(CEREMONY_GATE_TARGET);
    let target = if argv_positional_safe(raw) {
        raw.to_string()
    } else {
        CEREMONY_GATE_TARGET.to_string()
    };
    vec![Invocation {
        program: Program::External("make"),
        args: vec!["--".to_string(), target],
    }]
}

fn compose_s9(_values: &ParamValues) -> Vec<Invocation> {
                                                                                             
    Vec::new()
}

fn compose_s10(values: &ParamValues) -> Vec<Invocation> {
    let mut args = vec!["prod".to_string()];
    if let Some(ip) = values.get("ip") {
        args.push(ip.to_string());
    }
    flagged(values, "pubkey", "operator_pubkey", &mut args);
    flagged(values, "provisioning-user", "provisioning_user", &mut args);
    flagged(values, "ssh-identity", "ssh_identity", &mut args);
    flagged(
        values,
        "box-login-identity",
        "box_login_identity",
        &mut args,
    );
    flagged(values, "host-fingerprint", "host_fingerprint", &mut args);
    flagged(
        values,
        "runtime-hostkey-fingerprint",
        "runtime_hostkey_fingerprint",
        &mut args,
    );
    flagged(values, "port", "port", &mut args);
    flagged(values, "recovery-pubkey", "recovery_pubkey", &mut args);
    flagged(values, "keys-dir", "keys_dir", &mut args);
                                                                                               
                                                                                                   
                                   
    vec![Invocation {
        program: Program::SelfExe,
        args,
    }]
}

fn compose_s11(_values: &ParamValues) -> Vec<Invocation> {
                                                                                          
                                         
    Vec::new()
}

                                                                                                   

                               
pub static SPINE: [Step; 11] = [
    Step {
        id: StepId::S1BuildContainer,
        title: "build the pinned build container",
        explain: "docker-builds the pinned Alpine build container every containerized step runs in",
        params: &[P_CONTAINER_IMAGE],
        input_identities: &[InputIdentity {
            id: "containerfile",
            explain: "crates/image-builder/Containerfile at the ceremony checkout's HEAD",
        }],
        preconditions: &[],
        artifact_present: Some(DONE_S1),
        compose: compose_s1,
        compose_env: no_env,
        produces: "the host-global build container image tag (<container_image>)",
        writes: &[WriteDecl {
            class: WriteClass::HostShared,
            checkout: CheckoutRef::Executing,
                                                                                      
                                                                                                 
                                                       
            pathspec: "docker-image:<container_image>",
        }],
        gate: GateClass::None,
        executor: ExecutorClass::Internal,
        verb: None,
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S2OperatorKeys,
        title: "operator key bootstrap",
        explain: "generates the operator key set and commits the public fingerprint pins",
        params: &[P_KEYS_DIR],
        input_identities: &[],
        preconditions: &[],
        artifact_present: None,
        compose: compose_s2,
        compose_env: no_env,
        produces: "the 7-file key set + committed fingerprint pin(s)",
        writes: &[
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "<keys_dir>",
            },
            WriteDecl {
                class: WriteClass::RepoTree,
                checkout: CheckoutRef::Executing,
                pathspec: "crates/image-builder/pinned-cert-fingerprints.toml",
            },
                                                                                                  
                                                                                                    
                                                                                                  
                                                                                                 
                                            
        ],
        gate: GateClass::SpineSupplied,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::GenerateKeys),
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S3Prime,
        title: "prime the pinned sources",
        explain: "fetches + stages the sha256-pinned kernel and syslinux tarballs under /tmp",
        params: &[],
        input_identities: &[InputIdentity {
            id: "pins.toml",
            explain: "the kernel/syslinux versions + sha256 pins at the ceremony checkout's HEAD",
        }],
        preconditions: &[],
        artifact_present: Some(DONE_S3),
        compose: compose_s3,
        compose_env: no_env,
        produces: "staged kernel + syslinux source tarballs",
        writes: &[
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "/tmp/recipes-kbuild",
            },
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "/tmp/recipes-syslinux",
            },
        ],
        gate: GateClass::None,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::Prime),
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S4StoreVendor,
        title: "populate vendor/ from the store",
        explain: "re-vendors the pinned source drops from the artifact store (wholesale overwrite)",
        params: &[],
        input_identities: &[InputIdentity {
            id: "consume-pins.toml",
            explain: "the pinned source shas the vendor re-derive verifies against",
        }],
        preconditions: &[PR_STORE_PRESENT],
        artifact_present: None,
        compose: compose_s4,
        compose_env: no_env,
        produces: "the tracked vendor/ tree, store-verified",
        writes: &[
            WriteDecl {
                class: WriteClass::RepoTree,
                checkout: CheckoutRef::Executing,
                pathspec: "vendor/",
            },
            WriteDecl {
                class: WriteClass::Store,
                checkout: CheckoutRef::Executing,
                pathspec: "(artifact store)",
            },
        ],
        gate: GateClass::SpineSupplied,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::Vendor),
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S5TenantPublish,
        title: "tenant publish",
        explain: "the tenant repo's own `make publish` builds + hands off the pinned binaries",
        params: &[P_TENANT_SOURCE_REF],
        input_identities: &[
            InputIdentity {
                id: "tenant_source_ref",
                explain: "the operator-supplied tenant commit the publish was built from",
            },
            InputIdentity {
                id: "handoff-tree-hash",
                explain: "the content hash of the quiescent handoff tree (bound at probe-accept)",
            },
        ],
        preconditions: &[PR_HANDOFF_TREE],
        artifact_present: None,
        compose: compose_s5,
        compose_env: no_env,
        produces: "/tmp/recipes-build-handoff with the tenant's release binaries",
                                                                                          
                                                                                    
                                                                               
        writes: &[
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: HANDOFF_ROOT,
            },
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "/tmp/recipes-pub-target",
            },
        ],
        gate: GateClass::None,
        executor: ExecutorClass::ExternalChecklist,
        verb: None,
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S6TenantRepin,
        title: "tenant re-pin",
        explain: "re-pins the tenant's published artifacts into consume-pins via market upgrade",
        params: &[P_TENANT_REPO, P_TENANT_ARTIFACTS],
        input_identities: &[InputIdentity {
            id: "published-pins",
            explain: "the tenant's published-pins.toml shas the re-pin stages from",
        }],
        preconditions: &[PR_STORE_PRESENT],
        artifact_present: None,
        compose: compose_s6_entry,
        compose_env: no_env,
        produces: "consume-pins re-pinned to the tenant's publish; store revisions",
        writes: &[
            WriteDecl {
                class: WriteClass::RepoTree,
                checkout: CheckoutRef::Executing,
                pathspec: "consume-pins.toml",
            },
                                                                                        
            WriteDecl {
                class: WriteClass::RepoTree,
                checkout: CheckoutRef::Executing,
                pathspec: "vendor/",
            },
            WriteDecl {
                class: WriteClass::Store,
                checkout: CheckoutRef::Executing,
                pathspec: "(artifact store)",
            },
            WriteDecl {
                class: WriteClass::RepoTree,
                checkout: CheckoutRef::Sibling(SiblingId::TenantRepo),
                pathspec: "published-pins.toml",
            },
        ],
        gate: GateClass::VerbOwned,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::MarketUpgrade),
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S7ImageBuild,
        title: "image build",
        explain: "bakes the signed, byte-reproducible image triple from the pinned inputs",
        params: &[
            P_DOMAIN,
            P_NET,
            P_FIRMWARE,
            P_IMAGE_VERSION,
            P_OUT_DIR,
            P_KEYS_DIR,
            P_OPERATOR_PUBKEY,
            P_RECOVERY_PUBKEY,
            P_MANIFEST,
            P_CONTAINER_IMAGE,
            P_DHA_WEIGHTS,
        ],
        input_identities: &[
            InputIdentity {
                id: "ceremony-head",
                explain: "the ceremony checkout commit the image is built from",
            },
            InputIdentity {
                id: "consume-pins.toml",
                explain: "the pinned binary/config closure baked into the image",
            },
        ],
        preconditions: &[PR_CONTAINER_PRESENT, PR_PRIMED_SOURCES, PR_STORE_PRESENT],
        artifact_present: None,
        compose: compose_s7,
        compose_env: no_env,
        produces: "the image triple (.img + .layout.toml + .sha256) + provenance sidecar",
        writes: &[
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "<out_dir>",
            },
                                                                                             
            WriteDecl {
                class: WriteClass::HostShared,
                checkout: CheckoutRef::Executing,
                pathspec: "/tmp/recipes-kbuild",
            },
                                                                                            
                                                                                              
                                          
            WriteDecl {
                class: WriteClass::RunLocal,
                checkout: CheckoutRef::Executing,
                pathspec: "(build-time production tempdirs: config-virt, leaf-der, linux-virt staging)",
            },
                                                            
                                                                                                    
                                                                                                    
                                                                             
            WriteDecl {
                class: WriteClass::Record,
                checkout: CheckoutRef::Executing,
                pathspec: "<out_dir> (provenance sidecar, beside the image triple)",
            },
        ],
        gate: GateClass::None,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::Build),
        requires_clean_tree: true,
    },
    Step {
        id: StepId::S8BootGate,
        title: "produced-bytes gate",
        explain: "runs the declared boot-gate leg composition on the built image and emits the record",
        params: &[P_GATE_TARGET],
        input_identities: &[InputIdentity {
            id: "staged-set-hashes",
            explain: "the content hashes of the .img + vmlinuz + initramfs the gate booted",
        }],
        preconditions: &[],
        artifact_present: None,
        compose: compose_s8,
        compose_env: super::runner::s8_child_env,
        produces: "the gate-emitted pass record",
        writes: &[WriteDecl {
            class: WriteClass::Record,
            checkout: CheckoutRef::Executing,
            pathspec: "the gate record beside the built image (produced by S7)",
        }],
        gate: GateClass::None,
        executor: ExecutorClass::InternalWhere(PreconditionSetId::S8GateComposition),
        verb: None,
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S9BoxPreflight,
        title: "box preflight",
        explain: "a freshly-provisioned target, reachable as the cloud user with sudo",
        params: &[
            P_IP,
            P_PORT,
            P_PROVISIONING_USER,
            P_SSH_IDENTITY,
            P_HOST_FINGERPRINT,
        ],
        input_identities: &[],
        preconditions: &[PR_SSH_PREFLIGHT],
        artifact_present: None,
        compose: compose_s9,
        compose_env: no_env,
        produces: "a reachable, freshly-provisioned target",
        writes: &[],
        gate: GateClass::None,
        executor: ExecutorClass::ExternalChecklist,
        verb: None,
        requires_clean_tree: false,
    },
    Step {
        id: StepId::S10ProdInstall,
        title: "prod install",
        explain: "the kexec-takeover greenfield install onto the target's whole disk",
        params: &[
            P_IP,
            P_PORT,
            P_PROVISIONING_USER,
            P_SSH_IDENTITY,
            P_HOST_FINGERPRINT,
            P_RUNTIME_HOSTKEY_FINGERPRINT,
            P_BOX_LOGIN_IDENTITY,
            P_OPERATOR_PUBKEY,
            P_RECOVERY_PUBKEY,
            P_KEYS_DIR,
                                                                                                   
                                                                                         
                                                                                                    
                                                               
            P_GATE_TARGET,
        ],
        input_identities: &[InputIdentity {
            id: "staged-set-hashes",
            explain: "the exact artifact set staged to the target (bound by the S8 record)",
        }],
        preconditions: &[PR_GATE_RECORD],
        artifact_present: None,
        compose: compose_s10,
        compose_env: no_env,
        produces: "the installed box, crypto-identity verified",
        writes: &[
            WriteDecl {
                class: WriteClass::TargetBox,
                checkout: CheckoutRef::Executing,
                pathspec: "(target whole disk)",
            },
                                                                                               
                                                                            
            WriteDecl {
                class: WriteClass::TargetBox,
                checkout: CheckoutRef::Executing,
                pathspec: "(target staging dir; prod --image-stage-dir)",
            },
                                                                                                 
                                                                                
            WriteDecl {
                class: WriteClass::RunLocal,
                checkout: CheckoutRef::Executing,
                pathspec: "(ephemeral per-invocation known_hosts)",
            },
        ],
        gate: GateClass::None,
        executor: ExecutorClass::Internal,
        verb: Some(VerbId::Prod),
        requires_clean_tree: true,
    },
    Step {
        id: StepId::S11PostBoot,
        title: "post-boot verify",
        explain: "confirms the box serves; tenant-supplied checks are the operator's follow-up",
        params: &[],
        input_identities: &[],
        preconditions: &[],
        artifact_present: None,
        compose: compose_s11,
        compose_env: no_env,
        produces: "a serving box, confirmed",
        writes: &[],
        gate: GateClass::None,
        executor: ExecutorClass::Internal,
        verb: None,
        requires_clean_tree: false,
    },
];

                                                                                        
/// enumerated by the compiler-forced `VerbId::all`, so a new ceremony verb cannot escape
/// classification (P-H, the retired `.chain([Guide, Run])` tail let one through). The shape lock
/// `spine_order_and_derived_verb_subset_hold` pins the exact set.
pub fn spine_modeled_verbs() -> std::collections::BTreeSet<VerbId> {
    VerbId::all().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::param::DerivationInputs;
    use std::path::PathBuf;

    fn derive_with(operator_pubkey: Option<&str>) -> Option<String> {
        let root = PathBuf::from("/repo");
        let inputs = DerivationInputs::for_reads(&["operator_pubkey"], &root, |r| match r {
            "operator_pubkey" => operator_pubkey,
            _ => None,
        });
        derive_box_login_identity(&inputs)
    }

    #[test]
    fn box_login_identity_is_operator_pubkey_minus_dot_pub() {
                                                                                                    
        assert_eq!(
            derive_with(Some("/keys/op.pub")).as_deref(),
            Some("/keys/op")
        );
                                                       
        assert_eq!(derive_with(Some("/keys/op")).as_deref(), Some("/keys/op"));
    }

    #[test]
    fn box_login_identity_is_absent_without_operator_pubkey() {
        assert_eq!(derive_with(None), None);
    }
}
