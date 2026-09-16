                                                                          
                                                      
//!
                                                            
//! 1. the profile is loaded and the context resolved by the caller — the profile is the context
                                                                                         
//! 2. parameter resolution (flag/typed > profile; the builtin default is NOT materialized here —
                                                                           
                                                                                         
//!    over;
//! 4. parameter validation, scoped to the params of NOT-DONE steps (a converged profile whose
                                                                  
                                                                                 
//! 8. the ceremony-immutable preconditions of not-done steps (`SubjectOrigin::CeremonyImmutable`;
//!    step-product preconditions evaluate at their own step).
//!
                                                                                        
//! chokepoint and holds it for every writing verb before the verb body runs, `run` included. That
                                                                                              
//! host; cross-host resource locking is Q2's (fleet cycle), not v1's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::Utf8PathBuf;
use super::param::{DefaultWithSource, DerivationInputs, ParamClass, ParamRecord, ParamValues};
use super::probes::{DoneResult, ProbeCtx, ProbeResult, SubjectOrigin};
use super::records::RunRecords;
use super::refusal::{MissingParam, Refusal, RefusalId, UnmetPrecondition};
use super::spine::{CheckoutRef, SPINE, Step, StepId, WriteClass};
use crate::deploy::context::ResolvedContext;
use crate::deploy::profile::{Profile, ip_cross_check};

                                                                  
/// executing invocation carried, never a merged value. Reading a merged value instead is the
                             
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunInvocation {
    pub profile_path: Utf8PathBuf,
                                                                                         
    pub target: Option<String>,
    /// Judgment-class values typed on THIS invocation, keyed by ceremony parameter name.
    pub judgment: BTreeMap<String, String>,
                                    
    pub commit: bool,
                                        
    pub wipe_confirmed: bool,
                                                                                          
    pub porcelain: bool,
    /// The operator-ratified declared-space directory (`--repo-form-dir`); `None` means the default
    /// `boxes/repo-form/`.
    pub repo_form_dir: Option<Utf8PathBuf>,
}

/// Bare when every byte is in `[A-Za-z0-9_./:=+@%,-]` and the token is non-empty; otherwise
/// POSIX single-quoted, each `'` rendered `'\''` (XCU single quotes cannot nest).
fn shell_word(token: &str) -> String {
    let bare = !token.is_empty()
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'.' | b'/' | b':' | b'=' | b'+' | b'@' | b'%' | b',' | b'-'
                )
        });
    if bare {
        token.to_string()
    } else {
        format!("'{}'", token.replace('\'', "'\\''"))
    }
}

impl RunInvocation {
    /// The `orchard run` argv this invocation re-types: `run`, the profile, `--target`, the
    /// judgment flags in map order, `--commit`/`--wipe-confirmed`/`--porcelain` per the set fields,
    /// then `--repo-form-dir` and the resolved context flags.
    pub fn argv(&self, ctx: &ResolvedContext) -> Vec<String> {
        let mut argv = vec!["run".to_string(), self.profile_path.as_str().to_string()];
        if let Some(t) = &self.target {
            argv.push("--target".to_string());
            argv.push(t.clone());
        }
        for (name, value) in &self.judgment {
            argv.push(format!("--{}", name.replace('_', "-")));
            argv.push(value.clone());
        }
        if self.commit {
            argv.push("--commit".to_string());
        }
        if self.wipe_confirmed {
            argv.push("--wipe-confirmed".to_string());
        }
        if self.porcelain {
            argv.push("--porcelain".to_string());
        }
        if let Some(dir) = &self.repo_form_dir {
            argv.push("--repo-form-dir".to_string());
            argv.push(dir.as_str().to_string());
        }
        argv.extend(ctx.forward_flags());
        argv
    }

    /// The resume command an owed stop prints: `orchard ` + [`argv`](Self::argv), each token quoted
    /// for the shell (`shell_word`): the `Run` fields as typed, then the resolved context flags.
    pub fn resume_command(&self, ctx: &ResolvedContext) -> String {
        let words: Vec<String> = self.argv(ctx).iter().map(|t| shell_word(t)).collect();
        format!("orchard {}", words.join(" "))
    }

    /// The `orchard admit` argv that ratifies this invocation's declared-space directory: `admit`,
    /// `--box`, the profile, `--repo-form-dir` when set, then the resolved context flags.
    pub fn admit_argv(&self, ctx: &ResolvedContext) -> Vec<String> {
        let mut argv = vec![
            "admit".to_string(),
            "--box".to_string(),
            self.profile_path.as_str().to_string(),
        ];
        if let Some(dir) = &self.repo_form_dir {
            argv.push("--repo-form-dir".to_string());
            argv.push(dir.as_str().to_string());
        }
        argv.extend(ctx.forward_flags());
        argv
    }

    /// The admit command a declared-space cure prints: `orchard ` + [`admit_argv`](Self::admit_argv),
    /// each token quoted for the shell (`shell_word`).
    pub fn admit_command(&self, ctx: &ResolvedContext) -> String {
        let words: Vec<String> = self.admit_argv(ctx).iter().map(|t| shell_word(t)).collect();
        format!("orchard {}", words.join(" "))
    }

    /// A clone carrying the headless commit authorization.
    pub fn with_commit(&self) -> Self {
        Self {
            commit: true,
            ..self.clone()
        }
    }

    /// A clone carrying the destructive-token authorization.
    pub fn with_wipe_confirmed(&self) -> Self {
        Self {
            wipe_confirmed: true,
            ..self.clone()
        }
    }

    /// The ratified declared-space file for a named checkout (§1.1):
    /// `<repo_form_dir>/<checkout>.keys` under `repo_root`, the directory defaulting to
    /// `boxes/repo-form`. An absolute `repo_form_dir` survives the join.
    pub fn ratified_file(&self, repo_root: &Utf8PathBuf, checkout: &str) -> Utf8PathBuf {
        let default_dir = Utf8PathBuf::from("boxes/repo-form");
        let dir = self.repo_form_dir.as_ref().unwrap_or(&default_dir);
        repo_root
            .join(dir)
            .join(&Utf8PathBuf::from(format!("{checkout}.keys")))
    }
}

/// A ratified declared-space file that exists but cannot be read as the declared space (§3.3): an
/// I/O error, or bytes outside UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatifiedFileError {
    /// The file exists and `read` returned an I/O error (a directory in place, an unreadable mode).
    Io { path: PathBuf, error: String },
    /// The file was read and holds bytes outside UTF-8; `sample` is the runner's `escape_ascii` form.
    NonUtf8 { path: PathBuf, sample: String },
}

impl std::fmt::Display for RatifiedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatifiedFileError::Io { path, error } => write!(f, "{}: {error}", path.display()),
            RatifiedFileError::NonUtf8 { path, sample } => {
                write!(f, "{}: bytes outside UTF-8 ({sample})", path.display())
            }
        }
    }
}

/// Read a ratified declared-space file (§3.3): `NotFound` is `Ok(None)`; any other I/O error is
/// `Io`; a read that succeeds with non-UTF-8 bytes is `NonUtf8` with the runner's escaped sample.
pub fn read_ratified(path: &Path) -> Result<Option<String>, RatifiedFileError> {
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Ok(Some(s)),
            Err(e) => Err(RatifiedFileError::NonUtf8 {
                path: path.to_path_buf(),
                sample: super::gate_commit::non_utf8_sample(super::gate_commit::offending_record(
                    e.as_bytes(),
                    e.utf8_error().valid_up_to(),
                )),
            }),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(RatifiedFileError::Io {
            path: path.to_path_buf(),
            error: e.to_string(),
        }),
    }
}

/// What the runner measured about the executing checkout before admission. Passed in so the
/// admission core is hermetic (no git, no CWD): [`measure`] is the live producer.
#[derive(Debug, Clone, Default)]
pub struct Measured {
    /// Working-tree dirty paths, repo-root-relative (`git status --porcelain`), untracked
    /// included.
    pub dirty: Vec<String>,
    /// The ceremony checkout's HEAD sha — the `ceremony-head` input identity. `None` when it
    /// cannot be derived (no git, not a repo): the identity check then SKIPS, it never
    /// invalidates a record (see [`identity_value`]).
    pub head: Option<String>,
}

/// One step's admission-time decision.
#[derive(Debug, Clone)]
pub struct PlannedStep {
    pub id: StepId,
    pub done: DoneResult,
}

impl PlannedStep {
    pub fn is_done(&self) -> bool {
        matches!(self.done, DoneResult::Done)
    }
}

/// The admission verdict: the values the run executes with and the plan it executes.
#[derive(Debug)]
pub struct Admitted {
    pub values: ParamValues,
    pub plan: Vec<PlannedStep>,
    pub measured: Measured,
}

impl Admitted {
    /// The not-done steps, in spine order (what the loop will attempt).
    pub fn pending(&self) -> impl Iterator<Item = &PlannedStep> {
        self.plan.iter().filter(|p| !p.is_done())
    }
}

/// Live admission: measure the executing checkout, then run the hermetic core.
pub fn admit(
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    profile: &Profile,
    records: &RunRecords,
) -> Result<Admitted, Refusal> {
    let measured = measure(&ctx.repo_root);
    admit_with(inv, ctx, profile, records, measured)
}

                                                                                      
pub fn admit_with(
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    profile: &Profile,
    records: &RunRecords,
    measured: Measured,
) -> Result<Admitted, Refusal> {
    let values = resolve_values(inv, profile, ctx);
    let probe_ctx = ProbeCtx::new(ctx, Some(profile.clone()));
    let plan = plan_of(&probe_ctx, &values, records, &measured);
    validate_parameters(&plan, &probe_ctx, &values)?;
    check_typed_target(inv, profile, &plan)?;
    check_judgment_resupply(inv, &plan)?;
    let own_profile = profile_repo_relative(inv.profile_path.as_path(), &ctx.repo_root);
    check_ceremony_tree_dirt(&measured, own_profile.as_deref())?;
    check_admission_preconditions(&plan, &probe_ctx)?;
    check_required_present(&plan, &values)?;
    Ok(Admitted {
        values,
        plan,
        measured,
    })
}

                                                                                             
/// interview needs exactly this — it computes its ask set from the done-marks, and it is about to
/// COLLECT the values whose absence those gates refuse on, so running them first would refuse
/// every first interview.
pub fn plan_of(
    probe_ctx: &ProbeCtx,
    values: &ParamValues,
    records: &RunRecords,
    measured: &Measured,
) -> Vec<PlannedStep> {
    SPINE
        .iter()
        .map(|step| PlannedStep {
            id: step.id,
            done: step_done(step, probe_ctx, values, records, measured),
        })
        .collect()
}

                                                                                                   

/// Resolve every spine parameter: the typed invocation first, then the profile, then (pass 2) the
/// runtime producers for `Derived`/`FromContext` defaults. The builtin default is deliberately NOT
                                               
/// value here means "this invocation supplies none" and the composed child argv simply omits the
/// flag. FAC-GC-3: a `Derived`/`FromContext` default DOES resolve here, via its own producer, so a
                                              
pub fn resolve_values(
    inv: &RunInvocation,
    profile: &Profile,
    ctx: &ResolvedContext,
) -> ParamValues {
                                                      
    let mut values = ParamValues::default();
    for step in SPINE.iter() {
        for p in step.params {
            if let Some(v) = resolve_one(p, inv, profile) {
                values.insert(p.name, v);
            }
        }
    }
                                                                                                   
                                                                                                  
                                                                                                 
                                                               
    let mut derived = Vec::new();
    for step in SPINE.iter() {
        for p in step.params {
            if values.get(p.name).is_none()
                && let Some(d) = p.default.derivation()
            {
                let inputs =
                    DerivationInputs::for_reads(d.reads, &ctx.repo_root, |r| values.get(r));
                if let Some(v) = (d.f)(&inputs) {
                    derived.push((p.name, v));
                }
            }
        }
    }
    for (name, v) in derived {
        values.insert(name, v);
    }
    values
}

fn resolve_one(p: &ParamRecord, inv: &RunInvocation, profile: &Profile) -> Option<String> {
                                                                                                
                                                                                      
                                                                                                  
                                                                                                
    if p.name == "ip" {
        return inv
            .target
            .clone()
            .or_else(|| profile_value(profile, p.name));
    }
    if p.class == ParamClass::Judgment
        && let Some(v) = inv.judgment.get(p.name)
    {
        return Some(v.clone());
    }
    profile_value(profile, p.name)
}

/// Read one profile key as a scalar string. DERIVED from the schema by serializing the typed
/// profile (the `noted_keys_present` technique), never a hand-written name→field map that a new
/// key silently escapes.
pub fn profile_value(profile: &Profile, key: &str) -> Option<String> {
    let v = serde_json::to_value(profile).ok()?;
    match v.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

                                                                                            
/// ordering). A value that fails its own probe refuses with the probe's cure.
fn validate_parameters(
    plan: &[PlannedStep],
    ctx: &ProbeCtx,
    values: &ParamValues,
) -> Result<(), Refusal> {
    for step in SPINE.iter() {
        if plan.iter().any(|p| p.id == step.id && p.is_done()) {
            continue;
        }
        for p in step.params {
            let Some(v) = values.get(p.name) else {
                continue;
            };
            match (p.probe)(ctx, v) {
                ProbeResult::Met => {}
                ProbeResult::Unmet(why) | ProbeResult::Unevaluable(why) => {
                    return Err(Refusal::new(
                        RefusalId::ParameterInvalid,
                        format!("{} = {v:?} ({}): {why}", p.name, step.id.token()),
                    )
                    .with_cure_extra(format!("the offending key is `{}`", p.name)));
                }
            }
        }
    }
    Ok(())
}

                                                                                                     
/// step declares must be PRESENT at admission. Presence-only `validate_parameters` skips an absent
/// value, so before this an absent Required param was admitted and its flag simply omitted from the
/// child argv (`spine::flagged`), leaving the refusal to the child verb mid-run after earlier steps
/// mutated. Decision 2026-08-25 (admission-enforce), operator-directed: supersedes the
/// step-time-only handling S6 point-fixed for `tenant_artifacts`, which stays as defense in depth.
fn check_required_present(plan: &[PlannedStep], values: &ParamValues) -> Result<(), Refusal> {
    for (step, p) in required_present_params(plan) {
        if values.get(p.name).is_none() {
            let detail = format!(
                "step {} is not done and its required parameter `{}` has no value — {}",
                step.token(),
                p.name,
                p.explain
            );
            return Err(Refusal::typed(
                RefusalId::RequiredParamMissing,
                detail,
                &MissingParam {
                    name: p.name,
                    class: p.class,
                },
            ));
        }
    }
    Ok(())
}

/// The `Required` params NOT-DONE steps declare, deduped by name and attributed to the first
/// declaring not-done step. `check_required_present` demands exactly this set; the interview's
/// `ask_set` MUST be a superset of it, pinned by
                                                                                                   
/// this gate are two walks over one spine set, and nothing else reconciles them). Derived from the
                                                                                                    
/// typed `--target`, not the resolved param.
pub fn required_present_params(plan: &[PlannedStep]) -> Vec<(StepId, &'static ParamRecord)> {
    let mut out: Vec<(StepId, &'static ParamRecord)> = Vec::new();
    for step in SPINE.iter() {
        if plan.iter().any(|p| p.id == step.id && p.is_done()) {
            continue;
        }
        for p in step.params {
            if p.default != DefaultWithSource::Required || p.name == "ip" {
                continue;
            }
            if !out.iter().any(|(_, q)| q.name == p.name) {
                out.push((step.id, p));
            }
        }
    }
    out
}

/// The spine `ParamRecord` for a parameter looked up by NAME. The step-time backstops
/// (`runner::step_completion`) build `MissingParam` from this for the same params the admission gate
/// does; a name with no spine entry is an internal invariant, not an operator artifact.
pub(crate) fn spine_param(name: &str) -> Option<&'static ParamRecord> {
    SPINE
        .iter()
        .flat_map(|s| s.params.iter())
        .find(|p| p.name == name)
}

                                                                                                   

                                                                                             
/// its input identities and its produced artifacts, and the step's own `artifact_present` probe
/// covers a product the record cannot see. All of them must hold; anything unevaluable counts
/// NOT-done (fail-closed re-execution).
pub fn step_done(
    step: &Step,
    ctx: &ProbeCtx,
    values: &ParamValues,
    records: &RunRecords,
    measured: &Measured,
) -> DoneResult {
    let Some(rec) = records.step_record(step.id.token()) else {
        return DoneResult::NotDone(format!(
            "no record of {} in this profile's run records",
            step.id.token()
        ));
    };
    for p in step.params {
        let now = values.get(p.name);
        let recorded = rec.params.get(p.name).map(String::as_str);
        if now != recorded {
            return DoneResult::NotDone(format!(
                "parameter `{}` changed since the recorded run (recorded {recorded:?}, now \
                 {now:?})",
                p.name
            ));
        }
    }
    for id in step.input_identities {
                                                                                               
                                                                                                  
                                                                                  
        let Some(now) = identity_value(id.id, ctx, values, measured) else {
            continue;
        };
        let recorded = rec.input_identities.get(id.id).map(String::as_str);
        if recorded != Some(now.as_str()) {
            return DoneResult::NotDone(format!(
                "input identity `{}` changed since the recorded run (recorded {recorded:?}, now \
                 {:?})",
                id.id,
                Some(now.as_str())
            ));
        }
    }
                                                                                              
                                                                                 
                                                                                                  
                                                                                                
                                                                  
    for (name, art) in &rec.produced {
        let p = Path::new(&art.path);
        if !p.exists() {
            return DoneResult::NotDone(format!(
                "produced artifact `{name}` is gone ({}) — the step re-executes",
                art.path
            ));
        }
        if art.sha256.is_empty() {
            return DoneResult::NotDone(format!(
                "produced artifact `{name}` has no recorded hash to bind ({}) — the step re-executes",
                art.path
            ));
        }
        match file_sha256(p) {
            Some(now) if now == art.sha256 => {}
            Some(now) => {
                return DoneResult::NotDone(format!(
                    "produced artifact `{name}` at {} changed since the record (recorded {}, now \
                     {now}) — the step re-executes",
                    art.path, art.sha256
                ));
            }
            None => {
                return DoneResult::NotDone(format!(
                    "produced artifact `{name}` at {} cannot be re-hashed — the step re-executes",
                    art.path
                ));
            }
        }
    }
    match step.artifact_present {
        None => DoneResult::Done,
        Some(probe) => match (probe.run)(ctx, values) {
            DoneResult::Done => DoneResult::Done,
            DoneResult::NotDone(why) => DoneResult::NotDone(why),
                                                                
            DoneResult::Unevaluable(why) => DoneResult::NotDone(format!("unevaluable: {why}")),
        },
    }
}

/// Input identities the runner cannot re-derive yet, with the task that supplies them. A
/// spine identity absent from BOTH this list and `identity_value`'s arms is a self-test failure
/// (`ceremony_selftests::every_input_identity_resolves_or_is_declared_deferred`), so a new
/// identity cannot silently become a permanent SKIP.
pub const IDENTITIES_DEFERRED: &[(&str, &str)] = &[
    (
        "published-pins",
        "resolved by the SIBLING GATE at its own step (`runner::sibling_gate` reads the sibling's \
         declared path and recognizes it through the shared store), so re-deriving it here would \
         duplicate a check that already refuses before the overwriting step",
    ),
    (
        "staged-set-hashes",
        "bound by the S8 GATE RECORD, which is S8's recorded product and S10's precondition input \
         (`gate_record::verify` compares it against the image's own provenance). Re-deriving it \
         as an identity here would compare the record against itself",
    ),
];

/// Re-derive one input identity's CURRENT value. `None` = not derivable in this context (see
/// `step_done`: the record then stands).
pub fn identity_value(
    id: &str,
    ctx: &ProbeCtx,
    values: &ParamValues,
    measured: &Measured,
) -> Option<String> {
    match id {
        "containerfile" => file_sha256(&ctx.repo_root().join("crates/image-builder/Containerfile")),
        "pins.toml" => file_sha256(&ctx.repo_root().join("pins.toml")),
        "consume-pins.toml" => file_sha256(&ctx.repo_root().join("consume-pins.toml")),
        "ceremony-head" => measured.head.clone(),
        "tenant_source_ref" => values.get("tenant_source_ref").map(str::to_string),
        "handoff-tree-hash" => handoff_tree_hash(Path::new(super::spine::HANDOFF_ROOT)),
        _ => None,
    }
}

                                                                                                  
                                                                             
/// `plan_of`/`step_done`, and a produced artifact is the `.img`, so `std::fs::read` loaded the
/// image into memory each pass. Fail-closed: an absent/unreadable file is `None`, so the step
/// re-executes. Same SHA-256 the build's own `image::sha256_hex` sidecar records.
fn file_sha256(path: &Path) -> Option<String> {
    crate::deploy::stage_stream::hash_file_chunked(path)
        .ok()
        .map(hex::encode)
}

/// A content hash over a directory tree: every regular file's repo-relative path and bytes, in
/// sorted path order, folded into one digest. Absent tree ⇒ `None`.
pub fn handoff_tree_hash(root: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    if !root.is_dir() {
        return None;
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(root, &mut files).ok()?;
    files.sort();
    let mut h = Sha256::new();
    for f in files {
        let rel = f.strip_prefix(root).ok()?;
        h.update(rel.to_string_lossy().as_bytes());
        h.update([0u8]);
        let bytes = std::fs::read(&f).ok()?;
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    Some(hex::encode(h.finalize()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(&p, out)?;
        } else if ft.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

                                                                                                   

                                                                                             
/// holds a NOT-DONE destructive step (a SKIP-only run is exempt, D20's mirror). The destructive
/// set is derived from the declared writes (`Step::destructive`), never a hand list.
fn check_typed_target(
    inv: &RunInvocation,
    profile: &Profile,
    plan: &[PlannedStep],
) -> Result<(), Refusal> {
    let pending_destructive: Vec<&'static str> = SPINE
        .iter()
        .filter(|s| s.destructive())
        .filter(|s| plan.iter().any(|p| p.id == s.id && !p.is_done()))
        .map(|s| s.id.token())
        .collect();
    if pending_destructive.is_empty() {
        return Ok(());
    }
    let typed = inv.target.as_deref().ok_or_else(|| {
        Refusal::new(
            RefusalId::TargetNotTyped,
            format!(
                "this run's plan contains the not-done destructive step(s) {pending_destructive:?} \
                 and no target was typed on the invocation"
            ),
        )
    })?;
    let stored = profile_value(profile, "ip").ok_or_else(|| {
        Refusal::new(
            RefusalId::ProfileTargetMissing,
            format!(
                "the profile carries no `ip`, so the typed target `{typed}` has nothing to \
                 cross-check against"
            ),
        )
    })?;
                                                                                        
                                                                                                 
                                                                                         
    if ip_cross_check(typed, Some(&stored)).is_err() {
        return Err(Refusal::new(
            RefusalId::TargetMismatch,
            format!(
                "the typed target `{typed}` does not match the profile's stored `ip = \"{stored}\"`"
            ),
        ));
    }
    Ok(())
}

                                                                                                   

                                                                                                  
                                                                                          
/// seeded-wrong build reads the merge and passes on a profile-carried value alone).
fn check_judgment_resupply(inv: &RunInvocation, plan: &[PlannedStep]) -> Result<(), Refusal> {
    for step in SPINE.iter() {
        if plan.iter().any(|p| p.id == step.id && p.is_done()) {
            continue;
        }
        for p in step.judgment_params() {
            if !inv.judgment.contains_key(p.name) {
                return Err(Refusal::new(
                    RefusalId::JudgmentNotResupplied,
                    format!(
                        "step {} is not done and consumes the judgment value `{}`, which this \
                         invocation did not supply — {}",
                        step.id.token(),
                        p.name,
                        p.explain
                    ),
                )
                .with_cure_extra(format!("the flag is --{}", p.name.replace('_', "-"))));
            }
        }
    }
    Ok(())
}

                                                                                                   

                                                                          
/// spine's declared repo-tree writes. A trailing `/` marks a directory pathspec.
pub fn declared_repo_paths() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = SPINE
        .iter()
        .flat_map(|s| s.writes.iter())
        .filter(|w| w.class == WriteClass::RepoTree && w.checkout == CheckoutRef::Executing)
        .map(|w| w.pathspec)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Is a repo-relative path inside the declared written set?
pub fn is_declared(path: &str) -> bool {
    declared_repo_paths()
        .iter()
        .any(|d| match d.strip_suffix('/') {
            Some(dir) => path == dir || path.starts_with(&format!("{dir}/")),
            None => path == *d,
        })
}

                                                                                    
/// guide writes the profile, so it is the run's config, never foreign operator dirt.
fn profile_repo_relative(profile_path: &Path, repo_root: &Path) -> Option<String> {
    let rel = if profile_path.is_absolute() {
        profile_path.strip_prefix(repo_root).ok()?
    } else {
        profile_path
    };
    rel.to_str().map(str::to_owned)
}

                                                                                                
                                                                                             
                                                                 
pub fn check_ceremony_tree_dirt(
    measured: &Measured,
    own_profile: Option<&str>,
) -> Result<(), Refusal> {
    let foreign: Vec<&str> = measured
        .dirty
        .iter()
        .map(String::as_str)
        .filter(|p| !is_declared(p) && Some(*p) != own_profile)
        .collect();
    if foreign.is_empty() {
        return Ok(());
    }
    Err(Refusal::new(
        RefusalId::CeremonyTreeDirty,
        format!(
            "the ceremony checkout has uncommitted changes outside the paths this ceremony \
             writes: {foreign:?}"
        ),
    ))
}

                                                                                                   

                                                                                            
/// actually run. Step-product preconditions (`SubjectOrigin::StepProduct`) evaluate at their own
                                                                                      
/// refusing on a precondition nothing is about to consume.
fn check_admission_preconditions(plan: &[PlannedStep], ctx: &ProbeCtx) -> Result<(), Refusal> {
    let mut seen: Vec<&'static str> = Vec::new();
    for step in SPINE.iter() {
        if plan.iter().any(|p| p.id == step.id && p.is_done()) {
            continue;
        }
        for probe in step.preconditions {
            if probe.subject != SubjectOrigin::CeremonyImmutable || seen.contains(&probe.id) {
                continue;
            }
            seen.push(probe.id);
            let result = (probe.run)(ctx);
            let detail = match &result {
                ProbeResult::Met => continue,
                ProbeResult::Unmet(remedy) => {
                    format!("{} ({}): {remedy}", probe.id, probe.explain)
                }
                ProbeResult::Unevaluable(why) => {
                    format!("{} could not be evaluated: {why}", probe.id)
                }
            };
            return Err(Refusal::typed(
                RefusalId::PreconditionUnmet,
                detail,
                &UnmetPrecondition::from_probe(probe, result, None),
            ));
        }
    }
    Ok(())
}

                                                                                                   

                                                                                                  
/// behind `build`'s own clean-tree refusal (the step-time gate), so on an UNEVALUABLE checkout it
/// degrades to an empty list — the documented pre-FAC-GC-1 behaviour, kept deliberately because the
/// executing gates (`sibling_gate`, `executing_gate`) now fail CLOSED on the same signal and are
/// the load-bearing controls. The `DirtScan` match makes that degradation an explicit choice rather
/// than an `.unwrap_or_default()` collapse.
pub fn measure(repo_root: &Path) -> Measured {
    Measured {
        dirty: match git_dirty_paths(repo_root) {
            DirtScan::Scanned(v) => v,
            DirtScan::Unevaluable(_) => vec![],
        },
        head: git_head(repo_root),
    }
}

fn git_head(repo_root: &Path) -> Option<String> {
    match super::gate_commit::Git::new(repo_root)
        .args(&["rev-parse", "HEAD"])
        .text_or_exit("rev-parse HEAD")
    {
        Ok(super::gate_commit::GitReply::Ok(s)) => {
            let s = s.trim().to_string();
            (!s.is_empty()).then_some(s)
        }
        _ => None,
    }
}

/// The three-state answer to "what is dirty in this checkout?". `Option` +
/// `.unwrap_or_default()` collapsed the unevaluable case — a non-repo, git missing, a spawn
/// failure, a non-zero `git status`, or output outside UTF-8 — to the SAFE reading, an empty set
                                                                                            
               
/// `ProbeResult`/`DoneResult`, whose `Unevaluable` the compiler already forces each consumer to
/// match; here each of the five reader sites must state its reading of the unevaluable case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirtScan {
    /// `git status` ran and reported this set (possibly empty = clean).
    Scanned(Vec<String>),
    /// `git status` could not answer: the spawn failed, git exited non-zero, or its output held
    /// bytes outside UTF-8.
    Unevaluable(super::refusal::GitRunError),
}

/// `git status --porcelain=v1 -z --untracked-files=all`, parsed. The NUL form is used because a
/// path with a space, a quote or a newline is rendered verbatim there, while the default form
/// C-quotes it — a quoted path would not match a declared pathspec and would refuse as foreign
/// dirt. A rename/copy entry is followed by its ORIGIN path as a separate NUL-terminated field;
/// both paths are reported (an origin outside the declared set is real dirt). Returns
/// `DirtScan::Unevaluable` rather than an empty set when the command cannot run or fails, so a
/// consumer cannot silently read "clean".
pub fn git_dirty_paths(repo_root: &Path) -> DirtScan {
                                                                                               
                                                                                                 
    let op = format!("status (in {})", repo_root.display());
    match super::gate_commit::Git::new(repo_root)
        .args(&[
            "--no-optional-locks",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ])
        .text_or_exit(&op)
    {
        Ok(super::gate_commit::GitReply::Ok(text)) => DirtScan::Scanned(parse_porcelain_z(&text)),
        Ok(super::gate_commit::GitReply::Exit { code, stderr }) => {
            DirtScan::Unevaluable(super::refusal::GitRunError::Exit {
                op,
                status: super::gate_commit::exit_status_string(code),
                stderr,
            })
        }
        Err(e) => DirtScan::Unevaluable(e),
    }
}

/// The parser half, driven directly by the tests (the shapes come from `git status` runs, not
/// from the manpage).
pub fn parse_porcelain_z(raw: &str) -> Vec<String> {
    let mut fields = raw.split('\0').filter(|f| !f.is_empty());
    let mut out = Vec::new();
    while let Some(entry) = fields.next() {
                                                                              
        let Some(path) = entry.get(3..) else { continue };
        let status = &entry[..entry.len().min(2)];
        out.push(path.to_string());
        if (status.starts_with('R') || status.starts_with('C'))
            && let Some(origin) = fields.next()
        {
            out.push(origin.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}
