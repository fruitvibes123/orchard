                                                                                                 
//! each converging on its own done decision.
//!
//! Two seams keep the loop testable without spawning anything:
//! - [`child_invocations`] composes the FULL child argv — the spine's `compose` output plus the
//!   resolved context flags, the runner-resolved step inputs, and the typed tokens forwarded
                                                                                  
//!   drive it rather than `compose` alone; nothing appends to an argv behind their back.
//! - [`Executor`] is what the loop calls to run one child. `ProcessExecutor` spawns; the arms
//!   record the calls and hand back a scripted outcome.
//!
                                             
//! inherits BOTH descriptors, so verb-owned y/e/N gates and passphrase prompts run exactly as the
                                                                                             
//! Porcelain and headless mode pipes the child's stdio and frames it as `detail` records; there
//! `is_tty` is false in the child, which selects the verb's headless consent branch — the regime
                                    

use std::path::{Path, PathBuf};

use super::admission::{Admitted, RunInvocation, step_done};
use super::classify::{FlagClass, VerbId, flag_table};
use super::emit::emit_stdout;
use super::param::ParamValues;
use super::porcelain::{OwedKind, OwedStop, PorcelainRecord};
use super::probes::{DoneResult, ProbeCtx, ProbeResult, SubjectOrigin};
use super::records::{DeclaredPathName, RunRecords, StepRecord};
use super::refusal::{
    GitReadFailure, GitReadPurpose, GitRunError, MissingParam, Refusal, RefusalId,
    UnmetPrecondition,
};
use super::spine::{ExecutorClass, Invocation, Program, SPINE, Step, StepId};
use crate::deploy::context::ResolvedContext;

/// Where a child resolves relative paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildCwd {
    /// Kernel inheritance: the child resolves relative paths as its parent does; no `current_dir`.
    Inherit,
    /// A pinned directory the child runs in regardless of the parent's shell cwd.
    At(PathBuf),
}

/// One composed child call, as the loop hands it to its executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildCall {
    pub step: StepId,
    pub program: Program,
    pub args: Vec<String>,
    pub cwd: ChildCwd,
    /// Environment ADDITIONS for the child (the ceremony lock token, so a runner-driven child
    /// JOINS the host lock instead of refusing against it — plan-inputs §Locks).
    pub env: Vec<(String, String)>,
    /// Inherit the caller's stdio (interactive) instead of piping it (porcelain/headless).
    pub inherit_stdio: bool,
}

/// What an executor reports back about one child.
#[derive(Debug)]
pub enum ChildOutcome {
    Ok,
    /// The child ran and exited non-zero, or could not be spawned (an operator-fixable verb
                                             
    Failed(String),
}

/// One child execution. `sink` receives the child's output LINE BY LINE as it arrives in the
/// piped regime (porcelain/headless), so a long step is not silent; in the inherited regime the
/// child writes to the real descriptors and the sink is never called.
pub trait Executor {
    fn run(&mut self, call: &ChildCall, sink: &mut dyn FnMut(&str)) -> ChildOutcome;
}

/// How the loop reports progress: porcelain records or human lines.
pub struct Reporter {
    pub porcelain: bool,
}

impl Reporter {
    fn step(&self, step: &Step, action: &str, why: &str) {
        if self.porcelain {
            emit_stdout(&format!(
                "{}\n",
                PorcelainRecord::new("step")
                    .field("step", step.id.token())
                    .field("action", action)
                    .render()
            ));
        } else {
            let tail = if why.is_empty() {
                String::new()
            } else {
                format!(" — {why}")
            };
            emit_stdout(&format!(
                "[{action}] {}  {}{tail}\n",
                step.id.token(),
                step.title
            ));
        }
    }

    fn detail(&self, step: &Step, line: &str) {
        if self.porcelain {
            emit_stdout(&format!(
                "{}\n",
                PorcelainRecord::new("detail")
                    .field("step", step.id.token())
                    .field("detail", line)
                    .render()
            ));
        } else {
            emit_stdout(&format!("  {line}\n"));
        }
    }

    fn owed(&self, step: &Step, action: &str) {
        if self.porcelain {
            emit_stdout(&format!(
                "{}\n",
                PorcelainRecord::new("owed")
                    .field("step", step.id.token())
                    .field("action", action)
                    .render()
            ));
        } else {
            emit_stdout(&format!("[owed] {}: {action}\n", step.id.token()));
        }
    }
}

/// Everything the loop needs from the outside world, bundled so the signature stays readable and
/// every seam is visible in one place.
pub struct RunnerDeps<'a> {
    pub exec: &'a mut dyn Executor,
    pub reporter: &'a Reporter,
    pub lock_token: Option<&'a str>,
    /// Interactive iff BOTH descriptors are a tty — the same rule the underlying verbs use, so
                                                                                   
    pub is_tty: bool,
    /// The y/e/N keystroke source. Runs ONLY on the interactive branch.
    pub prompt: &'a dyn Fn() -> char,
    /// `$EDITOR` for the `e` branch's message edit, read in the CLI. `None` drives the edit-abort
    /// stop deterministically from an arm.
    pub editor: Option<&'a std::ffi::OsStr>,
}

                                                                                                    

/// The forwardable classes, by construction: a token of one of these classes may appear in a
/// composed child argv ONLY because the operator typed it on the executing invocation. The spine
                        
/// and `child_invocations` adds one only from the matching `RunInvocation` field.
fn forwarded_flag(verb: VerbId, class: FlagClass) -> Option<&'static str> {
    flag_table()
        .iter()
        .find(|(v, _, c)| *v == verb && *c == class)
        .map(|(_, f, _)| *f)
}

/// Compose every child argv for one step: the spine's `compose`, plus the resolved context flags
/// (children never re-resolve from their own CWD — the P4 class), plus the runner-resolved step
/// inputs, plus the typed tokens forwarded verbatim.
pub fn child_invocations(
    step: &Step,
    values: &ParamValues,
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    records: &RunRecords,
) -> Result<Vec<Invocation>, Refusal> {
    let mut out = Vec::new();
    for mut invocation in (step.compose)(values) {
        if invocation.program == Program::SelfExe {
                                                                                               
                                                                                     
            if step.id == StepId::S10ProdInstall {
                let img = records
                    .step_record(StepId::S7ImageBuild.token())
                    .and_then(|r| r.produced.get("img"))
                    .ok_or_else(|| {
                        Refusal::new(
                            RefusalId::StepInputMissing,
                            "s10-prod-install needs the image s7-image-build produced, and this \
                             profile's records name none",
                        )
                        .with_cure_extra(super::records::records_dir_cure(records.dir()))
                    })?;
                invocation.args.push("--image".into());
                invocation.args.push(img.path.clone());
            }
                                                                                                    
                                                                     
            invocation.args.extend(ctx.forward_flags());
            if let Some(verb) = step.verb {
                if inv.commit
                    && let Some(f) = forwarded_flag(verb, FlagClass::ConsentBearing)
                {
                    invocation.args.push(format!("--{f}"));
                }
                if inv.wipe_confirmed
                    && let Some(f) = forwarded_flag(verb, FlagClass::MandatoryDestructiveToken)
                {
                    invocation.args.push(format!("--{f}"));
                }
            }
        }
        out.push(invocation);
    }
    Ok(out)
}

/// The environment additions for a step's children: the host-lock token (so a
/// runner-driven child JOINS the host lock, plan-inputs §Locks), the ceremony's resolved artifact
                                                                                               
/// would otherwise re-resolve `<repo>/../artifact-store`), plus the step's own composed env. Every
/// step's env flows through here, the env analogue of `child_invocations`.
pub fn child_env(
    step: &Step,
    lock_token: Option<&str>,
    artifact_store: &Path,
    records: &RunRecords,
    values: &ParamValues,
) -> Vec<(String, String)> {
    let mut env = lock_token
        .map(|t| {
            vec![
                (super::lock::LOCK_TOKEN_ENV.to_string(), t.to_string()),
                                                                                                  
                                                                 
                (
                    super::lock::CEREMONY_PPID_ENV.to_string(),
                    std::process::id().to_string(),
                ),
            ]
        })
        .unwrap_or_default();
    env.push((
        crate::deploy::context::ARTIFACT_STORE_ENV.to_string(),
        artifact_store.display().to_string(),
    ));
                                                                                                 
                                                                                                    
                                                                                                    
                            
    env.push(("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()));
                                                                                                
                                      
    env.push(("GIT_NO_LAZY_FETCH".to_string(), "1".to_string()));
    env.extend((step.compose_env)(records, values));
    env
}

                                                                                                    

/// What the loop decides to do with one step, BEFORE any child runs. Pure: it reads the records,
/// the probes and the typed invocation, and touches nothing. Separating it from the loop is what
/// lets the arms drive every step's decision without a host that can satisfy S1..S9.
#[derive(Debug)]
pub enum StepDisposition {
                                   
    Skip(String),
    /// Ready to execute; the reason it is not done rides along for the progress line.
    Execute(String),
                                   
    Owed(Box<OwedStop>),
                                                                   
    Refuse(Box<Refusal>),
}

                                                                          
/// destructive gate. The done decision is re-evaluated HERE, at step time, not read from the
                                                                                                  
pub fn step_disposition(
    step: &Step,
    probe_ctx: &ProbeCtx,
    values: &ParamValues,
    records: &RunRecords,
    measured: &super::admission::Measured,
    inv: &RunInvocation,
    ctx: &ResolvedContext,
) -> StepDisposition {
    let why = match step_done(step, probe_ctx, values, records, measured) {
        DoneResult::Done => return StepDisposition::Skip(String::new()),
        DoneResult::NotDone(why) | DoneResult::Unevaluable(why) => why,
    };
    for probe in step.preconditions {
        if probe.subject == SubjectOrigin::CeremonyImmutable {
            continue;
        }
        let result = (probe.run)(probe_ctx);
        if matches!(result, ProbeResult::Met) {
            continue;
        }
        let cond = UnmetPrecondition::from_probe(probe, result, Some(inv.resume_command(ctx)));
        let detail = cond.detail();
        let refusal = Refusal::typed(RefusalId::PreconditionUnmet, detail, &cond);
                                                                                           
                                                                                            
        return if step.executor == ExecutorClass::ExternalChecklist {
            StepDisposition::Owed(Box::new(OwedStop::new(
                OwedKind::ExternalChecklistStop,
                refusal,
            )))
        } else {
            StepDisposition::Refuse(Box::new(refusal))
        };
    }
    if let Some(owed) = typed_destructive_gate(step, inv, ctx) {
        return StepDisposition::Owed(Box::new(owed));
    }
    StepDisposition::Execute(why)
}

                                                                                                
/// invocation. Its own function because the gate is reached only AFTER the step's preconditions
                                                                                  
/// so the gate's own behaviour is held here, and the integration through S10's disposition is
/// held once that precondition can pass.
pub fn typed_destructive_gate(
    step: &Step,
    inv: &RunInvocation,
    ctx: &ResolvedContext,
) -> Option<OwedStop> {
    if !step.destructive() || inv.wipe_confirmed {
        return None;
    }
    let resume = inv.with_wipe_confirmed().resume_command(ctx);
    Some(OwedStop::new(
        OwedKind::TypedGateStop,
        Refusal::new(
            RefusalId::DestructiveTokenNotTyped,
            format!(
                "{} is destructive and this invocation carries no typed authorization",
                step.id.token()
            ),
        )
        .with_cure_extra(format!("resume with: {resume}")),
    ))
}

                                                                     
                                                                                          
pub fn run_ceremony(
    admitted: &Admitted,
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    profile: &crate::deploy::profile::Profile,
    records: &mut RunRecords,
    deps: &mut RunnerDeps<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reporter = deps.reporter;
    let lock_token = deps.lock_token;
    let mut gate_settled = false;
                                                                                       
                                                                     
    let mut executed: Vec<StepId> = Vec::new();
                                                                                           
                                                                                            
                                                                                                
                                                                               
    let mut measured = admitted.measured.clone();
    for step in SPINE.iter() {
                                                                                            
                                                                                              
                                                                                                
                                          
        let probe_ctx = ProbeCtx::new(ctx, Some(profile.clone()))
            .with_values(admitted.values.clone())
            .with_run_paths(staged_image_of(records), records.dir().to_path_buf());
        let why = match step_disposition(
            step,
            &probe_ctx,
            &admitted.values,
            records,
            &measured,
            inv,
            ctx,
        ) {
            StepDisposition::Skip(_) => {
                reporter.step(step, "skip", "");
                continue;
            }
            StepDisposition::Owed(owed) => {
                reporter.owed(step, owed.refusal.cure().as_str());
                return Err(owed);
            }
            StepDisposition::Refuse(r) => return Err(r),
            StepDisposition::Execute(why) => why,
        };
        reporter.step(step, "run", &why);
                                                                                             
                                                       
        sibling_gate(step, inv, ctx, profile, reporter)?;
                                                                                              
                                                                                                  
                
        if step.requires_clean_tree && !gate_settled {
            gate_settled = true;
            if executing_gate(&executed, inv, ctx, records, deps)? == GateEffect::Committed {
                measured = super::admission::measure(&ctx.repo_root);
            }
        }
        if step.executor == ExecutorClass::ExternalChecklist {
                                                                                                
                                                                                          
                                                                                                  
            step_completion(step, admitted, ctx, records, inv)?;
            record_step(step, admitted, &probe_ctx, &measured, ctx, records)?;
            executed.push(step.id);
            continue;
        }
                                                                                                   
                                                                                                 
                                                                                               
                                                                                                     
                                           
        let dirty_before = match super::admission::git_dirty_paths(&ctx.repo_root) {
            super::admission::DirtScan::Scanned(v) => v,
            super::admission::DirtScan::Unevaluable(_) => vec![],
        };
        let mut open_tokens = Vec::new();
        for spec in step.executing_repo_writes() {
                                                                                                  
                                                                                                 
                                                                                     
            if !spec.ends_with('/') {
                open_tokens.push(super::records::open_path_record(
                    records,
                    &ctx.repo_root.to_path_buf().join(spec),
                )?);
            }
        }
        for call in child_invocations(step, &admitted.values, inv, ctx, records)? {
            let env = child_env(
                step,
                lock_token,
                &ctx.artifact_store,
                records,
                &admitted.values,
            );
            let call = ChildCall {
                step: step.id,
                program: call.program,
                args: call.args,
                cwd: ChildCwd::At(ctx.repo_root.to_path_buf()),
                env,
                inherit_stdio: !reporter.porcelain,
            };
            let outcome = deps
                .exec
                .run(&call, &mut |line| reporter.detail(step, line));
            match outcome {
                ChildOutcome::Ok => {}
                ChildOutcome::Failed(detail) => {
                    reporter.detail(step, &detail);
                    return Err(Box::new(
                        Refusal::new(
                            RefusalId::StepFailed,
                            format!("{} failed: {detail}", step.id.token()),
                        )
                        .with_cure_extra(format!(
                            "fix what the step reported, then resume with: {}",
                            inv.resume_command(ctx)
                        )),
                    ));
                }
            }
        }
        for tok in open_tokens {
            super::records::finalize_path_record(records, tok)?;
        }
        record_directory_writes(step, ctx, &dirty_before, records)?;
        step_completion(step, admitted, ctx, records, inv)?;
        record_step(step, admitted, &probe_ctx, &measured, ctx, records)?;
        executed.push(step.id);
    }
                                                                                                   
                                                                                             
    if !gate_settled {
        executing_gate(&executed, inv, ctx, records, deps)?;
    }
    Ok(())
}

/// After a step, record the files its DIRECTORY-shaped declared writes touched. The pre-state
/// comes from git HEAD, so the entry says what the step changed relative to the committed tree.
fn record_directory_writes(
    step: &Step,
    ctx: &ResolvedContext,
    before: &[String],
    records: &mut RunRecords,
) -> Result<(), Box<dyn std::error::Error>> {
    let dirs: Vec<&str> = step
        .executing_repo_writes()
        .filter(|s| s.ends_with('/'))
        .collect();
    if dirs.is_empty() {
        return Ok(());
    }
                                                                                                    
                                                                                                 
                                            
    let dirty = match super::admission::git_dirty_paths(&ctx.repo_root) {
        super::admission::DirtScan::Scanned(v) => v,
        super::admission::DirtScan::Unevaluable(_) => vec![],
    };
    for rel in dirty {
                                                                                               
                                                                                       
        if !dirs.iter().any(|d| {
            let dir = d.trim_end_matches('/');
            rel == dir || rel.starts_with(&format!("{dir}/"))
        }) {
            continue;
        }
                                                                                                
                                                                                                  
                                                                                              
                                                                                            
                                      
        if before.contains(&rel) {
            continue;
        }
        let pre = super::records::head_content_state(&ctx.repo_root, &rel);
        super::records::record_completed_write(
            records,
            &ctx.repo_root.to_path_buf().join(&rel),
            pre,
        )?;
    }
    Ok(())
}

                                                                                
                                                                                                     
                                
fn gate_dirt(
    root: &std::path::Path,
    subject: &str,
    purpose: &str,
    read_purpose: super::refusal::GitReadPurpose,
) -> Result<Vec<String>, Refusal> {
    match super::admission::git_dirty_paths(root) {
        super::admission::DirtScan::Scanned(v) => Ok(v),
        super::admission::DirtScan::Unevaluable(outcome) => {
            let detail = format!("cannot read {subject}'s git state to {purpose}: {outcome}");
            Err(Refusal::typed(
                RefusalId::GitStateUnreadable,
                detail,
                &GitReadFailure {
                    purpose: read_purpose,
                    outcome,
                },
            ))
        }
    }
}

                                                                                              
                                                                                       
/// otherwise. Unrelated sibling dirt is never read and never blocks.
pub fn sibling_gate(
    step: &Step,
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    profile: &crate::deploy::profile::Profile,
    reporter: &Reporter,
) -> Result<(), Box<dyn std::error::Error>> {
    for (sibling, spec) in step.sibling_writes() {
        let super::spine::SiblingId::TenantRepo = sibling;
        let root = tenant_repo_root(ctx, profile)?;
                                                                                        
        super::gate_commit::check_repository_contract(
            &root,
            &inv.ratified_file(&ctx.repo_root, super::spine::SiblingId::TenantRepo.token()),
            super::spine::SiblingId::TenantRepo.token(),
            &inv.admit_command(ctx),
            super::refusal::GitReadPurpose::SiblingCheckout,
        )?;
        let file = root.join(spec);
        let scanned = gate_dirt(
            &root,
            &format!("the sibling checkout {}", root.display()),
            &format!("check for an overwrite of {spec:?}"),
            super::refusal::GitReadPurpose::SiblingCheckout,
        )?;
        let dirty = scanned
            .into_iter()
            .filter(|p| p == spec)
            .map(|p| {
                let ok = super::records::sibling_output_recognized(&ctx.artifact_store, &file);
                (p, ok)
            })
            .collect::<Vec<_>>();
        let unrecognized: Vec<String> = dirty
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(p, _)| p.clone())
            .collect();
                                                                                                 
                                                                                                 
        let disclosure = if unrecognized.is_empty() {
            String::new()
        } else {
            let rows: Vec<super::disclosure::GateRow> = unrecognized
                .iter()
                .map(|p| super::disclosure::GateRow::Sibling {
                    path: DeclaredPathName::new((*p).to_string()),
                    len: std::fs::metadata(root.join(p)).ok().map(|m| m.len()),
                })
                .collect();
            super::disclosure::render_rows(&rows)
        };
        match super::consent::decide_sibling("tenant", &dirty, &root, &disclosure) {
            super::consent::SiblingDecision::Proceed { owed } => {
                for cmd in owed {
                    reporter.owed(step, &cmd);
                }
            }
            super::consent::SiblingDecision::Stop(stop) => return Err(stop),
        }
    }
    Ok(())
}

pub fn tenant_repo_root(
    ctx: &ResolvedContext,
    profile: &crate::deploy::profile::Profile,
) -> Result<PathBuf, Refusal> {
    let name = profile
        .tenant_repo
        .clone()
        .unwrap_or_else(|| super::spine::CEREMONY_TENANT_REPO.to_string());
    let manifest = recipes_image_builder::repo_manifest::RepoManifest::load(&ctx.repo_manifest)
        .map_err(|e| {
            Refusal::new(
                RefusalId::RepoManifestUnusable,
                format!(
                    "cannot read the repo-manifest {} to locate the tenant checkout `{name}` \
                     before S6 overwrites its declared paths: {e}",
                    ctx.repo_manifest.display()
                ),
            )
        })?;
    manifest.repo_path(&name, &ctx.repo_root).ok_or_else(|| {
        Refusal::new(
            RefusalId::RepoManifestUnusable,
            format!(
                "the repo-manifest names no tenant checkout `{name}` for the ceremony to examine \
                 before S6 re-pins it; declare it or set `tenant_repo`"
            ),
        )
    })
}

/// Whether the gate moved HEAD (the caller re-measures when it did).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateEffect {
    Unchanged,
    Committed,
}

                                                                                                
/// run records. Nothing commits except through this gate; the commit is the §3 construction over
                                           
fn executing_gate(
    executed: &[StepId],
    inv: &RunInvocation,
    ctx: &ResolvedContext,
    records: &mut RunRecords,
    deps: &mut RunnerDeps<'_>,
) -> Result<GateEffect, Box<dyn std::error::Error>> {
                                                                                                 
                          
    super::gate_commit::check_repository_contract(
        &ctx.repo_root,
        &inv.ratified_file(&ctx.repo_root, "executing"),
        "executing",
        &inv.admit_command(ctx),
        super::refusal::GitReadPurpose::CommitGate,
    )?;
    let dirty = gate_dirt(
        &ctx.repo_root,
        &format!("the checkout {}", ctx.repo_root.display()),
        "decide the commit gate",
        super::refusal::GitReadPurpose::CommitGate,
    )?;
    let mut owed: Vec<(DeclaredPathName, super::records::DirtClass)> = Vec::new();
                                                                                 
                                                                                            
    let mut witnesses: std::collections::BTreeMap<DeclaredPathName, super::records::PathWitness> =
        std::collections::BTreeMap::new();
    for p in dirty
        .into_iter()
        .filter(|p| super::admission::is_declared(p))
    {
        let abspath = ctx.repo_root.to_path_buf().join(&p);
        let (class, witness) = super::records::classify_and_witness(records, &abspath);
        let name = DeclaredPathName::new(p);
        if let Some(w) = witness {
            witnesses.insert(name.clone(), w);
        }
        owed.push((name, class));
    }
    let resume = inv.resume_command(ctx);
    let resume_with_commit = inv.with_commit().resume_command(ctx);
    let owed_paths: Vec<&str> = owed.iter().map(|(p, _)| p.as_str()).collect();
    let profile_name = inv
        .profile_path
        .as_path()
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "box".to_string());
    let steps: Vec<&str> = executed.iter().map(|id| id.token()).collect();
                                                                                            
                                                                                                     
                                                                                             
                                                                                                  
                                                                                                 
    let mut prepared = None;
    let mut discards: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if !owed.is_empty() && owed.iter().all(|(_, c)| c.speakable()) {
        super::records::refuse_unmerged_owed_paths(&ctx.repo_root, &owed_paths)?;
        super::gate_commit::refuse_if_in_progress(&ctx.repo_root)?;
        prepared = Some(super::gate_commit::prepare(
            &ctx.repo_root,
            records.dir(),
            records,
            &owed,
            &witnesses,
        )?);
        discards = super::disclosure::discard_set(&ctx.repo_root, &owed_paths)?;
    }
                                                                                     
    let rows = executing_rows(&owed, &witnesses, records.run_id());
    let mut disclosure_text = super::disclosure::render_rows(&rows);
    if !discards.is_empty() {
        disclosure_text.push_str(&format!(
            "\n staged edit(s) the commit overwrites: {}",
            super::disclosure::render_overwrite_set(&discards)
        ));
    }
    let repo_root = ctx.repo_root.clone();
    let decision = super::consent::decide_executing_gate(
        &owed,
        deps.is_tty,
        inv.commit,
        || {
                                                                                                  
            super::emit::emit_stdout(&format!("{disclosure_text}\n"));
            Ok((deps.prompt)())
        },
        &resume,
        &resume_with_commit,
    );
    let internal_no_prepared = || -> Box<dyn std::error::Error> {
        Box::new(Refusal::new(
            RefusalId::InternalInvariantViolated,
            "the gate reached a commit decision with no constructed tree",
        ))
    };
    match decision {
        super::consent::GateDecision::Proceed => Ok(GateEffect::Unchanged),
        super::consent::GateDecision::Stop(stop) => Err(stop),
        super::consent::GateDecision::Refuse(r) => Err(r),
        super::consent::GateDecision::Commit {
            paths,
            disclosure_shown,
        } => {
                                                                                                     
                                                                                                    
                                                                                                     
                                                                                           
            if !disclosure_shown && !discards.is_empty() {
                super::emit::emit_stdout(&format!(
                    " staged edit(s) the commit overwrites: {}\n",
                    super::disclosure::render_overwrite_set(&discards)
                ));
            }
            let message = super::consent::commit_message(&profile_name, &steps, &paths);
            let prepared = prepared.ok_or_else(internal_no_prepared)?;
            super::gate_commit::commit(&repo_root, &prepared, &message, &profile_name)?;
            Ok(GateEffect::Committed)
        }
        super::consent::GateDecision::EditThenCommit { paths, declined } => {
            let base = super::consent::commit_message(&profile_name, &steps, &paths);
            match crate::deploy::git_commit::edit_message_with(deps.editor, &base) {
                crate::deploy::git_commit::EditOutcome::Edited(m) => {
                    let prepared = prepared.ok_or_else(internal_no_prepared)?;
                    super::gate_commit::commit(&repo_root, &prepared, &m, &profile_name)?;
                    Ok(GateEffect::Committed)
                }
                crate::deploy::git_commit::EditOutcome::Aborted => {
                    Err(super::consent::edit_aborted_stop(
                        declined,
                        &paths,
                        &resume,
                        &resume_with_commit,
                    ))
                }
            }
        }
    }
}

/// The record-view rows for the executing gate, from the classifier's witnesses (no git reads). A
/// path with no witness (an unspeakable member that never reaches the rendered prompt) renders
/// without a run/sha, a defensive fallback.
fn executing_rows(
    owed: &[(DeclaredPathName, super::records::DirtClass)],
    witnesses: &std::collections::BTreeMap<DeclaredPathName, super::records::PathWitness>,
    this_run_id: &str,
) -> Vec<super::disclosure::GateRow> {
    use super::records::ContentState;
    owed.iter()
        .map(|(p, class)| {
            let (run_id, this_run, sha_prefix, len) = match witnesses.get(p) {
                Some(w) => {
                    let sha = match &w.post {
                        ContentState::Sha256 { sha256, .. } => {
                            sha256.chars().take(12).collect::<String>()
                        }
                        ContentState::Absent => String::new(),
                    };
                    (w.run_id.clone(), w.run_id == this_run_id, sha, w.len)
                }
                None => (String::new(), false, String::new(), None),
            };
            super::disclosure::GateRow::Executing {
                path: p.clone(),
                class: *class,
                run_id,
                this_run,
                sha_prefix,
                len,
            }
        })
        .collect()
}

/// S7's recorded image, when S7 has run. The one place the runner resolves it; S10's precondition
/// and S10's composed `--image` both read the record, never a naming convention.
pub fn staged_image_of(records: &RunRecords) -> Option<PathBuf> {
    records
        .step_record(StepId::S7ImageBuild.token())
        .and_then(|r| r.produced.get("img"))
        .map(|a| PathBuf::from(&a.path))
}

                                                                                
/// read their image from `RECIPES_{DRYRUN,PROD}_IMG` and the prod privkey from
/// `RECIPES_PROD_PRIVKEY`, and PANIC without them (the M-α no-false-green guard), so a real
/// `orchard run` could not gate its own image without an undocumented manual export. The runner has
/// both values — S7's recorded image (`staged_image_of`) and the resolved `box_login_identity` — so
/// it sets them. A WRONG export still refuses at `adopt_gate_record` (the record binds the recorded
/// image, `GateRecordMissing`), so this only supplies the RIGHT value, never overrides a check.
/// Empty when the image is not yet recorded: S8 does not run before S7 records it.
pub fn s8_child_env(records: &RunRecords, values: &ParamValues) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(img) = staged_image_of(records) {
        let img = img.display().to_string();
        env.push(("RECIPES_DRYRUN_IMG".to_string(), img.clone()));
        env.push(("RECIPES_PROD_IMG".to_string(), img));
    }
    if let Some(privkey) = values.get("box_login_identity") {
        env.push(("RECIPES_PROD_PRIVKEY".to_string(), privkey.to_string()));
    }
    env
}

/// A `RequiredParamMissing` for a spine parameter named at a step-time backstop. The record is
/// resolved from the spine by name; a name with no spine entry (a rename leaving the backstop
/// behind) is an internal invariant, not an operator-fixable artifact.
fn missing_param_refusal(name: &'static str, detail: &str) -> Box<dyn std::error::Error> {
    match super::admission::spine_param(name) {
        Some(p) => Box::new(Refusal::typed(
            RefusalId::RequiredParamMissing,
            detail.to_string(),
            &MissingParam {
                name: p.name,
                class: p.class,
            },
        )),
        None => Box::new(Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!("required param `{name}` has no spine entry (a rename left a backstop behind)"),
        )),
    }
}

/// What a step owes BEYOND its own execution, at the moment it completes. Two steps have one:
/// S5 binds the quiescent handoff tree it accepted, and S8 ADOPTS the gate record from beside the
                                                                                                   
/// and clearing an out_dir between S8 and S10 is routine).
pub fn step_completion(
    step: &Step,
    admitted: &Admitted,
    ctx: &ResolvedContext,
    records: &mut RunRecords,
    inv: &RunInvocation,
) -> Result<(), Box<dyn std::error::Error>> {
    if step.id == StepId::S8BootGate {
        let img = staged_image_of(records).ok_or_else(|| {
            Refusal::new(
                RefusalId::StepInputMissing,
                "s8-boot-gate completed but this profile's records name no image for it to have \
                 gated",
            )
            .with_cure_extra(super::records::records_dir_cure(records.dir()))
        })?;
        super::gate_record::adopt_gate_record(&img, records.dir())?;
        return Ok(());
    }
    if step.id == StepId::S6TenantRepin {
        if admitted.values.get("tenant_artifacts").is_none() {
            return Err(missing_param_refusal(
                "tenant_artifacts",
                "s6-tenant-repin needs `tenant_artifacts` (the kind:key artifacts to re-pin); \
                 absent, S6 composes no `market upgrade` and would record DONE having re-pinned \
                 nothing",
            ));
        }
        return Ok(());
    }
    if step.id != StepId::S5TenantPublish {
        return Ok(());
    }
    let root = std::path::Path::new(super::spine::HANDOFF_ROOT);
    let tree_hash = match super::handoff::quiescent(root) {
        Ok(h) => h,
        Err(ProbeResult::Met) => unreachable!("quiescent returns Err only for a failed probe"),
        Err(other) => {
            let cond = UnmetPrecondition::named(
                "tenant-handoff-quiescent",
                "the tenant handoff tree is quiescent",
                other,
                Some(inv.resume_command(ctx)),
            );
            return Err(Box::new(OwedStop::new(
                OwedKind::ExternalChecklistStop,
                Refusal::typed(RefusalId::PreconditionUnmet, cond.detail(), &cond),
            )));
        }
    };
                                                                                           
                                                                        
    let tenant_source_ref = admitted
        .values
        .get("tenant_source_ref")
        .ok_or_else(|| {
            missing_param_refusal(
                "tenant_source_ref",
                "s5-tenant-publish needs `tenant_source_ref` — the tenant commit the publish was \
                 built from — and neither the invocation nor the profile supplies one",
            )
        })?
        .to_string();
    records.record_s5_confirmation(super::records::S5Confirmation {
        tree_hash,
        tenant_source_ref,
    })?;
    Ok(())
}

                                                                                        
/// identity the runner can derive. Produced artifacts are recorded by the step-specific writers
/// (S7's image triple) once those land; a step recording none is decided by its parameters,
/// identities and `artifact_present` probe alone.
fn record_step(
    step: &Step,
    admitted: &Admitted,
    probe_ctx: &ProbeCtx,
    measured: &super::admission::Measured,
    ctx: &ResolvedContext,
    records: &mut RunRecords,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = std::collections::BTreeMap::new();
    for p in step.params {
        if let Some(v) = admitted.values.get(p.name) {
            params.insert(p.name.to_string(), v.to_string());
        }
    }
    let mut identities = std::collections::BTreeMap::new();
    for id in step.input_identities {
        if let Some(v) =
            super::admission::identity_value(id.id, probe_ctx, &admitted.values, measured)
        {
            identities.insert(id.id.to_string(), v);
        }
    }
    let records_dir = records.dir().to_path_buf();
    let produced = produced_artifacts(step, &admitted.values, ctx, measured, &records_dir)?;
    records.record_step(StepRecord {
        step: step.id.token().to_string(),
        run_id: records.run_id().to_string(),
        params,
        input_identities: identities,
        produced,
    })?;
    Ok(())
}

                                                                                           
/// the step's own parameters and records them, so nothing downstream re-derives a naming
                                                                                      
///
/// S7 and S8 are the producing steps: S7's image triple, and S8's ADOPTED gate record. S7's triple is named
/// `recipes-image-<label>.{img,layout.toml,sha256,vmlinuz,initramfs}` under `out_dir`, with the
/// base name from image-builder's own `image_output_base` — the one home of that convention — and
/// the label from the ceremony HEAD the build consumed. FAIL-CLOSED: a step that reported success
/// without leaving its triple where it must be is an error, not an empty `produced` map that
/// would make the step SKIP forever.
pub fn produced_artifacts(
    step: &Step,
    values: &ParamValues,
    ctx: &ResolvedContext,
    measured: &super::admission::Measured,
    records_dir: &std::path::Path,
) -> Result<
    std::collections::BTreeMap<String, super::records::ProducedArtifact>,
    Box<dyn std::error::Error>,
> {
    use super::records::ProducedArtifact;
    let mut out = std::collections::BTreeMap::new();
    if step.id == StepId::S8BootGate {
                                                                                                  
                                                                                               
                                                                                       
        let path = super::gate_record::profile_gate_record_path(records_dir);
        if !path.exists() {
            return Err(Box::new(Refusal::new(
                RefusalId::GateRecordMissing,
                format!(
                    "s8-boot-gate completed but no gate record was adopted at {}",
                    path.display()
                ),
            )));
        }
        out.insert(
            "gate-record".to_string(),
            super::records::ProducedArtifact {
                sha256: file_sha256(&path).unwrap_or_default(),
                path: path.display().to_string(),
            },
        );
        return Ok(out);
    }
    if step.id != StepId::S7ImageBuild {
        return Ok(out);
    }
    let label = measured.head.clone().ok_or_else(|| {
        Refusal::typed(
            RefusalId::GitStateUnreadable,
            "s7-image-build produced an image but the ceremony checkout's HEAD could not be read, \
             so the artifact cannot be named",
            &GitReadFailure {
                purpose: GitReadPurpose::ArtifactNaming,
                outcome: GitRunError::Spawn {
                    op: "rev-parse HEAD".to_string(),
                    err: "the ceremony checkout's HEAD was not measured".to_string(),
                },
            },
        )
    })?;
    let out_dir = std::path::PathBuf::from(
        values
            .get("out_dir")
            .unwrap_or(crate::deploy::build_image::DEFAULT_OUT_DIR),
    );
    let base = recipes_image_builder::image::image_output_base(&label);
    let _ = ctx;
    for (name, ext, sidecar) in [
        ("img", "img", Some("sha256")),
        ("layout", "layout.toml", None),
        ("vmlinuz", "vmlinuz", Some("vmlinuz.sha256")),
        ("initramfs", "initramfs", Some("initramfs.sha256")),
    ] {
        let path = out_dir.join(format!("{base}.{ext}"));
        if !path.exists() {
            return Err(Box::new(
                Refusal::new(
                    RefusalId::StepFailed,
                    format!(
                        "s7-image-build reported success but {} is not there",
                        path.display()
                    ),
                )
                .with_cure_extra(
                    "check the build's own output above; the image triple is named from the \
                     ceremony checkout's HEAD and the resolved out_dir"
                        .to_string(),
                ),
            ));
        }
                                                                                              
                                                                                          
        let sha256 = match sidecar {
            Some(suffix) => {
                super::gate_record::read_sha256_sidecar(&out_dir.join(format!("{base}.{suffix}")))
                    .unwrap_or_default()
            }
            None => file_sha256(&path).unwrap_or_default(),
        };
        out.insert(
            name.to_string(),
            ProducedArtifact {
                path: path.display().to_string(),
                sha256,
            },
        );
    }
    Ok(out)
}

fn file_sha256(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    Some(hex::encode(Sha256::digest(std::fs::read(path).ok()?)))
}

/// The production executor: spawns the composed child, wiring the I/O regime the call declares.
pub struct ProcessExecutor;

impl Executor for ProcessExecutor {
    fn run(&mut self, call: &ChildCall, sink: &mut dyn FnMut(&str)) -> ChildOutcome {
        let program: PathBuf = match &call.program {
            Program::SelfExe => match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => return ChildOutcome::Failed(format!("cannot locate this binary: {e}")),
            },
            Program::External(name) => PathBuf::from(name),
        };
        let mut cmd = std::process::Command::new(&program);
        cmd.args(&call.args);
        if let ChildCwd::At(dir) = &call.cwd {
            cmd.current_dir(dir);
        }
        for (k, v) in &call.env {
            cmd.env(k, v);
        }
        if call.inherit_stdio {
            cmd.stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .stdin(std::process::Stdio::inherit());
            return match cmd.status() {
                Ok(s) if s.success() => ChildOutcome::Ok,
                Ok(s) => ChildOutcome::Failed(exit_detail(&program, s)),
                Err(e) => ChildOutcome::Failed(format!("spawn {}: {e}", program.display())),
            };
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return ChildOutcome::Failed(format!("spawn {}: {e}", program.display())),
        };
                                                                                                
                                                                                  
        let err_handle = child.stderr.take().map(|err| {
            std::thread::spawn(move || {
                use std::io::BufRead as _;
                std::io::BufReader::new(err)
                    .lines()
                    .map_while(Result::ok)
                    .collect::<Vec<_>>()
            })
        });
        if let Some(out) = child.stdout.take() {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                sink(&line);
            }
        }
        let stderr_lines = err_handle.and_then(|h| h.join().ok()).unwrap_or_default();
        for line in &stderr_lines {
            sink(line);
        }
        match child.wait() {
            Ok(s) if s.success() => ChildOutcome::Ok,
            Ok(s) => ChildOutcome::Failed(exit_detail(&program, s)),
            Err(e) => ChildOutcome::Failed(format!("wait for {}: {e}", program.display())),
        }
    }
}

fn exit_detail(program: &std::path::Path, status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(c) => format!("{} exited {c}", program.display()),
        None => format!("{} was terminated by a signal", program.display()),
    }
}
