                                                                                                  
//! borrowed getters over resolved paths + the loaded profile — no `&mut` API, no process/command
//! capability. The attached `ParamValues` carries an interior-mutable access log that `value`
                                                                                   
                                                                                              
//! fn-pointer signatures; the type shape is the construction half.

use std::path::{Path, PathBuf};

use crate::deploy::context::ResolvedContext;
use crate::deploy::profile::Profile;

                                                       
#[derive(Debug, Clone)]
pub struct ProbeCtx {
    repo_root: PathBuf,
    artifact_store: PathBuf,
    repo_manifest: PathBuf,
    profile: Option<Profile>,
    /// The image S10 would stage — S7's recorded product. Runner-supplied; a probe that needs it
    /// reports unevaluable without it, which is fail-closed NOT-ready.
    staged_image: Option<PathBuf>,
                                                                                 
    records_dir: Option<PathBuf>,
    /// The RESOLVED ceremony parameters (typed > profile), when the runner supplies them. A
    /// probe reads its subject's declared value from here rather than re-deriving it from the
    /// profile plus a literal default, so a ceremony declaring a non-default value is probed
                                            
    values: Option<super::param::ParamValues>,
                                                                                                
    /// self-test can drive a precondition over populated values and log its value-gated reads
    /// without an SSH attempt. False in production.
    seam_network: bool,
}

impl ProbeCtx {
    pub fn new(ctx: &ResolvedContext, profile: Option<Profile>) -> Self {
        ProbeCtx {
            repo_root: ctx.repo_root.to_path_buf(),
            artifact_store: ctx.artifact_store.to_path_buf(),
            repo_manifest: ctx.repo_manifest.to_path_buf(),
            profile,
            staged_image: None,
            records_dir: None,
            values: None,
            seam_network: false,
        }
    }

    /// Attach the paths only the runner knows: S7's recorded image and the profile's records dir.
    pub fn with_run_paths(mut self, staged_image: Option<PathBuf>, records_dir: PathBuf) -> Self {
        self.staged_image = staged_image;
        self.records_dir = Some(records_dir);
        self
    }

    pub fn staged_image(&self) -> Option<&Path> {
        self.staged_image.as_deref()
    }

    pub fn records_dir(&self) -> Option<&Path> {
        self.records_dir.as_deref()
    }

    /// Attach the resolved parameter set (the runner's constructor).
    pub fn with_values(mut self, values: super::param::ParamValues) -> Self {
        self.values = Some(values);
        self
    }

                                                                                                
    /// populated values with this set, so value-gated reads are logged without an SSH attempt.
    pub fn with_network_seam(mut self) -> Self {
        self.seam_network = true;
        self
    }

    /// Whether a probe should skip its network attempt (see [`with_network_seam`]).
    pub fn network_seamed(&self) -> bool {
        self.seam_network
    }

    /// One resolved parameter value, when the runner attached the set.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.as_ref().and_then(|v| v.get(name))
    }

                                                                                             
    /// self-test that a precondition or done-probe touches only its step's declared params: the
    /// access log lives in the attached `ParamValues` (interior-mutable), and `value` reaches it
    /// through `ParamValues::get`. Empty when no set is attached.
    pub fn accessed_names(&self) -> std::collections::BTreeSet<String> {
        self.values
            .as_ref()
            .map(|v| v.accessed_names())
            .unwrap_or_default()
    }

    /// A fixture constructor for tests and non-context probes (paths only).
    pub fn from_paths(repo_root: PathBuf, artifact_store: PathBuf, repo_manifest: PathBuf) -> Self {
        ProbeCtx {
            repo_root,
            artifact_store,
            repo_manifest,
            profile: None,
            staged_image: None,
            records_dir: None,
            values: None,
            seam_network: false,
        }
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }
    pub fn artifact_store(&self) -> &Path {
        &self.artifact_store
    }
    pub fn repo_manifest(&self) -> &Path {
        &self.repo_manifest
    }
    pub fn profile(&self) -> Option<&Profile> {
        self.profile.as_ref()
    }
}

/// A precondition probe's outcome. `Unevaluable` carries the reason and NEVER counts as met
                             
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    Met,
    /// Unmet, with the cure (what the operator does to meet it).
    Unmet(String),
    /// The probe could not run; the reason is reported, the step counts not-ready.
    Unevaluable(String),
}

                                                                                               
                      
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoneResult {
    Done,
    NotDone(String),
    Unevaluable(String),
}

                                                                                            
/// subject no ceremony step produces is evaluable BEFORE the first mutation and runs at
/// admission; a precondition over a step PRODUCT can only be evaluated once that step has run,
/// so it runs at its own step. Declared as spine data rather than decided by the runner, so the
/// split is checkable: `ceremony_selftests::precondition_subjects_precede_their_consumers`
/// asserts a named producer step precedes every step declaring the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectOrigin {
    /// No ceremony step produces this subject (the operator or the host supplies it).
    CeremonyImmutable,
    /// The named step produces it; the probe evaluates at its own step, never at admission.
    StepProduct(super::spine::StepId),
}

/// A named precondition probe (spine data).
#[derive(Clone, Copy)]
pub struct Probe {
    pub id: &'static str,
    pub explain: &'static str,
    pub subject: SubjectOrigin,
    pub run: fn(&ProbeCtx) -> ProbeResult,
}

impl std::fmt::Debug for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Probe").field("id", &self.id).finish()
    }
}

                                                                                         
/// produces is still there"). The identity- and parameter-bound half is the run records', and the
/// runner ANDs the two (`ceremony::admission::step_done`). A step whose product the runner cannot
/// probe on the host declares `artifact_present: None` — there is no vacuously-`Done` probe body.
#[derive(Clone, Copy)]
pub struct DoneProbe {
    pub id: &'static str,
    pub run: fn(&ProbeCtx, &super::param::ParamValues) -> DoneResult,
}

impl std::fmt::Debug for DoneProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoneProbe").field("id", &self.id).finish()
    }
}
