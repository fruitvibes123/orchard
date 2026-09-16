                                                                       
//! type carrying id + cure + detail; there is no cureless constructor. Cure TOTALITY is
//! compile-shaped: the id→cure-source match inside the `refusal_ids!` macro is total over the
                                                                                               
//! every rendered cure is non-empty (`tests/ceremony_selftests.rs`).
//!
                                                                                                
//! over the NEW surface; O1's C4-2026-07 rule covers the old ones, extended in Task 10).

/// Why the ceremony was reading git state when a `git-state-unreadable` refusal was constructed.
/// Selects the cure by total match (decision 2026-09-01-condition-typed-cures). A new purpose must
/// choose its cure here to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitReadPurpose {
                                                    
    CommitGate,
                                                           
    SiblingCheckout,
    /// S7's HEAD read that names the produced image artifact.
    ArtifactNaming,
}

impl GitReadPurpose {
    pub fn cure(self) -> &'static str {
        match self {
            GitReadPurpose::CommitGate => {
                "the ceremony could not read the checkout's git state for its commit gate; run \
                 from the checkout the ceremony was invoked on, with `git` on PATH"
            }
            GitReadPurpose::SiblingCheckout => {
                "the ceremony could not read the sibling checkout's git state for its sibling \
                 gate; run from the checkout the ceremony was invoked on, with `git` on PATH"
            }
            GitReadPurpose::ArtifactNaming => {
                "the ceremony reads HEAD to name the S7 artifact; run against the git checkout the \
                 ceremony was invoked on, with git on PATH"
            }
        }
    }

    /// The read's purpose named in a `GitReadFailure` Exit cure.
    pub fn what(self) -> &'static str {
        match self {
            GitReadPurpose::CommitGate => "the commit gate",
            GitReadPurpose::SiblingCheckout => "the sibling gate",
            GitReadPurpose::ArtifactNaming => "the S7 artifact naming",
        }
    }
}

/// Derived ids reach their cure only through this trait (decision 2026-09-01-condition-typed-cures).
pub trait TypedCure {
    fn cure(&self) -> String;
}

/// A ceremony git command failed to spawn, or ran and exited non-zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRunError {
    Spawn {
        op: String,
        err: String,
    },
    Exit {
        op: String,
        status: String,
        stderr: String,
    },
    /// The command ran and exited zero, but the output (or a field of it) the site decodes as text
    /// is not UTF-8. `sample` is the offending record (`escape_ascii`, cut to 120 characters).
    NonUtf8Output {
        op: String,
        sample: String,
    },
}

impl std::fmt::Display for GitRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitRunError::Spawn { op, err } => write!(f, "`git {op}` could not run: {err}"),
            GitRunError::Exit { op, status, stderr } => {
                write!(f, "`git {op}` failed ({status}): {stderr}")
            }
            GitRunError::NonUtf8Output { op, sample } => {
                write!(f, "`git {op}` emitted bytes outside UTF-8 ({sample})")
            }
        }
    }
}

/// A git read that failed, typed by why it ran and how it failed. `Spawn` gives the purpose's
/// git-on-PATH remedy; `Exit` sends the operator to git's own line in the detail.
pub(in crate::ceremony) struct GitReadFailure {
    pub purpose: GitReadPurpose,
    pub outcome: GitRunError,
}

impl TypedCure for GitReadFailure {
    fn cure(&self) -> String {
        match &self.outcome {
            GitRunError::Spawn { .. } => self.purpose.cure().to_string(),
            GitRunError::Exit { .. } => format!(
                "git refused the read for {}; the detail carries git's line; repair what it names, \
                 then re-run",
                self.purpose.what()
            ),
            GitRunError::NonUtf8Output { op, .. } => format!(
                "git's `{op}` output for {} holds bytes outside UTF-8; the ceremony requires UTF-8 \
                 paths and configuration keys; rename the path or key the sample names to \
                 UTF-8, then re-run",
                self.purpose.what()
            ),
        }
    }
}

/// A required parameter absent at a gate. Built from the spine `ParamRecord`; the cure is the two
/// `ParamClass` match arms below.
pub(in crate::ceremony) struct MissingParam {
    pub name: &'static str,
    pub class: super::param::ParamClass,
}

impl TypedCure for MissingParam {
    fn cure(&self) -> String {
        match self.class {
            super::param::ParamClass::Judgment => {
                format!("pass --{} on the invocation", self.name.replace('_', "-"))
            }
            super::param::ParamClass::Identity => {
                format!(
                    "add `{}` to the profile (the guided interview collects it)",
                    self.name
                )
            }
        }
    }
}

pub(in crate::ceremony) enum ProbeOutcome {
    Unmet(String),
    Unevaluable(String),
}

impl From<super::probes::ProbeResult> for ProbeOutcome {
    fn from(r: super::probes::ProbeResult) -> Self {
        match r {
            super::probes::ProbeResult::Unmet(s) => ProbeOutcome::Unmet(s),
            super::probes::ProbeResult::Unevaluable(s) => ProbeOutcome::Unevaluable(s),
                                                                                        
            super::probes::ProbeResult::Met => {
                ProbeOutcome::Unevaluable("the precondition probe reported met".to_string())
            }
        }
    }
}

/// Built only by `from_probe` and `named`.
pub(in crate::ceremony) struct UnmetPrecondition {
    probe: &'static str,
    explain: &'static str,
    outcome: ProbeOutcome,
    resume: Option<String>,
}

impl UnmetPrecondition {
    pub fn from_probe(
        probe: &super::probes::Probe,
        result: super::probes::ProbeResult,
        resume: Option<String>,
    ) -> Self {
        UnmetPrecondition {
            probe: probe.id,
            explain: probe.explain,
            outcome: result.into(),
            resume,
        }
    }

    pub fn named(
        probe: &'static str,
        explain: &'static str,
        result: super::probes::ProbeResult,
        resume: Option<String>,
    ) -> Self {
        UnmetPrecondition {
            probe,
            explain,
            outcome: result.into(),
            resume,
        }
    }

    pub fn detail(&self) -> String {
        match &self.outcome {
            ProbeOutcome::Unmet(remedy) => format!("{} ({}): {remedy}", self.probe, self.explain),
            ProbeOutcome::Unevaluable(why) => {
                format!(
                    "{} ({}): could not be evaluated: {why}",
                    self.probe, self.explain
                )
            }
        }
    }
}

impl TypedCure for UnmetPrecondition {
    fn cure(&self) -> String {
        let base = match &self.outcome {
            ProbeOutcome::Unmet(remedy) => remedy.clone(),
            ProbeOutcome::Unevaluable(_) => format!("make {} evaluable, then re-run", self.explain),
        };
        match &self.resume {
            Some(r) => format!("{base}; then resume with: {r}"),
            None => base,
        }
    }
}

/// A git operation in progress at the executing checkout (§3.1). Selects the finish-or-abort cure
/// by total match (decision 2026-09-01-condition-typed-cures). A new operation must choose its cure
/// here to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InProgressOp {
    Merge,
    CherryPick,
    Revert,
    Rebase,
    Am,
    Bisect,
}

impl InProgressOp {
    /// The marker label the detail names.
    pub fn label(self) -> &'static str {
        match self {
            InProgressOp::Merge => "merge",
            InProgressOp::CherryPick => "cherry-pick",
            InProgressOp::Revert => "revert",
            InProgressOp::Rebase => "rebase",
            InProgressOp::Am => "am",
            InProgressOp::Bisect => "bisect",
        }
    }
}

impl TypedCure for InProgressOp {
    fn cure(&self) -> String {
        match self {
            InProgressOp::Merge => {
                "finish the merge (`git merge --continue`) or abort it \
                                    (`git merge --abort`), then re-run"
            }
            InProgressOp::CherryPick => {
                "finish the cherry-pick (`git cherry-pick --continue`) or \
                                         abort it (`git cherry-pick --abort` / `--quit`), then \
                                         re-run"
            }
            InProgressOp::Revert => {
                "finish the revert (`git revert --continue`) or abort it \
                                     (`git revert --abort` / `--quit`), then re-run"
            }
            InProgressOp::Rebase => {
                "finish the rebase (`git rebase --continue`) or abort it \
                                     (`git rebase --abort`), then re-run"
            }
            InProgressOp::Am => {
                "finish the am (`git am --continue`) or abort it (`git am \
                                 --abort`), then re-run"
            }
            InProgressOp::Bisect => "end the bisect (`git bisect reset`), then re-run",
        }
        .to_string()
    }
}

/// A named checkout outside its operator-ratified form (§1.4). Selects the cure by total match; a
/// new condition must choose its cure here to compile (decision 2026-09-01-condition-typed-cures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoFormCondition {
    /// A `refs/replace/*` ref exists.
    ReplaceRefs,
    /// An `info/grafts` file exists.
    Grafts,
    /// `.git/shallow` present.
    ShallowClone,
    /// No ratified declared-space file for this checkout. `admit` is the invocation's own `orchard
                                                      
    NoDeclaredSpace { checkout: String, admit: String },
    /// The measured declared space differs from the ratified file.
    DeclaredSpaceDelta {
        checkout: String,
        added: Vec<String>,
        removed: Vec<String>,
        admit: String,
    },
    /// The `--list --show-scope` read git itself refused or could not run.
    Unreadable(GitRunError),
    /// The ratified declared-space file exists and cannot be read (§3.3). `file` is the file the
                                                                         
    RatifiedUnreadable {
        checkout: String,
        file: super::Utf8PathBuf,
        error: String,
        admit: String,
    },
}

impl TypedCure for RepoFormCondition {
    fn cure(&self) -> String {
        match self {
            RepoFormCondition::ReplaceRefs => "the ceremony does not commit onto replaced history; \
                remove or finish the replacement (`git replace -d <ref>`), then re-run"
                .to_string(),
            RepoFormCondition::Grafts => "remove the grafts file (git deprecates grafts; \
                `git replace --convert-graft-file` converts them, which this check also refuses), \
                then re-run"
                .to_string(),
            RepoFormCondition::ShallowClone => {
                "the ceremony refuses a shallow clone; unshallow it (`git fetch --unshallow`), then \
                 re-run"
                    .to_string()
            }
            RepoFormCondition::NoDeclaredSpace { checkout, admit } => format!(
                "the {checkout} checkout has no operator-ratified declared space; run `{admit}` to \
                 ratify its current declared space, then re-run"
            ),
            RepoFormCondition::DeclaredSpaceDelta { checkout, admit, .. } => format!(
                "the {checkout} checkout's effective git configuration differs from its ratified \
                 declared space (the delta is in the detail: keys at every scope, and values at \
                 the program-valued keys); revert the configuration, or run `{admit}` to ratify \
                 the shown delta, then re-run"
            ),
            RepoFormCondition::Unreadable(e) => format!(
                "the ceremony could not read the checkout's git configuration listing ({e}); \
                 repair what git names, then re-run"
            ),
            RepoFormCondition::RatifiedUnreadable {
                file, admit, ..
            } => format!(
                "restore `{file}` from a trusted copy (its git history when the file is tracked), \
                 or remove it and run `{admit}` to ratify the current declared space, then re-run"
            ),
        }
    }
}

/// A refusal's cure SOURCE: a static template, or a marker that the site's
/// `cure_extra` IS the whole cure. One source per id, never both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CureSource {
    /// A static template rendered for every site of the id, composed with the extra when present.
    Static(&'static str),
    /// No static template: the site's `cure_extra` is the whole cure. A refusal built without an
    /// extra trips the non-empty assert in [`Cure::rendered`], loud at the construction site.
    Derived,
}

/// Declares the refusal ids with their kebab token and their cure SOURCE in one place: the match
                                                                                                   
/// ↔ one remedy class (R6 cures): the class unit is the remedy, not the subsystem noun, so a cure
/// must be true and safe at every site that constructs the id. The trigger is stated once, per site
/// and derived, on the `detail` line `Display` renders above the cure.
macro_rules! refusal_ids {
    ($($variant:ident => ($token:literal, $cure:expr)),+ $(,)?) => {
                                                            
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RefusalId {
            $($variant),+
        }

        impl RefusalId {
            pub const ALL: &'static [RefusalId] = &[$(RefusalId::$variant),+];

            /// The kebab token porcelain + human renders carry.
            pub fn token(self) -> &'static str {
                match self {
                    $(RefusalId::$variant => $token),+
                }
            }

            /// The cure SOURCE (static template, or derived from the site's extra). Rendered by
                                                                                                  
            pub fn cure_source(self) -> CureSource {
                match self {
                    $(RefusalId::$variant => $cure),+
                }
            }
        }
    };
}

refusal_ids! {
                                                        
                                                                                                 
                                                                                            
                                                                                         
                                                                                           
                                                                                                 
            
    ContextUnresolvable => (
        "context-unresolvable",
        CureSource::Static(
            "run from a working directory that exists, or fix the named path, or supply the value \
             via its flag (--repo-root / --artifact-store / --repo-manifest), the profile, \
             $FRUIT_ARTIFACT_STORE, or the context file"
        )
    ),
    ContextConflict => (
        "context-conflict",
        CureSource::Static("pass exactly one context source, or make them agree")
    ),
                                                                                               
                                                                                                 
                                         
    ContextFileInvalid => (
        "context-file-invalid",
        CureSource::Static(
            "the context file must exist (an explicitly named --context file has no silent \
             fallback) and be readable (check its ownership and permissions), and its schema is \
             exactly {repo_root, artifact_store, repo_manifest}"
        )
    ),
    ProfileContextPathRelative => (
        "profile-context-path-relative",
        CureSource::Static(
            "profile context paths travel with the profile and must be absolute; replace the \
             relative value"
        )
    ),
    ContextNotUtf8 => (
        "context-not-utf8",
        CureSource::Static(
            "rename the path the detail names so it is UTF-8 text, or supply a UTF-8 path at a \
             higher tier (the flag, the profile, the env var, the context file), then re-run"
        )
    ),
                              
                                                                                           
                                                                                           
                                                                                               
                                                                                              
    WeightsEnvRefused => (
        "weights-env-refused",
        CureSource::Static(
            "unset the RECIPES_DHA_* env var; weights enter as `orchard build \
             --dha-weights-gguf/--dha-mmproj-gguf <path>` or the profile's `dha_weights_gguf` key \
             — bake with build, then hand the image to dryrun/prod"
        )
    ),
                                    
    LockHeld => (
        "lock-held",
        CureSource::Static(
            "wait for or stop the holding invocation (named in the detail when its sidecar is \
             readable); one WRITING orchard invocation per host"
        )
    ),
                                                                                          
                                                                     
    LockUnavailable => (
        "lock-unavailable",
        CureSource::Static(
            "check the lock directory's ownership and permissions, or, when no orchard invocation \
             is running on this host, remove a lock dir another account left behind"
        )
    ),
                                      
                                                                             
    RecordsUnreadable => (
        "records-unreadable",
        CureSource::Static("move the run records aside to re-establish them by re-running")
    ),
                                                                                            
                                                                                               
    RecordsSchemaOutdated => (
        "records-schema-outdated",
        CureSource::Static(
            "this records directory predates the v2 witness schema; archive it (move the dir aside, \
             e.g. to <dir>.v1) and re-run — previously recorded paths classify as unrecorded once \
             and are yours to settle"
        )
    ),
    RecordsUnwritable => (
        "records-unwritable",
        CureSource::Static("check the named path's permissions and free space")
    ),
                                      
    ParameterInvalid => (
        "parameter-invalid",
        CureSource::Static(
            "fix the value in the profile (a flagged value like --target or --image-version can \
             also be corrected on the invocation)"
        )
    ),
                                                                                                 
                                                
    RequiredParamMissing => (
        "required-param-missing",
        CureSource::Derived
    ),
    TargetNotTyped => (
        "target-not-typed",
        CureSource::Static(
            "the target is typed on the invocation, never taken from the profile — re-run with \
             `--target <ip-or-hostname>`"
        )
    ),
    ProfileTargetMissing => (
        "profile-target-missing",
        CureSource::Static(
            "the ceremony cross-checks the typed target against the profile's stored `ip`, so the profile \
             must carry one — add `ip = \"<the box>\"` to the profile"
        )
    ),
    TargetMismatch => (
        "target-mismatch",
        CureSource::Static(
            "you may be pointing the wrong box's profile at this target; fix one to match, or drop \
             `ip` from the profile"
        )
    ),
    JudgmentNotResupplied => (
        "judgment-not-resupplied",
        CureSource::Static(
            "a judgment value is re-decided every run and is never carried silently from the \
             profile — pass its flag on this invocation"
        )
    ),
    CeremonyTreeDirty => (
        "ceremony-tree-dirty",
        CureSource::Static(
            "the ceremony never sweeps operator work: commit or stash the listed paths in the \
             ceremony checkout, then re-run"
        )
    ),
                                                                                                 
                                                                                               
    PreconditionUnmet => (
        "precondition-unmet",
        CureSource::Derived
    ),
                                      
    DestructiveTokenNotTyped => (
        "destructive-token-not-typed",
        CureSource::Static(
            "a destructive step is authorized BY VALUE on the executing invocation and by nothing \
             else — re-run the resume command once you mean it"
        )
    ),
    StepFailed => (
        "step-failed",
        CureSource::Static(
            "the step's own output says what went wrong; fix that, then re-run — the completed \
             steps SKIP on the next run"
        )
    ),
                                                                                                 
                                                  
    StepInputMissing => (
        "step-input-missing",
        CureSource::Static("re-run so the earlier step executes, or restore the records dir")
    ),
                                              
    ConsentGateOwed => (
        "consent-gate-owed",
        CureSource::Static(
            "the ceremony commits nothing the operator has not reviewed or recorded — \
             review the paths and re-run the resume command"
        )
    ),
    SiblingContentUnrecognized => (
        "sibling-content-unrecognized",
        CureSource::Static(
            "the ceremony never commits into a sibling checkout, so this one is yours to \
             settle"
        )
    ),
                                                                   
                                                                                                     
                                                                                                   
    PartialCommitBlocked => (
        "partial-commit-blocked",
        CureSource::Derived
    ),
                                                                                                     
                                                
    UnmergedOwedPath => (
        "unmerged-owed-path",
        CureSource::Static(
            "resolve the conflict at the named owed path(s), stage the resolution (`git add` or \
             `git rm`), then re-run"
        )
    ),
                                                                                                      
                                                                                                  
    CommitPreviewEmpty => (
        "commit-preview-empty",
        CureSource::Static(
            "no owed declared path holds a change against HEAD for the ceremony to commit: either \
             every owed path's recorded state already equals its committed state, or a content \
             filter configured on a declared path re-dirties it after the first ceremony commit; \
             settle or commit any staged-only edits yourself, then re-run"
        )
    ),
                                                     
                                                                                                  
                                 
    GateContentMoved => (
        "gate-content-moved",
        CureSource::Static(
            "a declared path's content changed between the gate's classification and the commit \
             construction; re-run (the re-run reclassifies the path)"
        )
    ),
                                                                                                 
                                                                                           
    GateRecordDropped => (
        "gate-record-dropped",
        CureSource::Static(
            "git dropped a declared path from the constructed tree because git rejects the name (a \
             `.git`-equivalent, a `.`/`..` or empty path component); rename or settle the named \
             path(s) by hand, then re-run"
        )
    ),
                                                                                                    
                                                                                                   
                                                                                                   
    GateTreeDeltaExceedsOwed => (
        "gate-tree-delta-exceeds-owed",
        CureSource::Derived
    ),
                                                                                              
                                                                              
    RepositoryFormUnmodelled => (
        "repository-form-unmodelled",
        CureSource::Derived
    ),
                                                                                                     
                                             
    GateSettleFailed => (
        "gate-settle-failed",
        CureSource::Derived
    ),
                                                                                                     
                                                                        
    CeremonyCommitRefused => (
        "ceremony-commit-refused",
        CureSource::Derived
    ),
                                                                                                     
                                             
    CommitVerifyFailed => (
        "ceremony-commit-verify-failed",
        CureSource::Derived
    ),
                                                           
                                                                                               
                                                                                             
    GitStateUnreadable => (
        "git-state-unreadable",
        CureSource::Derived
    ),
                                           
    ProvenanceUnusable => (
        "provenance-unusable",
        CureSource::Static(
            "the image's provenance sidecar is what tells the gate WHAT it is gating, and a gate \
             that could be told its parameters instead would attest whatever it was told — \
             rebuild the image, or copy the whole triple with its sidecars"
        )
    ),
    GateRecordMissing => (
        "gate-record-missing",
        CureSource::Static(
            "S10 installs only what a gate RUN attested — run the ceremony's gate target \
             on this image, or copy the emitted `<img>.gate-record.toml` from the host that ran \
             it into the profile's records dir"
        )
    ),
    GateRecordMismatch => (
        "gate-record-mismatch",
        CureSource::Static("re-run the gate on the staged image")
    ),
    GateCompositionUnsatisfiable => (
        "gate-composition-unsatisfiable",
        CureSource::Static("name a gate target whose legs boot the image")
    ),
    RealDomainGateUnavailable => (
        "real-domain-gate-unavailable",
        CureSource::Static(
            "a real-domain image's gate boot must be hermetic and must exercise the SeaBIOS \
             installed-disk boot; no such composition exists yet (the cross-stream `DryrunOpts` \
             hermeticity item, spec Q7) — gate this image on a test domain, or wait for that item"
        )
    ),
                                      
    InterviewNotInteractive => (
        "interview-not-interactive",
        CureSource::Static(
            "run `orchard guide` from a terminal; for an unattended run use `orchard run \
             <profile>` with the flags typed on the invocation"
        )
    ),
    ProfileWriteRefused => (
        "profile-write-refused",
        CureSource::Static(
            "the interview writes a profile of identity only — never destructive intent, key \
             material or a typed confirmation"
        )
    ),
                              
                                                                                            
                                                                                                
                                                                                                 
                 
    ProfileSchemaSkew => (
        "profile-schema-skew",
        CureSource::Static(
            "upgrade orchard, or lower the profile's schema_version to this version's (named in \
             the detail) and remove any keys this version then rejects"
        )
    ),
                                                      
                                                                                                
                                                                             
    RunnerLivenessLost => (
        "runner-liveness-lost",
        CureSource::Static(
            "re-run the ceremony. ORCHARD_CEREMONY_PPID is exported by the runner, never set by \
             hand"
        )
    ),
                                                                                   
                                                                                        
    DeclaredPathUnhashable => (
        "declared-path-unhashable",
        CureSource::Derived
    ),
    InternalInvariantViolated => (
        "internal-invariant-violated",
        CureSource::Static(
            "no operator artifact is at fault; re-run, and report the printed detail if it recurs"
        )
    ),
    GateRecordSchemaSkew => (
        "gate-record-schema-skew",
        CureSource::Static(
            "upgrade orchard, or re-run the gate with this orchard so it emits a record this \
             version reads"
        )
    ),
    SidecarUnwritable => (
        "sidecar-unwritable",
        CureSource::Static("fix the named path (ownership, permissions, free space)")
    ),
    RepoManifestUnusable => (
        "repo-manifest-unusable",
        CureSource::Static(
            "the ceremony locates the tenant checkout through the repo-manifest — make the named \
             manifest readable and declare the tenant checkout, or set `tenant_repo` in the \
             profile"
        )
    ),
    ProfileAnswerInvalid => (
        "profile-answer-invalid",
        CureSource::Static("re-answer the named key")
    ),
    ProfileUnwritable => (
        "profile-unwritable",
        CureSource::Static("check the named path's ownership, permissions and free space")
    ),
}

/// The rendered cure (template + optional instance specifics, or the instance specifics alone for
/// a derived-source id). The field is PRIVATE and the one factory validates non-emptiness, so an
/// empty cure VALUE is unrepresentable outside this module (the floor-builder handback after
                                                                                              
/// [`Refusal::cure`] — no cureless path exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cure(String);

impl Cure {
    /// Sole factory. A [`CureSource::Static`] template is a non-empty literal and a
    /// [`CureSource::Derived`] id carries its whole cure in the extra, so an empty render here is a
    /// regression (a derived id built with no extra) — loud at the construction site, not a blank
    /// line in the operator's terminal.
    fn rendered(text: String) -> Cure {
        assert!(
            !text.trim().is_empty(),
            "empty cure render — every refusal carries a non-empty cure"
        );
        Cure(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// TOML-encode a struct orchard owns, mapping a `toml::ser::Error` to
/// [`RefusalId::InternalInvariantViolated`]. A serialize failure over an
/// owned struct is an internal invariant, never an operator artifact, so the id cannot be a
/// path- or image-shaped remedy. `what` names the artifact for the detail line.
pub fn encode_owned<T: serde::Serialize>(
    value: &T,
    what: impl std::fmt::Display,
) -> Result<String, Refusal> {
    toml::to_string_pretty(value).map_err(|e| {
        Refusal::new(
            RefusalId::InternalInvariantViolated,
            format!("serialize {what}: {e}"),
        )
    })
}

                                                                                  
/// source plus optional specifics.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub id: RefusalId,
    pub detail: String,
    /// Instance-specific cure suffix (e.g. the exact path to fix); appended to a static template,
    /// or the WHOLE cure for a [`CureSource::Derived`] id.
    cure_extra: Option<String>,
}

impl Refusal {
    pub fn new(id: RefusalId, detail: impl Into<String>) -> Self {
        Refusal {
            id,
            detail: detail.into(),
            cure_extra: None,
        }
    }

    /// Read-only; writes go through [`Refusal::with_cure_extra`] (a static id) or
    /// [`Refusal::typed`] (a derived id).
    pub fn cure_extra(&self) -> Option<&str> {
        self.cure_extra.as_deref()
    }

    pub fn with_cure_extra(mut self, extra: impl Into<String>) -> Self {
        assert!(
            matches!(self.id.cure_source(), CureSource::Static(_)),
            "with_cure_extra on a Derived id ({:?}); a Derived id's cure comes from Refusal::typed",
            self.id
        );
        self.cure_extra = Some(extra.into());
        self
    }

    /// A [`CureSource::Derived`] id's whole cure, computed by the condition's [`TypedCure`] match.
    /// The only cure path for a `Derived` id.
    pub fn typed(id: RefusalId, detail: impl Into<String>, cond: &impl TypedCure) -> Self {
        assert!(
            matches!(id.cure_source(), CureSource::Derived),
            "Refusal::typed on a Static id ({id:?}); a Static id's cure is its template"
        );
        Refusal {
            id,
            detail: detail.into(),
            cure_extra: Some(cond.cure()),
        }
    }

    pub fn cure(&self) -> Cure {
        match self.id.cure_source() {
            CureSource::Static(template) => match &self.cure_extra {
                Some(e) => Cure::rendered(format!("{template} ({e})")),
                None => Cure::rendered(template.to_string()),
            },
                                                                                                   
                                                                        
            CureSource::Derived => {
                Cure::rendered(self.cure_extra.as_deref().unwrap_or("").to_string())
            }
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusal ({}): {}\n  cure: {}",
            self.id.token(),
            self.detail,
            self.cure().as_str()
        )
    }
}

impl std::error::Error for Refusal {}
