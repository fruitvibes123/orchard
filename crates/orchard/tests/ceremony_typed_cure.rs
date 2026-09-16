//! R16 fold-3 typed-cure floor arms (delta §3 + §3.4, `code-phaseR-r16-FLOOR3B.md`). Every arm
//! drives the production path and reads the composed refusal the operator receives. The cure
//! literals are hand-written: deriving one from the `TypedCure` body it checks would compare the
//! mechanism against itself, and a rotation of two arm bodies would rotate both sides.

#[path = "ceremony_gate_commit/fixture.rs"]
#[allow(dead_code)]
mod fixture;

use std::path::{Path, PathBuf};

use fixture::*;
use orchard::ceremony::records::RunRecords;
use orchard::ceremony::refusal::{CureSource, Refusal, RefusalId, TypedCure};

                                                                                                    

/// A `TypedCure` whose text is fixed, for the `Refusal::typed` construction arms.
struct FixedCure(&'static str);

impl TypedCure for FixedCure {
    fn cure(&self) -> String {
        self.0.to_string()
    }
}

/// Delta §3.1: a `CureSource::Derived` id's cure comes from `Refusal::typed`, so the instance-suffix
/// constructor refuses one at the construction site. The arm drives `with_cure_extra` on a `Derived`
/// id; dropping the assert lands a hand-written cure on a derived id with the suite green.
#[test]
#[should_panic(expected = "with_cure_extra on a Derived id")]
fn with_cure_extra_on_a_derived_id_panics_at_the_construction_site() {
                                                                       
    assert!(
        matches!(
            RefusalId::GitStateUnreadable.cure_source(),
            CureSource::Derived
        ),
        "the arm's id is no longer a Derived-source id"
    );
    let _ = Refusal::new(RefusalId::GitStateUnreadable, "detail-text")
        .with_cure_extra("a hand-written cure on a derived id");
}

/// The other direction of the same split: `Refusal::typed` on a `CureSource::Static` id would put a
/// computed cure where the id's template stands, and refuses at the construction site.
#[test]
#[should_panic(expected = "Refusal::typed on a Static id")]
fn refusal_typed_on_a_static_id_panics_at_the_construction_site() {
                                                                      
    assert!(
        matches!(RefusalId::LockHeld.cure_source(), CureSource::Static(_)),
        "the arm's id is no longer a Static-source id"
    );
    let _ = Refusal::typed(
        RefusalId::LockHeld,
        "detail-text",
        &FixedCure("a computed cure on a static id"),
    );
}

                                                                                                    

/// Restores `PATH` on drop, so a panicking arm does not leave the shim on the next arm's `PATH`.
struct PathGuard(String);

impl Drop for PathGuard {
    fn drop(&mut self) {
                                                     
        unsafe { std::env::set_var("PATH", &self.0) };
    }
}

fn resolve(bin: &str) -> String {
    let out = std::process::Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .output()
        .expect("resolve a host binary");
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!p.is_empty(), "{bin} must be resolvable for these arms");
    p
}

/// A `git` on `PATH` that execs the real git by absolute path and DELETES ITSELF at the first call
/// whose argv matches `trigger`; the next `Command::new("git")` then finds nothing. The technique is
                                                     
fn shim_git_removed_at(root: &Path, trigger: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let real_git = resolve("git");
    let real_rm = resolve("rm");
    let dir = root.join(".shim");
    std::fs::create_dir_all(&dir).expect("mk shim dir");
    let shim = dir.join("git");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\ncase \"$*\" in\n  *'{trigger}'*) '{real_rm}' -f '{p}' ;;\nesac\nexec {real_git} \"$@\"\n",
            p = shim.display()
        ),
    )
    .expect("write shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    (dir, shim)
}

/// `PATH` set to `dir` alone for the guard's lifetime.
fn path_only(dir: &Path) -> PathGuard {
    let old = std::env::var("PATH").expect("PATH");
                                                                             
    unsafe { std::env::set_var("PATH", dir.display().to_string()) };
    PathGuard(old)
}

/// The `std::io::Error` text a spawn of an absent program produces on this host, measured with a
/// name no PATH entry holds. The oracle for the `GitRunError::Spawn` clause a cure embeds.
fn absent_program_spawn_error() -> String {
    let e = std::process::Command::new("orchard-no-such-program-0e1f")
        .output()
        .expect_err("an absent program does not spawn");
    e.to_string()
}

                                                                                                     

/// Delta §3.2 `StageFailure`: the `MessageFile` variant's cure, driven at the msgfile site. No other
/// arm reaches this variant, so a rotation of its body onto the git-refused text passes the rest of
/// the suite.
#[test]
fn the_message_file_stage_renders_the_tmpdir_cure_not_a_git_refusal() {
    const MSGFILE_CURE: &str = "the commit could not be prepared (temp file); check TMPDIR space \
         and permissions, then re-run";
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2, "two declared paths are owed");
    i.commit = true;

    let ro = fx.at(".ro-tmp");
    std::fs::create_dir_all(&ro).expect("mk the read-only tmpdir");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).expect("chmod 500");
    }
                                                                                           
    assert!(
        std::fs::File::create(ro.join("probe")).is_err(),
        "the fixture tmpdir is writable, so this arm would measure a landed commit"
    );

    let head_before = git_head(&fx.root);
    let old_tmp = std::env::var("TMPDIR").ok();
                                                                                      
    unsafe { std::env::set_var("TMPDIR", ro.display().to_string()) };
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
                    
    unsafe {
        match &old_tmp {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).expect("restore");
    }

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("the commit message file could not be"),
        "the detail names the message-file stage: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        MSGFILE_CURE,
        "the MessageFile variant's cure, not a git-refusal cure"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a message-file refusal"
    );
}

                                                                                                     
/// reached by no leg (the shipped spawn arm removes the shim at `HEAD^{tree}` and at
/// `commit.gpgSign`, so it drives the hash-object and commit-tree sites only). This arm removes the
/// shim at `hash-object`, so `read-tree` — the first stage the closure serves — is the call that
/// cannot spawn.
#[test]
fn a_spawn_failure_at_a_closure_routed_stage_names_that_stage_in_the_detail_and_the_cure() {
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
                                                                                      
    record_write(
        &fx,
        &mut records,
        VENDORED,
        b"bytes no object holds yet\n",
        false,
    );
    i.commit = true;
    let head_before = git_head(&fx.root);

    let (dir, shim) = shim_git_removed_at(&fx.root, "hash-object");
    let run = {
        let _p = path_only(&dir);
        run_gate_headless(&fx, &mut records, &admitted, &i, &profile)
    };
                                                                                   
    assert!(
        !shim.exists(),
        "the shim never removed itself, so this arm measured a different failure"
    );

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("the ceremony's gate commit failed at `read-tree`")
            && refusal.detail.contains("`git read-tree` could not run"),
        "the detail names the stage the closure routed and the spawn failure: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        format!(
            "git could not be spawned at `read-tree` ({}); check that git is on PATH and \
             executable, then re-run",
            absent_program_spawn_error()
        ),
        "the Spawn cure names the closure-routed stage"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a spawn refusal"
    );
}

                                                                                                     

/// Delta §1.4 `RepoFormCondition::Unreadable`: the key-set read's own failure, the one variant of
/// the condition no other arm reaches. The shim leaves at `--is-shallow-repository`, so the three
/// git-asked reads answer and `config --list --show-scope --null` is the call that cannot spawn.
#[test]
fn a_key_set_read_that_cannot_spawn_renders_the_unreadable_condition_cure() {
    let (fx, mut records, admitted, i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
                                                                                                    
    assert_eq!(owed.len(), 2, "two declared paths are owed");
    let head_before = git_head(&fx.root);

    let (dir, shim) = shim_git_removed_at(&fx.root, "--is-shallow-repository");
    let run = {
        let _p = path_only(&dir);
        run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile)
    };
    assert!(
        !shim.exists(),
        "the shim never removed itself, so this arm measured a different failure"
    );

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "repository-form-unmodelled",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("cannot read the executing checkout's git configuration listing"),
        "the detail names the read that failed: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        format!(
            "the ceremony could not read the checkout's git configuration listing (`git config \
             --list --show-scope --null` could not run: {}); repair what git names, then re-run",
            absent_program_spawn_error()
        ),
        "the Unreadable condition's cure, not another RepoFormCondition arm's"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a §3.0 refusal"
    );
}

/// Delta §3.2 `GitReadFailure`: the `Spawn` outcome takes the READ PURPOSE's own remedy. Both driven
/// purposes get a leg, so a rotation of the two `GitReadPurpose::cure` bodies reds the leg that
/// disagrees. The `Exit` outcome of both purposes is pinned by the shipped arms
/// (`ceremony_gate_commit::the_sibling_checkout_read_renders_its_own_cure_not_the_commit_gates`,
/// `ceremony_runner::the_executing_gate_fails_closed_when_git_state_is_unreadable`).
#[test]
fn a_git_read_that_cannot_spawn_renders_its_own_purposes_remedy() {
    const COMMIT_GATE_SPAWN_CURE: &str = "the ceremony could not read the checkout's git state for \
         its commit gate; run from the checkout the ceremony was invoked on, with `git` on PATH";
    const SIBLING_SPAWN_CURE: &str = "the ceremony could not read the sibling checkout's git state \
         for its sibling gate; run from the checkout the ceremony was invoked on, with `git` \
         on PATH";
    assert_ne!(
        COMMIT_GATE_SPAWN_CURE, SIBLING_SPAWN_CURE,
        "two purposes, two routes"
    );

                                                                                           
    {
        let (fx, mut records, admitted, i, profile) = gate_fixture();
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "two declared paths are owed");
        let head_before = git_head(&fx.root);
        let empty = fx.at(".no-git");
        std::fs::create_dir_all(&empty).expect("mk an empty PATH dir");
        let run = {
            let _p = path_only(&empty);
            run_gate_pre_prompt(&fx, &mut records, &admitted, &i, &profile)
        };
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "git-state-unreadable",
            "{}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("could not run"),
            "the detail carries the spawn failure: {}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            COMMIT_GATE_SPAWN_CURE,
            "the commit gate's own remedy"
        );
        assert_eq!(
            git_head(&fx.root),
            head_before,
            "HEAD moved under a refusal"
        );
    }

                                                                                    
    {
        let (fx, _records, _admitted, i, profile) = gate_fixture();
        std::fs::write(
            fx.at("repo-manifest.toml"),
            "schema-version = 1\n[repos.recipes]\npath = \"../recipes\"\nartifacts = \
             [\"recipes-app\"]\n",
        )
        .expect("manifest");
        let tenant = fx.root.join("../recipes");
        std::fs::create_dir_all(&tenant).expect("tenant dir");
                                                                                                
                                                                  
        let (ok, _, _) = git_try(&fx.root, &["status", "--porcelain"]);
        assert!(ok, "the fixture root must be a readable repo");
        let empty = fx.at(".no-git");
        std::fs::create_dir_all(&empty).expect("mk an empty PATH dir");
        let reporter = orchard::ceremony::runner::Reporter { porcelain: true };
        let err = {
            let _p = path_only(&empty);
            orchard::ceremony::runner::sibling_gate(
                orchard::ceremony::spine::SPINE
                    .iter()
                    .find(|s| s.id == orchard::ceremony::spine::StepId::S6TenantRepin)
                    .expect("S6 in the spine"),
                &i,
                &fx.ctx,
                &profile,
                &reporter,
            )
            .expect_err("a sibling read that cannot spawn fails closed")
        };
        let refusal = err
            .downcast_ref::<Refusal>()
            .unwrap_or_else(|| panic!("expected a typed Refusal, got: {err}"));
        assert_eq!(
            refusal.id.token(),
            "git-state-unreadable",
            "{}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            SIBLING_SPAWN_CURE,
            "the sibling gate's own remedy"
        );
    }
}

/// A `reference-transaction` hook that rejects the transaction in the `prepared` phase, guarded on
/// the arming file; git aborts, exit 128, HEAD unmoved.
const RT_REJECT_PREPARED: &str = "[ \"$1\" = prepared ] || exit 0\n\
     [ -e .git/hook-armed ] || exit 0\n\
     echo 'policy: this repository forbids un-reviewed ref updates' >&2\n\
     exit 1\n";

/// Delta §3.2 `CasRefusal::HeadUnreadable`: the compare-and-swap is refused AND the HEAD read that
/// classifies the refusal cannot run. The hook refuses the update; the shim leaves at `update-ref`,
/// so the `rev-parse HEAD` that follows is the call that cannot spawn.
#[test]
fn a_refused_swap_whose_head_read_cannot_spawn_renders_the_head_unreadable_cure() {
    let (fx, mut records, admitted, mut i, profile) =
        gate_fixture_with(|root| install_hook(root, "reference-transaction", RT_REJECT_PREPARED));
    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2, "two declared paths are owed");
    arm_hook(&fx.root);
    i.commit = true;
    let head_before = git_head(&fx.root);

    let (dir, shim) = shim_git_removed_at(&fx.root, "update-ref");
    let run = {
        let _p = path_only(&dir);
        run_gate_headless(&fx, &mut records, &admitted, &i, &profile)
    };
    assert!(
        !shim.exists(),
        "the shim never removed itself, so this arm measured a different failure"
    );

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal
            .detail
            .contains("the HEAD read after the refused update failed"),
        "the detail states the HEAD read failed: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        format!(
            "the HEAD read after the refused update failed (`git rev-parse HEAD` could not run: \
             {}); inspect `git rev-parse HEAD` by hand, then re-run",
            absent_program_spawn_error()
        ),
        "the HeadUnreadable arm's cure, not the Moved or Unmoved arm's"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a refused compare-and-swap"
    );
}

/// A `reference-transaction` hook that moves HEAD back one commit after the ceremony's swap
/// committed, guarded on the arming file and fired once.
const RT_MOVE_HEAD_BACK: &str = "[ \"$1\" = committed ] || exit 0\n\
     if [ -e .git/hook-armed ] && [ ! -e .git/rt-done ]; then\n\
     : > .git/rt-done\n\
     git update-ref HEAD \"$(git rev-parse HEAD^)\"\n\
     fi\n\
     exit 0\n";

/// Delta §3.2 `IdentityFailure`: the cure is a match over the HEAD read's own outcome, and neither
/// arm is asserted by the shipped arms (they hold the DETAIL's settle clause). Leg (a) drives the
/// `Ok` arm (HEAD read, moved by a hook); leg (b) drives the `Err` arm (the read itself cannot
/// spawn). The constructed commit's id is read from git's reflog, never from the refusal.
#[test]
fn the_identity_failure_cure_is_the_head_reads_own_outcome() {
                                                                   
    {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture_with(|root| {
            install_hook(root, "reference-transaction", RT_MOVE_HEAD_BACK)
        });
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "two declared paths are owed");
        arm_hook(&fx.root);
        i.commit = true;
        let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);
                                                                                                
                                                 
        assert!(
            fx.root.join(".git/rt-done").exists(),
            "the hook never fired, so this arm measured nothing"
        );
        let c_new = git_out(&fx.root, &["rev-parse", "HEAD@{1}"]);
        assert_ne!(
            c_new,
            git_head(&fx.root),
            "the reflog's prior HEAD is the moved-from commit"
        );
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "ceremony-commit-verify-failed",
            "{}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            format!(
                "inspect `git log -1 HEAD` against {c_new}; a hook or a concurrent ref move \
                 replaced HEAD after the swap — settle by hand, then re-run"
            ),
            "the read-answered arm's cure"
        );
    }

                                                  
    {
        let (fx, mut records, admitted, mut i, profile) = gate_fixture();
        let owed = dirty_the_declared_pair(&fx, &mut records);
        assert_eq!(owed.len(), 2, "two declared paths are owed");
        i.commit = true;
        let head_before = git_head(&fx.root);
        let (dir, shim) = shim_git_removed_at(&fx.root, "update-ref");
        let run = {
            let _p = path_only(&dir);
            run_gate_headless(&fx, &mut records, &admitted, &i, &profile)
        };
        assert!(
            !shim.exists(),
            "the shim never removed itself, so this arm measured a different failure"
        );
                                                                                                     
        let c_new = git_head(&fx.root);
        assert_ne!(c_new, head_before, "the ceremony's commit did not land");
        let refusal = run.refusal();
        assert_eq!(
            refusal.id.token(),
            "ceremony-commit-verify-failed",
            "{}",
            refusal.detail
        );
        assert!(
            refusal
                .detail
                .contains("the identity read failed after the swap"),
            "the detail states the read failed: {}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            format!("inspect `git log -1 HEAD` against {c_new}, settle by hand, then re-run"),
            "the read-failed arm's cure"
        );
    }
}

/// Delta §3.4 `UnmetPrecondition`: the cure composes the outcome's base with the resume clause. The
/// shipped arms hold the `Unmet`-with-no-resume case exactly
/// (`ceremony_runner::a_derived_source_precondition_cure_renders_the_probes_own_text_and_nothing_else`)
/// and assert only that a resume-carrying cure CONTAINS `orchard run`, so neither the `Unevaluable`
/// base nor the composition order is pinned. Both legs assert the composed text end to end; the
/// resume command's own composition is the `destructive-token-not-typed` arm's claim.
#[test]
fn the_unmet_precondition_cure_composes_its_outcomes_base_with_the_resume_clause() {
    use orchard::ceremony::admission::{Measured, resolve_values};
    use orchard::ceremony::probes::ProbeCtx;
    use orchard::ceremony::runner::{StepDisposition, step_disposition};
    use orchard::ceremony::spine::{SPINE, StepId};

    let step_of = |id: StepId| {
        SPINE
            .iter()
            .find(|s| s.id == id)
            .expect("step in the spine")
    };

                                                                                                  
    {
        let (fx, _records, _admitted, i, profile) = gate_fixture();
                                                                                                 
        let records = RunRecords::open_dir(&fx.at("boxes/fresh.d"), "run-2").expect("records");
        let values = resolve_values(&i, &profile, &fx.ctx);
        let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
        let owed = match step_disposition(
            step_of(StepId::S9BoxPreflight),
            &probe_ctx,
            &values,
            &records,
            &Measured::default(),
            &i,
            &fx.ctx,
        ) {
            StepDisposition::Owed(owed) => owed,
            other => panic!("expected an owed external-checklist stop, got {other:?}"),
        };
                                                                                                 
        assert_eq!(owed.refusal.id.token(), "precondition-unmet");
        assert!(
            owed.refusal.detail.contains("target-ssh-preflight")
                && owed.refusal.detail.contains("could not be evaluated"),
            "the detail names the probe and its unevaluable outcome: {}",
            owed.refusal.detail
        );
        assert_eq!(
            owed.refusal.cure().as_str(),
            format!(
                "make the target is reachable as the cloud user with passwordless sudo (pre-kexec \
                 leg) evaluable, then re-run; then resume with: {}",
                i.resume_command(&fx.ctx)
            ),
            "the Unevaluable base, then the resume clause"
        );
    }

                                                                                                    
                                                                                                 
    {
        const UNSAFE_TAG: &str = "-flagshaped:tag";
        let (fx, _records, _admitted, i, profile) = gate_fixture();
        let records = RunRecords::open_dir(&fx.at("boxes/fresh.d"), "run-2").expect("records");
        let values = resolve_values(&i, &profile, &fx.ctx);
        let probe_ctx = ProbeCtx::new(
            &fx.ctx,
            Some(orchard::deploy::profile::Profile {
                container_image: Some(UNSAFE_TAG.to_string()),
                ..profile.clone()
            }),
        );
        let refusal = match step_disposition(
            step_of(StepId::S7ImageBuild),
            &probe_ctx,
            &values,
            &records,
            &Measured::default(),
            &i,
            &fx.ctx,
        ) {
            StepDisposition::Refuse(r) => r,
            other => panic!("expected a plain refusal on an internal step, got {other:?}"),
        };
                                                                                           
        assert_eq!(refusal.id.token(), "precondition-unmet");
        assert!(
            refusal.detail.contains("build-container-present")
                && !refusal.detail.contains("could not be evaluated"),
            "the detail names the probe and its unmet outcome: {}",
            refusal.detail
        );
        assert_eq!(
            refusal.cure().as_str(),
            format!(
                "container tag {UNSAFE_TAG:?} is not a safe image ref; then resume \
                 with: {}",
                i.resume_command(&fx.ctx)
            ),
            "the probe's own remedy, then the resume clause"
        );
    }
}

/// A `git` on `PATH` that answers the first call whose argv matches `trigger` with `stub` (printed
/// verbatim by `printf`, exit 0) and execs the real git by absolute path for every other call.
fn shim_git_stubbing(root: &Path, trigger: &str, stub: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let real_git = resolve("git");
    let dir = root.join(".stub-shim");
    std::fs::create_dir_all(&dir).expect("mk shim dir");
    let shim = dir.join("git");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\ncase \"$*\" in\n  *'{trigger}'*) printf '{stub}'; exit 0 ;;\nesac\nexec \
             {real_git} \"$@\"\n"
        ),
    )
    .expect("write shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    (dir, shim)
}

/// Delta §3.2 `StageFailure`: the `Parse` variant's cure, driven at the `ls-tree parse` site. git's
/// own `ls-tree -r -z` emits a tab in every record at 2.55.0 (`pC16b_15_lstree_record_shape.sh`), so
/// the variant is reached with a stub that answers the listing with a tab-less record; the parse,
/// the stage routing and the refusal construction are the production ones.
#[test]
fn an_unparseable_listing_renders_the_parse_cure_not_a_git_refusal() {
    const PARSE_CURE: &str = "the ceremony could not parse git's `ls-tree parse` output; the detail \
         carries the record; report it";
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2, "two declared paths are owed");
    i.commit = true;
    let head_before = git_head(&fx.root);

    let (dir, _shim) = shim_git_stubbing(&fx.root, "ls-tree", "norecordtab\\0");
    let run = {
        let _p = path_only(&dir);
        run_gate_headless(&fx, &mut records, &admitted, &i, &profile)
    };

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
                                                                                             
    assert!(
        refusal
            .detail
            .contains("ls-tree record \"norecordtab\" has no tab"),
        "the detail carries the parser's record: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        PARSE_CURE,
        "the Parse variant's cure, not a git-refusal cure"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a parse refusal"
    );
}

/// Delta §3.2 `StageFailure`: the signing read's own stage label in the cure. The shipped signing arm
/// (`ceremony_gate_commit::the_signing_read_signs_the_landed_commit_and_both_failure_shapes_refuse`)
/// asserts the DETAIL over a malformed `commit.gpgSign`; the cure this site renders is asserted here,
/// so a rotation of the `Stage::SigningRead` label reds a leg.
#[test]
fn a_malformed_signing_read_renders_the_signing_stages_cure() {
    const SIGNING_CURE: &str = "git refused the ceremony's commit at `commit.gpgSign`; the detail \
         carries git's own reason; repair what it names, then re-run";
    let (fx, mut records, admitted, mut i, profile) = gate_fixture();
    let owed = dirty_the_declared_pair(&fx, &mut records);
    assert_eq!(owed.len(), 2, "two declared paths are owed");
    git_out(&fx.root, &["config", "commit.gpgSign", "notabool"]);
                                                                            
    let (ok, _, err) = git_try(
        &fx.root,
        &["config", "--type=bool", "--default=false", "commit.gpgSign"],
    );
    assert!(
        !ok && err.contains("bad boolean config value"),
        "git accepts the value, so this arm measures no refused read: {err}"
    );
    i.commit = true;
    let head_before = git_head(&fx.root);
    let run = run_gate_headless(&fx, &mut records, &admitted, &i, &profile);

    let refusal = run.refusal();
    assert_eq!(
        refusal.id.token(),
        "ceremony-commit-refused",
        "{}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains("commit.gpgSign is malformed")
            && refusal.detail.contains("bad boolean config value"),
        "the detail names the read and carries git's line: {}",
        refusal.detail
    );
    assert_eq!(
        refusal.cure().as_str(),
        SIGNING_CURE,
        "the signing read's own stage in the cure"
    );
    assert_eq!(
        git_head(&fx.root),
        head_before,
        "HEAD moved under a signing-read refusal"
    );
}

                                                                                                    

/// The composed `precondition-unmet` detail, both outcomes, byte for byte.
///
/// The shipped arms read fragments of this line: `contains("could not be evaluated")` and its
/// negation, plus the probe id. A lost `({explain})` clause, a swapped composition order or a
/// changed separator leaves those green. `detail()` is the text `runner.rs` composed inline
/// before fold 4C moved it into the type, so the two literals below are that text.
///
/// Blind spot: the second `UnmetPrecondition` consumer (`runner.rs`'s `tenant-handoff-quiescent`
/// stop) composes its own detail and does not call `detail()`; it reads `handoff::quiescent` over
/// a fixed host path and no arm drives it.
#[test]
fn the_unmet_precondition_detail_is_the_composed_probe_explain_and_outcome() {
    use orchard::ceremony::admission::{Measured, resolve_values};
    use orchard::ceremony::probes::ProbeCtx;
    use orchard::ceremony::runner::{StepDisposition, step_disposition};
    use orchard::ceremony::spine::{SPINE, StepId};

    const UNEVALUABLE_DETAIL: &str = "target-ssh-preflight (the target is reachable as the cloud \
                                      user with passwordless sudo (pre-kexec leg)): could not be \
                                      evaluated: no target resolved for the preflight probe — the \
                                      runner attaches the parameter set";
    const UNSAFE_TAG: &str = "-flagshaped:tag";
    const UNMET_DETAIL: &str = "build-container-present (the pinned build container image exists \
                                on this host): container tag \"-flagshaped:tag\" is not a safe \
                                image ref";

    let step_of = |id: StepId| {
        SPINE
            .iter()
            .find(|s| s.id == id)
            .expect("step in the spine")
    };

                                                                                 
    {
        let (fx, _records, _admitted, i, profile) = gate_fixture();
        let records = RunRecords::open_dir(&fx.at("boxes/fresh.d"), "run-2").expect("records");
        let values = resolve_values(&i, &profile, &fx.ctx);
        let probe_ctx = ProbeCtx::new(&fx.ctx, Some(profile.clone()));
        let owed = match step_disposition(
            step_of(StepId::S9BoxPreflight),
            &probe_ctx,
            &values,
            &records,
            &Measured::default(),
            &i,
            &fx.ctx,
        ) {
            StepDisposition::Owed(owed) => owed,
            other => panic!("expected an owed external-checklist stop, got {other:?}"),
        };
                                                                                          
        assert_eq!(owed.refusal.id.token(), "precondition-unmet");
        assert_eq!(
            owed.refusal.detail, UNEVALUABLE_DETAIL,
            "the Unevaluable detail is `{{probe}} ({{explain}}): could not be evaluated: {{why}}`"
        );
    }

                                                                                            
                     
    {
        let (fx, _records, _admitted, i, profile) = gate_fixture();
        let records = RunRecords::open_dir(&fx.at("boxes/fresh.d"), "run-2").expect("records");
        let values = resolve_values(&i, &profile, &fx.ctx);
        let probe_ctx = ProbeCtx::new(
            &fx.ctx,
            Some(orchard::deploy::profile::Profile {
                container_image: Some(UNSAFE_TAG.to_string()),
                ..profile.clone()
            }),
        );
        let refusal = match step_disposition(
            step_of(StepId::S7ImageBuild),
            &probe_ctx,
            &values,
            &records,
            &Measured::default(),
            &i,
            &fx.ctx,
        ) {
            StepDisposition::Refuse(r) => r,
            other => panic!("expected a plain refusal on an internal step, got {other:?}"),
        };
                                                                                          
        assert_eq!(refusal.id.token(), "precondition-unmet");
        assert_eq!(
            refusal.detail, UNMET_DETAIL,
            "the Unmet detail is `{{probe}} ({{explain}}): {{remedy}}`"
        );
    }
}
