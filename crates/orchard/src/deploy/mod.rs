                                                                                   
//! this lives in the standalone `orchard` crate/binary, never linked into anything the
//! box bakes — a structurally stronger guarantee than the pre-split non-default `deploy`
//! Cargo feature it replaced (which no longer exists), enforced by the `crux-orchard`
//! Makefile gate rather than a feature flag.
//!
                                                                                                
//! §"Operator CLI surface" + §"Operator first-time key bootstrap" + §"Build pipeline".

pub mod artifact_keys;
pub mod artifact_sign;
pub mod artifact_verify;
pub mod build_image;
                                                                                                 
/// path through ONE chain (flag > profile > env > context file > builtin CWD default), printable
/// sources, fail-closed refusals on unresolvable named paths. The single home of the context
/// defaults; every consumer site routes through [`context::ResolvedContext`].
pub mod context;
/// `orchard update <host> --image <img>` (os-update A/B v1, C-E): the 8-step operator-push ceremony —
/// local sig-verify + compose ([`update::prepare_local_image`]) then pin/authorize/sign/stream/watch
/// ([`update::run_ceremony`], behind `UpdateOps` for FakeOps testing).
pub mod deploy_model;
/// `orchard doctor` (Component 2 / orchard-UX): a read-only, fail-honest readiness check.
/// Advisory — always exits 0, never a `make verify` leg; every unmet check names its cure.
pub mod doctor;
pub mod dryrun;
/// `prctl(PR_SET_DUMPABLE, 0)` — the seed-lifecycle-symmetric core-dump guard
                                                                    
pub mod dumpable;
/// The shared `next:` epilogue formatter (Component 4 / orchard-UX): every artifact-producing verb
/// ends with the natural next command(s). Reused by `doctor --for boot-gate` (C2) and `prime` (C6).
pub mod epilogue;
pub mod fingerprints;
/// The one-stop `market upgrade` commit seam (comfort Component 2): the pathspec-scoped GitCommit
/// trait + the fail-closed three-bucket partition of swapped paths (orchard-commit / sibling-print /
/// store-exclude).
pub mod git_commit;
/// `orchard update` (os-update A/B v1, C-E): the operator-local host-key PIN STORE — a durable
/// per-host known-good pin, non-silent first-contact bootstrap + refuse-silent-override on a key change.
pub mod host_pins;
pub mod installer_usb_cmd;
pub mod kernel_bump;
pub mod keys;
/// The docker-rung at-rest passphrase-wrap (Argon2id → XChaCha20-Poly1305): the
/// self-describing `WrappedBlob` format + wrap/unwrap core. Pure — extraction-ready.
pub mod keywrap;
                                                                                                    
/// SSH transport seam — `SshBox` (real, pinned per-host) + `FakeBox` (in-memory test double).
pub mod lifecycle;
pub mod market;
pub mod market_exec;
pub mod market_upgrade;
pub mod prod;
pub mod prod_e2e;
pub mod prod_orchestrate;
/// Deploy profiles (Component 5 / orchard-UX): the `--profile` whitelist TOML schema + parse + merge.
/// Destructive intent can never come from a profile; the merge is fail-closed on a missing required key.
pub mod profile;
                                                                                                    
/// the consent-gated offline shrink of a default-provisioned target's root, so the streaming
/// staging window lands in unpartitioned space and D-1 passes. Pure planning half + orchestrated half.
pub mod reclaim;
/// `orchard redelegate` (os-update A/B v1, C-F): mint the update-path delegations
/// (`UpdateImage`/`RootHash`) over an EXISTING root — the re-delegation ceremony the
/// root key file was reserved for. Box trust anchor untouched; no rebake owed.
pub mod redelegate;
pub mod refresh_apk_lock;
/// The human-report convention (Component 8 / orchard-UX): count-collapse the healthy bulk, itemize
/// anomalies columnar, abbreviate digests to 12-hex (display-only, per-report width). The shared
/// primitives are `abbrev_digests` (store status/prune) + `restore_manifest_rollup` (restore-image);
/// each consumer applies the count-collapse + columnar shaping over its own row type.
pub mod report;
                                                                                                  
/// invariant — a derive-not-trust preflight + a fail-safe append→verify→cleanup state machine over the
/// shared `BoxOps` transport; the atomic `mv` is the sole commit point.
pub mod rotate_key;
pub mod rust_bump;
pub mod secure_boot_keys;
pub mod sign_installer_usb;
pub mod sign_sb;
pub mod stage_stream;
pub mod staging_geometry;
                                                                                                  
/// `--image`/`--keys-dir`, with an honest exit taxonomy. All verdict logic runs operator-side on
/// sanitized box bytes.
pub mod status;
/// `market store` maintenance verbs (status/prune/migrate) over the CAS layout — the
/// worktree-aware reference scan lives here.
pub mod store_admin;
pub mod sync_pins;
pub mod tty;
pub mod update;
pub mod vendor_cmd;
pub mod verify;

/// The committed `pinned-artifact-root.toml` location under a repo root — the durable
                                                                                        
/// derivation (debt-burndown plan-audit L-1): the CLI arms and the bake both call this
/// (with `repo_root()` / `opts.repo_root`), so the path can never fork between them.
/// Mirrors `repo_fingerprints_path`'s anchor (`crates/image-builder/`, the generate-keys
/// ceremony's write target).
pub fn pinned_artifact_root_path(repo_root: &std::path::Path) -> std::path::PathBuf {
    repo_root
        .join("crates")
        .join("image-builder")
        .join("pinned-artifact-root.toml")
}
