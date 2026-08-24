                                                                                                            
//! the sha256 pin store by driving the owning repos' publisher (`grocer`) + the existing re-derive commands
//! (`orchard vendor`/`refresh-apk-lock`/`sync-pins`) + rewriting the pin manifests — it NEVER re-implements
//! a re-derive, and NEVER auto-commits (the operator reviews the diff as a security event; the trust model
//! stays git-review-rooted).
//!
//! ## Design — a pure PLAN + a separate executor (the testable seam)
//! [`plan`] builds an ordered `Vec<Step>` from the target PURELY (no effects), so the self-test asserts the
//! exact orchestration of each leg (which commands, in what order, which pins re-pinned) without running a
//! single build. Task 10 wires the CLI to BUILD + PRINT the plan (the operator preview); the stage-then-swap
//! EXECUTOR — every write directed into a temp stage (staged paths, not the real trees), `market verify` against
//! the staged result, swap only on green — is Task 11, so `market upgrade` cannot destructively mutate the
//! store until the atomic path exists.

use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest, PinManifestError};
use recipes_image_builder::repo_manifest::{RepoManifest, RepoManifestError};

/// The consume-pins keys whose binary is per-binary-publish-capable (Task 9), mapped to the BUILD bin name
/// the per-binary `build-binaries.sh` target takes. `recipes-app`'s bin is `recipes`; every other capable
/// key's bin equals the key. The static PID-1/installer pair (`box-init`/`initramfs-init`) is ABSENT — T9
/// left it whole-pair, so `--binary` on those is a hard error, not a silent whole-repo churn. The 3
/// v1-dha-box bins (creatine/dha-orchestrator/epa) are per-binary-capable — each is its own repo with a
/// `build-only.sh` (dha-owned deliverable); their consume-pins + repo-manifest entries land at publish.
const PER_BINARY_BUILD: &[(&str, &str)] = &[
    ("recipes-app", "recipes"),
    ("recipes-admin", "recipes-admin"),
    ("fb-acme", "fb-acme"),
    ("fb-oneshots", "fb-oneshots"),
    ("fb-backup", "fb-backup"),
    ("fb-cert-check", "fb-cert-check"),
                                                                                                         
                                                                                                        
    ("creatine-serve", "creatine-serve"),
    ("dha-orchestrator", "dha-orchestrator"),
    ("epa", "epa"),
                                                                                                      
                                                                                                        
    ("uds-pipe", "uds-pipe"),
];

/// What `market upgrade` re-derives (exactly one per run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A source-drop crate, by its `consume-pins` `*-src` key.
    Source(String),
    /// A single binary, by its `consume-pins` key.
    Binary(String),
                                                                                                          
    /// `--build-dir`, no whole-repo churn; the owning repo's config source must be git-tracked.
    Config(String),
    /// The apk closure (re-resolve + dual-verify; no binary rebuild).
    Apks,
    /// A new kernel version (fetch the signed sum → pins.toml → sync-pins).
    Kernel(String),
    /// A new rust toolchain version (the binary-cascade axis — re-pins ALL binaries).
    Rust(String),
    /// The whole store.
    All,
}

                                                                                                            
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Run an owning repo's publisher (`grocer`) with the staged `--store`/`--published-out` (no env redirect).
    /// `binary` Some → the per-binary build target (one bin in isolation); None → the whole-repo publish.
    Publish {
        repo: String,
        binary: Option<String>,
    },
    /// Run an owning repo's publisher in CONFIG-SUBSET mode (grocer `--only-configs --config-key <key>`):
    /// re-pin EXACTLY the ONE targeted `kind=config` artifact (tracked-source-checked, CAS-stored,
    /// published-pins read-merge-written; every OTHER config + the binaries byte-preserved). Targeting the
    /// single key is what keeps `--config <key>` narrow — grocer never republishes a SIBLING config, so a
    /// sibling that's ahead of its pin can't red the staged verify and wedge the leg (the M1 fold). NEVER
    /// computes `repo_owns_binary`/`--build-dir` (distinct from [`Step::Publish`]'s whole-repo path) — a
    /// config re-pin needs no binary handoff. The exec arm records the SCOPED CAS swap for this one key +
    /// byte-checks its staged revision against the pin before the swap.
    PublishConfigSubset { repo: String, key: String },
    /// `orchard vendor` — re-vendor the source drops into `orchard/vendor/` from the (staged) store.
    Vendor,
    /// `orchard refresh-apk-lock` — re-resolve + dual-verify (sha256 + Alpine RSA) the apk closure and
    /// rewrite `pinned-apks.toml`. NO binary rebuild (the closure is the rootfs extraction, not a build input).
    RefreshApkLock,
    /// `orchard sync-pins` — regenerate the format-locked `rust-toolchain.toml` + Containerfile FROM.
    SyncPins,
    /// Rebuild the self-assembled build container from the (staged, synced) Containerfile — double-build
    /// repro-check, capture the image digest, pin it as `[rust].container_digest` in every staged
    /// pins.toml. The subsequent `Publish` steps compile each repo's binaries IN this image BY DIGEST
    /// (Component C §7 — the digest the binaries build against IS the digest that gets pinned, so a
    /// concurrent rebuild elsewhere can never substitute it). A non-reproducible rebuild aborts pre-swap.
    RebuildContainer,
    /// Fetch the upstream signed sum for a new `kernel`/`rust` `version` and write it into (staged) pins.toml.
    BumpUpstream {
        which: &'static str,
        version: String,
    },
    /// Re-pin `consume-pins.toml` entries from the freshly-published `published-pins.toml`(s): one key for
    /// `--source`/`--binary`; the produced set for `--rust` (all binaries) / `--all` (the whole set).
    Repin { keys: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("repo manifest: {0}")]
    RepoManifest(#[from] RepoManifestError),
    #[error("pin manifest: {0}")]
    PinManifest(#[from] PinManifestError),
    #[error("--source target {0:?} is not a `kind=source` artifact (use --binary for a binary)")]
    NotSource(String),
    #[error(
        "--binary target {0:?} is not a `kind=binary` artifact (use --source for a source drop)"
    )]
    NotBinary(String),
    #[error(
        "--binary {0:?} is not per-binary-publish-capable — box-init/initramfs-init build as the whole static pair (T9); re-derive them via --rust or the whole-repo publish"
    )]
    NotPerBinary(String),
    #[error(
        "--config target {0:?} is not a `kind=config` artifact (use --source for a source drop, --binary for a binary)"
    )]
    NotConfig(String),
    #[error("target {0:?} has no owning repo in repo-manifest.toml")]
    Unowned(String),
    /// A staging filesystem operation failed (overlay build / stage-write / swap) — fail closed BEFORE the
    /// swap, so the real trees stay untouched (Task 11).
    #[error("market upgrade staging: {0}")]
    Io(#[from] std::io::Error),
    /// `market verify` against the STAGED result failed — the upgrade would break the store, so the swap is
    /// aborted and every tree + the store is left untouched (the AC5 fail-before-swap property). The string
    /// carries the rendered `MarketError` (the failing legs).
    #[error(
        "market upgrade: the staged result failed `market verify` — NOT swapped, every tree + the store is untouched:\n{0}"
    )]
    StagedVerify(String),
    /// One step's effect failed (publish.sh shell-out / vendor / refresh-apk-lock / sync-pins / bump-upstream
    /// / re-pin) — a failure BEFORE the swap, so every tree + the store stays untouched and the executor
    /// exits non-zero naming the step.
    #[error("market upgrade: step `{step}` failed before the swap (trees untouched): {detail}")]
    StepFailed { step: String, detail: String },
}

/// The repos in deterministic (manifest BTreeMap) order that own at least one `kind=binary` artifact.
fn binary_owner_repos(manifest: &RepoManifest, consume: &PinManifest) -> Vec<String> {
    manifest
        .repos
        .iter()
        .filter(|(_, e)| {
            e.artifacts
                .iter()
                .any(|k| matches!(consume.artifact(k), Ok(p) if p.kind == ArtifactKind::Binary))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// All `consume-pins` keys of a given kind, sorted (consume is a BTreeMap, so `.keys()` is already sorted).
fn keys_of_kind(consume: &PinManifest, kind: ArtifactKind) -> Vec<String> {
    consume
        .artifacts
        .iter()
        .filter(|(_, p)| p.kind == kind)
        .map(|(k, _)| k.clone())
        .collect()
}

/// Build the ordered orchestration plan for `target` PURELY (no effects). Validates the target's kind +
/// ownership; errors are returned, never executed.
pub fn plan(
    target: &Target,
    manifest: &RepoManifest,
    consume: &PinManifest,
) -> Result<Vec<Step>, UpgradeError> {
    let owner = |key: &str| -> Result<String, UpgradeError> {
        manifest
            .owner_of(key)
            .map(|(name, _)| name.to_string())
            .ok_or_else(|| UpgradeError::Unowned(key.to_string()))
    };
    let kind =
        |key: &str| -> Result<ArtifactKind, UpgradeError> { Ok(consume.artifact(key)?.kind) };

    match target {
        Target::Source(key) => {
            let repo = owner(key)?;
            if kind(key)? != ArtifactKind::Source {
                return Err(UpgradeError::NotSource(key.clone()));
            }
                                                                                                                
                                                                                               
                                                                                                             
                                                                                                           
            Ok(vec![
                Step::Publish { repo, binary: None },
                Step::Repin {
                    keys: vec![key.clone()],
                },
                Step::Vendor,
            ])
        }
        Target::Binary(key) => {
            let repo = owner(key)?;
            if kind(key)? != ArtifactKind::Binary {
                return Err(UpgradeError::NotBinary(key.clone()));
            }
            let build_bin = PER_BINARY_BUILD
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, b)| b.to_string())
                .ok_or_else(|| UpgradeError::NotPerBinary(key.clone()))?;
                                                                                                          
            Ok(vec![
                Step::Publish {
                    repo,
                    binary: Some(build_bin),
                },
                Step::Repin {
                    keys: vec![key.clone()],
                },
            ])
        }
        Target::Config(key) => {
            let repo = owner(key)?;
            if kind(key)? != ArtifactKind::Config {
                return Err(UpgradeError::NotConfig(key.clone()));
            }
                                                                                                            
                                                                                                          
                                                                                                        
                                                               
            Ok(vec![
                Step::PublishConfigSubset {
                    repo,
                    key: key.clone(),
                },
                Step::Repin {
                    keys: vec![key.clone()],
                },
            ])
        }
                                                                                                      
                                                              
        Target::Apks => Ok(vec![Step::RefreshApkLock]),
                                                                                                            
                                                                             
        Target::Kernel(version) => Ok(vec![
            Step::BumpUpstream {
                which: "kernel",
                version: version.clone(),
            },
            Step::SyncPins,
        ]),
                                                                                                          
                                                                        
        Target::Rust(version) => {
            let mut steps = vec![
                Step::BumpUpstream {
                    which: "rust",
                    version: version.clone(),
                },
                Step::SyncPins,
                                                                                                         
                                                                                                      
                Step::RebuildContainer,
            ];
            for repo in binary_owner_repos(manifest, consume) {
                steps.push(Step::Publish { repo, binary: None });
            }
            steps.push(Step::Repin {
                keys: keys_of_kind(consume, ArtifactKind::Binary),
            });
            Ok(steps)
        }
                                                                                                               
                                                                                              
        Target::All => {
                                                                                                       
                                                                                                         
                                                                                                        
                                                                                                     
                                                                                                             
            let mut steps = vec![Step::RefreshApkLock, Step::SyncPins, Step::RebuildContainer];
            for repo in manifest.repos.keys() {
                steps.push(Step::Publish {
                    repo: repo.clone(),
                    binary: None,
                });
            }
            steps.push(Step::Repin {
                keys: consume.artifacts.keys().cloned().collect(),
            });
            steps.push(Step::Vendor);
            Ok(steps)
        }
    }
}

/// Render a step as a one-line operator-facing description (for the `market upgrade` plan preview).
fn describe(step: &Step) -> String {
    match step {
        Step::Publish {
            repo,
            binary: Some(bin),
        } => format!("publish {repo} (per-binary: {bin}) → staged published-pins + store"),
        Step::Publish { repo, binary: None } => {
            format!("publish {repo} (whole-repo) → staged published-pins + store")
        }
        Step::PublishConfigSubset { repo, key } => {
            format!(
                "publish {repo} (config-subset: {key}) → tracked-source-checked config, staged published-pins read-merge-write + CAS store"
            )
        }
        Step::Vendor => {
            "orchard vendor → re-vendor the source drops into orchard/vendor/".to_string()
        }
        Step::RefreshApkLock => {
            "orchard refresh-apk-lock → re-resolve + dual-verify the apk closure".to_string()
        }
        Step::SyncPins => "orchard sync-pins → regenerate the format-locked files".to_string(),
        Step::RebuildContainer => {
            "docker build the container (double-build repro-check) → pin its \
             digest as [rust].container_digest; binaries then build in it BY DIGEST"
                .to_string()
        }
        Step::BumpUpstream { which, version } => {
            let anchor = match *which {
                "kernel" => "cashew vs keyring/kernel.org (the .tar.sign over the tarball)",
                "rust" => "cashew vs keyring/rust-lang (the .asc over the release manifest)",
                _ => "cashew vs the vendored keyring",
            };
            format!(
                "bump {which} → {version}: fetch + PGP-verify the upstream artifact ({anchor}), \
                 then rewrite EVERY staged pins.toml copy"
            )
        }
        Step::Repin { keys } => format!("re-pin consume-pins.toml: {}", keys.join(", ")),
    }
}

/// The operator-facing preview of a planned upgrade (Task 10 prints this; Task 11 executes it). Honest that
/// nothing has run + nothing is committed.
pub fn render_plan(target: &Target, steps: &[Step]) -> String {
    let mut s = format!(
        "market upgrade {target:?} — planned orchestration (NOTHING run; NEVER auto-commits — review the diff):\n"
    );
    for (i, step) in steps.iter().enumerate() {
        s.push_str(&format!("  {}. {}\n", i + 1, describe(step)));
    }
    s.push_str("  (execution = the stage-then-swap path, Task 11)");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
schema-version = 1
[repos.seed-vault]
path = "../seed-vault"
artifacts = ["grape-src", "dragonfruit-src"]
[repos.fruit-basket]
path = "../fruit-basket"
artifacts = ["fb-acme", "box-init", "rambutan-src"]
[repos.recipes]
path = "../../recipes"
artifacts = ["recipes-app", "recipes-admin", "service-manifest"]
"#;

    fn fixtures() -> (RepoManifest, PinManifest) {
        let m = RepoManifest::from_toml_str(MANIFEST).unwrap();
        let sha = "a".repeat(64);
        let mut c = String::from("schema-version = 1\n");
        for (k, kind) in [
            ("grape-src", "source"),
            ("dragonfruit-src", "source"),
            ("rambutan-src", "source"),
            ("fb-acme", "binary"),
            ("box-init", "binary"),
            ("recipes-app", "binary"),
            ("recipes-admin", "binary"),
            ("service-manifest", "config"),
        ] {
            c.push_str(&format!(
                "[artifacts.{k}]\nsha256 = \"{sha}\"\nkind = \"{kind}\"\n"
            ));
        }
        (m, PinManifest::from_toml_str(&c).unwrap())
    }

    fn plan_of(t: Target) -> Vec<Step> {
        let (m, c) = fixtures();
        plan(&t, &m, &c).expect("plans")
    }

    #[test]
    fn source_leg_publishes_repins_then_vendors_only_its_entry() {
                                                                                                          
                                                                                        
        assert_eq!(
            plan_of(Target::Source("dragonfruit-src".into())),
            vec![
                Step::Publish {
                    repo: "seed-vault".into(),
                    binary: None
                },
                Step::Repin {
                    keys: vec!["dragonfruit-src".into()]
                },
                Step::Vendor,
            ]
        );
    }

    #[test]
    fn binary_leg_uses_the_per_binary_target_and_repins_one_entry() {
                                                                                             
        assert_eq!(
            plan_of(Target::Binary("recipes-app".into())),
            vec![
                Step::Publish {
                    repo: "recipes".into(),
                    binary: Some("recipes".into())
                },
                Step::Repin {
                    keys: vec!["recipes-app".into()]
                },
            ]
        );
        assert_eq!(
            plan_of(Target::Binary("fb-acme".into()))[0],
            Step::Publish {
                repo: "fruit-basket".into(),
                binary: Some("fb-acme".into())
            }
        );
    }

    #[test]
    fn binary_leg_rejects_the_non_per_binary_static_pair() {
        let (m, c) = fixtures();
        assert!(matches!(
            plan(&Target::Binary("box-init".into()), &m, &c),
            Err(UpgradeError::NotPerBinary(_))
        ));
    }

    #[test]
    fn apks_leg_does_not_rebuild_binaries() {
                                                                                                           
        assert_eq!(plan_of(Target::Apks), vec![Step::RefreshApkLock]);
    }

    #[test]
    fn kernel_leg_bumps_pins_and_syncs_without_repinning_binaries() {
        assert_eq!(
            plan_of(Target::Kernel("6.19.0".into())),
            vec![
                Step::BumpUpstream {
                    which: "kernel",
                    version: "6.19.0".into()
                },
                Step::SyncPins,
            ]
        );
    }

    #[test]
    fn rust_leg_cascades_to_all_binaries() {
        let steps = plan_of(Target::Rust("1.97.0".into()));
                                                                                                     
                                                    
        assert_eq!(
            steps[0],
            Step::BumpUpstream {
                which: "rust",
                version: "1.97.0".into()
            }
        );
        assert_eq!(steps[1], Step::SyncPins);
                                                                                                   
        assert_eq!(steps[2], Step::RebuildContainer);
        assert!(steps.contains(&Step::Publish {
            repo: "fruit-basket".into(),
            binary: None
        }));
        assert!(steps.contains(&Step::Publish {
            repo: "recipes".into(),
            binary: None
        }));
        assert!(!steps.contains(&Step::Publish {
            repo: "seed-vault".into(),
            binary: None
        }));
        let repin = steps.last().unwrap();
        assert_eq!(
            repin,
            &Step::Repin {
                keys: vec![
                    "box-init".into(),
                    "fb-acme".into(),
                    "recipes-admin".into(),
                    "recipes-app".into()
                ]
            }
        );
    }

    #[test]
    fn all_leg_refreshes_publishes_every_repo_repins_the_whole_set_then_vendors() {
        let steps = plan_of(Target::All);
        assert_eq!(steps[0], Step::RefreshApkLock);
                                                                                                         
                                                                                                      
        assert_eq!(steps[1], Step::SyncPins);
        assert_eq!(steps[2], Step::RebuildContainer);
                                                                                                            
        assert_eq!(steps.last().unwrap(), &Step::Vendor);
                                                                                        
        for repo in ["fruit-basket", "recipes", "seed-vault"] {
            assert!(steps.contains(&Step::Publish {
                repo: repo.into(),
                binary: None
            }));
        }
                                                                                             
        match &steps[steps.len() - 2] {
            Step::Repin { keys } => assert_eq!(keys.len(), 8),
            other => panic!("expected a Repin before the final Vendor, got {other:?}"),
        }
    }

    #[test]
    fn source_leg_rejects_a_binary_key() {
        let (m, c) = fixtures();
        assert!(matches!(
            plan(&Target::Source("fb-acme".into()), &m, &c),
            Err(UpgradeError::NotSource(_))
        ));
    }

                                                                       

    /// A self-contained dha fixture (creatine-serve + uds-pipe binaries + a dha-epa-config config) — kept
    /// SEPARATE from `fixtures()` so the existing whole-set plan asserts (rust/all legs) don't shift.
    fn dha_fixtures() -> (RepoManifest, PinManifest) {
        let m = RepoManifest::from_toml_str(
            r#"
schema-version = 1
[repos.dha]
path = "../../dha"
artifacts = ["creatine-serve", "uds-pipe", "dha-epa-config"]
"#,
        )
        .unwrap();
        let sha = "a".repeat(64);
        let mut c = String::from("schema-version = 1\n");
        for (k, kind) in [
            ("creatine-serve", "binary"),
            ("uds-pipe", "binary"),
            ("dha-epa-config", "config"),
        ] {
            c.push_str(&format!(
                "[artifacts.{k}]\nsha256 = \"{sha}\"\nkind = \"{kind}\"\n"
            ));
        }
        (m, PinManifest::from_toml_str(&c).unwrap())
    }

    #[test]
    fn config_leg_publishes_config_subset_then_repins_only_its_entry() {
                                                                                                            
        let (m, c) = dha_fixtures();
        assert_eq!(
            plan(&Target::Config("dha-epa-config".into()), &m, &c).unwrap(),
            vec![
                Step::PublishConfigSubset {
                    repo: "dha".into(),
                    key: "dha-epa-config".into()
                },
                Step::Repin {
                    keys: vec!["dha-epa-config".into()]
                },
            ]
        );
    }

    #[test]
    fn config_leg_rejects_a_non_config_key() {
                                                                                                
        let (m, c) = dha_fixtures();
        assert!(matches!(
            plan(&Target::Config("uds-pipe".into()), &m, &c),
            Err(UpgradeError::NotConfig(_))
        ));
    }

    #[test]
    fn config_leg_rejects_an_unowned_key() {
        let (m, c) = dha_fixtures();
        assert!(matches!(
            plan(&Target::Config("nosuch".into()), &m, &c),
            Err(UpgradeError::Unowned(_))
        ));
    }

    #[test]
    fn binary_leg_plans_the_uds_pipe_and_creatine_serve_riders() {
                                                                                                                
        let (m, c) = dha_fixtures();
        assert_eq!(
            plan(&Target::Binary("uds-pipe".into()), &m, &c).unwrap()[0],
            Step::Publish {
                repo: "dha".into(),
                binary: Some("uds-pipe".into())
            }
        );
        assert_eq!(
            plan(&Target::Binary("creatine-serve".into()), &m, &c).unwrap()[0],
            Step::Publish {
                repo: "dha".into(),
                binary: Some("creatine-serve".into())
            }
        );
    }
}
