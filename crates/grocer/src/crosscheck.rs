//! The fail-closed allowlist that stops a buggy/hostile `publish-manifest.toml` from publishing the WRONG
                                                                                                   
//!
//! - `sanitize_source` — every `source` must be a relative, in-base path (no absolute, no `..`), so a
//!   `source = "../../etc/passwd"` can never read outside `--build-dir`/the repo root.
//! - `cross_check` — the publish-manifest must agree with TWO independent authorities a single hostile
//!   manifest edit cannot control: its KEY set must exactly equal `repo-manifest.toml`'s `repos[repo].artifacts`
//!   (both directions), and each artifact's KIND must equal that key's authoritative `ArtifactKind` in
//!   `consume-pins.toml` (so a binary->config flip that would dodge the kind-gated handling fails closed).

use std::collections::BTreeSet;
use std::path::{Component, Path};

use recipes_image_builder::pin_manifest::{ArtifactKind, PinManifest};
use recipes_image_builder::repo_manifest::RepoManifest;

use crate::publish_manifest::PublishManifest;

#[derive(Debug, thiserror::Error)]
pub enum CrossError {
    #[error(
        "publish-manifest source {value:?} is unsafe: {why} (must be a relative in-base path)"
    )]
    BadSource { value: String, why: &'static str },
    #[error("repo {0:?} is not in repo-manifest.toml")]
    UnknownRepo(String),
    #[error(
        "publish-manifest key set for repo {repo:?} diverges from repo-manifest — missing {missing:?}, extra {extra:?}"
    )]
    KeySetMismatch {
        repo: String,
        missing: Vec<String>,
        extra: Vec<String>,
    },
    #[error("publish-manifest key {0:?} is not in consume-pins.toml (the kind authority)")]
    KeyNotInConsume(String),
    #[error(
        "publish-manifest key {key:?} declares kind={declared:?} but consume-pins says {authority:?} — REFUSING (kind-flip)"
    )]
    KindMismatch {
        key: String,
        declared: ArtifactKind,
        authority: ArtifactKind,
    },
    #[error(
        "source dir {dir:?} has untracked files {entries:?} — refusing to publish accidental pollution (commit or remove them; deliberate TRACKED edits are fine)"
    )]
    UntrackedFiles { dir: String, entries: Vec<String> },
    #[error("git status failed for {dir:?}: {msg}")]
    GitStatus { dir: String, msg: String },
    #[error(
        "config source {src:?} (key {key:?}) is UNTRACKED in git — a config-subset publish requires a \
         COMMITTED source, never a generated/untracked file (`git add` it first): {msg}"
    )]
    UntrackedConfigSource {
        key: String,
        src: String,
        msg: String,
    },
    #[error(
        "config source {src:?} (key {key:?}) is a SYMLINK — a config-subset publish stores a plain \
         committed file's OWN bytes, never a link's dereferenced target (which can point outside the \
         repo); replace the symlink with the real file"
    )]
    SymlinkConfigSource { key: String, src: String },
}

/// A `source` must be a RELATIVE path with no `..` component, so joining it onto its base dir (the repo root
                                                                                                  
pub fn sanitize_source(source: &str) -> Result<(), CrossError> {
    if source.is_empty() {
        return Err(CrossError::BadSource {
            value: source.to_string(),
            why: "empty",
        });
    }
    let p = Path::new(source);
    if p.is_absolute() {
        return Err(CrossError::BadSource {
            value: source.to_string(),
            why: "absolute path",
        });
    }
    for c in p.components() {
        match c {
            Component::ParentDir => {
                return Err(CrossError::BadSource {
                    value: source.to_string(),
                    why: "contains `..`",
                });
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(CrossError::BadSource {
                    value: source.to_string(),
                    why: "rooted/prefixed path",
                });
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }
    Ok(())
}

                                                                                                       
/// invocation forms (the executor passes `--repo`/`--repo-manifest`/`--consume-pins`).
pub fn cross_check(
    manifest: &PublishManifest,
    repo: &str,
    repo_manifest: &RepoManifest,
    consume: &PinManifest,
) -> Result<(), CrossError> {
                                                                           
    let entry = repo_manifest
        .repos
        .get(repo)
        .ok_or_else(|| CrossError::UnknownRepo(repo.to_string()))?;
    let expected: BTreeSet<&str> = entry.artifacts.iter().map(String::as_str).collect();
    let declared: BTreeSet<&str> = manifest.artifact.iter().map(|a| a.key.as_str()).collect();
    if declared != expected {
        return Err(CrossError::KeySetMismatch {
            repo: repo.to_string(),
            missing: expected
                .difference(&declared)
                .map(|s| s.to_string())
                .collect(),
            extra: declared
                .difference(&expected)
                .map(|s| s.to_string())
                .collect(),
        });
    }
                                                              
    for a in &manifest.artifact {
        let pin = consume
            .artifacts
            .get(&a.key)
            .ok_or_else(|| CrossError::KeyNotInConsume(a.key.clone()))?;
        if a.kind != pin.kind {
            return Err(CrossError::KindMismatch {
                key: a.key.clone(),
                declared: a.kind,
                authority: pin.kind,
            });
        }
    }
    Ok(())
}

/// Refuse to publish a source drop whose crate dir carries UNTRACKED files (editor backups, build droppings,
                                                                                                               
/// TRACKED modifications are ALLOWED: a deliberate source edit IS the legitimate bump path (its backstop is the
/// git pin-diff review, not this guard). `target/` is gitignored, so it never appears as untracked.
pub fn assert_no_untracked(crate_dir: &Path) -> Result<(), CrossError> {
    let git_err = |msg: String| CrossError::GitStatus {
        dir: crate_dir.display().to_string(),
        msg,
    };
                                                                                                  
                                                                                                   
                                                                                   
    let out = std::process::Command::new("git")
        .current_dir(crate_dir)
        .args(["--no-optional-locks", "status", "--porcelain", "--", "."])
        .output()
        .map_err(|e| git_err(e.to_string()))?;
    if !out.status.success() {
        return Err(git_err(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let untracked: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("??"))
        .map(|l| l[2..].trim().to_string())
        .collect();
    if !untracked.is_empty() {
        return Err(CrossError::UntrackedFiles {
            dir: crate_dir.display().to_string(),
            entries: untracked,
        });
    }
    Ok(())
}

                                                                                                      
/// subset re-pin publishes ONE config file's bytes, so it must be a committed source — never a generated
/// or untracked one silently swept into the store. `git ls-files --error-unmatch <source>` exits non-zero
/// iff `source` is not tracked. Distinct from [`assert_no_untracked`] (which polices a source-drop DIR for
/// pollution); this polices that the ONE named FILE is committed. Read-only (`--no-optional-locks`).
pub fn assert_tracked_source(repo_root: &Path, key: &str, source: &str) -> Result<(), CrossError> {
    let out = std::process::Command::new("git")
        .current_dir(repo_root)
        .args([
            "--no-optional-locks",
            "ls-files",
            "--error-unmatch",
            "--",
            source,
        ])
        .output()
        .map_err(|e| CrossError::GitStatus {
            dir: repo_root.display().to_string(),
            msg: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(CrossError::UntrackedConfigSource {
            key: key.to_string(),
            src: source.to_string(),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
                                                                                                  
                                                                                                      
                                                                                                        
                                                                                                    
                                                                                                         
                                                               
    if repo_root.join(source).is_symlink() {
        return Err(CrossError::SymlinkConfigSource {
            key: key.to_string(),
            src: source.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_source_guard_refuses_an_untracked_config_file() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::create_dir_all(repo.join("deploy")).unwrap();
        std::fs::write(repo.join("deploy/committed.json"), b"{}").unwrap();
        let git = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .current_dir(repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["add", "deploy/committed.json"]);
        git(&["commit", "-q", "-m", "init"]);
                                         
        assert!(assert_tracked_source(repo, "k", "deploy/committed.json").is_ok());
                                                             
        std::fs::write(repo.join("deploy/generated.json"), b"{}").unwrap();
        assert!(
            matches!(
                assert_tracked_source(repo, "cfg", "deploy/generated.json"),
                Err(CrossError::UntrackedConfigSource { .. })
            ),
            "an untracked config source must be refused"
        );
    }

    #[test]
    fn sanitize_accepts_relative_in_base_and_refuses_escapes() {
        assert!(sanitize_source("crates/grape").is_ok());
        assert!(sanitize_source("release/recipes").is_ok());
        for bad in ["/etc/passwd", "../x", "a/../../b", "..", ""] {
            assert!(
                matches!(sanitize_source(bad), Err(CrossError::BadSource { .. })),
                "{bad:?} must be refused"
            );
        }
    }

                                                          
    fn repo_manifest() -> RepoManifest {
        RepoManifest::from_toml_str(
            r#"
schema-version = 1
[repos.seed-vault]
path = "../seed-vault"
artifacts = ["grape-src", "dragonfruit-src"]
"#,
        )
        .unwrap()
    }
    fn consume() -> PinManifest {
        PinManifest::from_toml_str(&format!(
            "schema-version = 1\n[artifacts]\ngrape-src = {{ sha256 = \"{z}\", kind = \"source\" }}\ndragonfruit-src = {{ sha256 = \"{z}\", kind = \"source\" }}\nrecipes-app = {{ sha256 = \"{z}\", kind = \"binary\" }}\n",
            z = "0".repeat(64)
        ))
        .unwrap()
    }
    fn manifest(body: &str) -> PublishManifest {
        PublishManifest::from_toml_str(body).unwrap()
    }

    const GOOD: &str = r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "source"
source = "crates/grape"
[[artifact]]
key = "dragonfruit-src"
kind = "source"
source = "crates/dragonfruit"
"#;

    #[test]
    fn cross_check_passes_on_a_matching_manifest() {
        assert!(cross_check(&manifest(GOOD), "seed-vault", &repo_manifest(), &consume()).is_ok());
    }

    #[test]
    fn cross_check_refuses_an_extra_key() {
        let m = manifest(
            r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "source"
source = "crates/grape"
[[artifact]]
key = "dragonfruit-src"
kind = "source"
source = "crates/dragonfruit"
[[artifact]]
key = "recipes-app"
kind = "binary"
source = "release/recipes"
linkage = "dynamic"
"#,
        );
        assert!(matches!(
            cross_check(&m, "seed-vault", &repo_manifest(), &consume()),
            Err(CrossError::KeySetMismatch { .. })
        ));
    }

    #[test]
    fn cross_check_refuses_a_missing_key() {
        let m = manifest(
            r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "source"
source = "crates/grape"
"#,
        );
        assert!(matches!(
            cross_check(&m, "seed-vault", &repo_manifest(), &consume()),
            Err(CrossError::KeySetMismatch { .. })
        ));
    }

    #[test]
    fn cross_check_refuses_a_kind_flip() {
                                                                                                             
                                                                 
        let m = manifest(
            r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "config"
source = "crates/grape"
[[artifact]]
key = "dragonfruit-src"
kind = "source"
source = "crates/dragonfruit"
"#,
        );
        assert!(matches!(
            cross_check(&m, "seed-vault", &repo_manifest(), &consume()),
            Err(CrossError::KindMismatch { .. })
        ));
    }

    #[test]
    fn cross_check_refuses_an_unknown_repo() {
        assert!(matches!(
            cross_check(&manifest(GOOD), "nope", &repo_manifest(), &consume()),
            Err(CrossError::UnknownRepo(_))
        ));
    }

    #[test]
    fn untracked_guard_refuses_untracked_allows_tracked_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let crate_dir = repo.join("crates/x");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("lib.rs"), b"fn a() {}").unwrap();
        let git = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .current_dir(repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "init"]);

                           
        assert!(assert_no_untracked(&crate_dir).is_ok());

                                                                        
        std::fs::write(crate_dir.join("lib.rs"), b"fn a() { /* edited */ }").unwrap();
        assert!(
            assert_no_untracked(&crate_dir).is_ok(),
            "tracked edits must be allowed"
        );

                                       
        std::fs::write(crate_dir.join("lib.rs.bak"), b"editor backup").unwrap();
        assert!(
            matches!(
                assert_no_untracked(&crate_dir),
                Err(CrossError::UntrackedFiles { .. })
            ),
            "untracked pollution must be refused"
        );
    }
}
