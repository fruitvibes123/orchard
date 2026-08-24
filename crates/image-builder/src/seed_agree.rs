//! Cross-repo seed agreement (lifted from `tests/pins_agree.rs`, 2026-06-23): every fruit-ecosystem repo
//! vendors a copy of the Seed-Vault `pins.toml`; orchard (the assembler) confirms they all byte-AGREE
//! before it consumes any pinned artifact, so two repos can't silently build against divergent
//! toolchains/containers. Manifest-driven: the canonical is `seed-vault/pins.toml`; the compared copies are
//! orchard's own (the repo root) + every other owning repo's. (The old test joined `fruit-ecosystem/recipes`
//! — which doesn't exist — so recipes' copy was never actually checked; the manifest fixes that.) An absent
                                                                                                        

use std::path::{Path, PathBuf};

use crate::repo_manifest::RepoManifest;

/// The canonical-owning repo in the manifest (its `pins.toml` is the reference all others must match).
const CANONICAL_REPO: &str = "seed-vault";

#[derive(Debug, thiserror::Error)]
pub enum SeedAgreeError {
    #[error("repo-manifest has no `{CANONICAL_REPO}` entry (the canonical pins.toml owner)")]
    NoCanonicalRepo,
    #[error(
        "canonical seed pins.toml absent at {0} (pass `--allow-missing {CANONICAL_REPO}` to skip)"
    )]
    CanonicalAbsent(String),
    #[error("{repo:?} pins.toml absent at {path} — pass `--allow-missing {repo}` for a partial-checkout dev loop")]
    RepoAbsent { repo: String, path: String },
    #[error(
        "repo seed(s) diverge from {CANONICAL_REPO}/pins.toml: {0}. Sync the copy + run `make pins` in each, then commit."
    )]
    Divergence(String),
}

#[derive(Debug, Default)]
pub struct SeedAgreeReport {
    /// Number of repo `pins.toml` copies byte-compared against the canonical.
    pub checked: usize,
    /// Repos skipped because absent + explicitly allow-missing'd.
    pub skipped: Vec<String>,
}

/// Verify every present repo's `pins.toml` byte-matches `seed-vault`'s canonical copy. `repo_root` is the
/// orchard repo root (whose own `pins.toml` is one of the compared copies; the manifest's repo paths are
/// relative to it). An absent copy is a HARD FAIL unless its repo is in `allow_missing`.
pub fn verify_seeds_agree(
    manifest: &RepoManifest,
    repo_root: &Path,
    allow_missing: &[String],
) -> Result<SeedAgreeReport, SeedAgreeError> {
    let canonical_dir = manifest
        .repo_path(CANONICAL_REPO, repo_root)
        .ok_or(SeedAgreeError::NoCanonicalRepo)?;
    let canonical_path = canonical_dir.join("pins.toml");
    let canonical = match std::fs::read_to_string(&canonical_path) {
        Ok(c) => c,
        Err(_) => {
                                                                         
            if allow_missing.iter().any(|r| r == CANONICAL_REPO) {
                return Ok(SeedAgreeReport {
                    checked: 0,
                    skipped: vec![CANONICAL_REPO.to_string()],
                });
            }
            return Err(SeedAgreeError::CanonicalAbsent(
                canonical_path.display().to_string(),
            ));
        }
    };

                                                                                                     
    let mut compared: Vec<(String, PathBuf)> =
        vec![("orchard".to_string(), repo_root.to_path_buf())];
    for name in manifest.repos.keys() {
        if name != CANONICAL_REPO {
            if let Some(dir) = manifest.repo_path(name, repo_root) {
                compared.push((name.clone(), dir));
            }
        }
    }

    let mut report = SeedAgreeReport::default();
    let mut divergent: Vec<String> = Vec::new();
    for (name, dir) in compared {
        let p = dir.join("pins.toml");
        match std::fs::read_to_string(&p) {
            Ok(copy) if copy == canonical => report.checked += 1,
            Ok(_) => divergent.push(name),
            Err(_) => {
                if allow_missing.iter().any(|r| r == &name) {
                    report.skipped.push(name);
                } else {
                    return Err(SeedAgreeError::RepoAbsent {
                        repo: name,
                        path: p.display().to_string(),
                    });
                }
            }
        }
    }

    if !divergent.is_empty() {
        return Err(SeedAgreeError::Divergence(divergent.join(", ")));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `<tmp>/orchard` (repo_root) with repo-manifest + its own pins.toml; sibling repo dirs
    /// `<tmp>/{seed-vault,fruit-basket,recipes}` each with a pins.toml. `divergent` drifts one repo's copy;
    /// `omit` skips creating one repo dir. Returns (tmp, repo_root, manifest).
    fn build(
        divergent: Option<&str>,
        omit: Option<&str>,
    ) -> (tempfile::TempDir, PathBuf, RepoManifest) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let orchard = root.join("orchard");
        std::fs::create_dir_all(&orchard).unwrap();

        let canonical = "[kernel]\nversion = \"6.18.34\"\nsha256 = \"deadbeef\"\n";
        std::fs::write(
            orchard.join("repo-manifest.toml"),
            "schema-version = 1\n\
             [repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n\
             [repos.fruit-basket]\npath = \"../fruit-basket\"\nartifacts = [\"box-init\"]\n\
             [repos.recipes]\npath = \"../recipes\"\nartifacts = [\"recipes-app\"]\n",
        )
        .unwrap();
                                                                 
        std::fs::write(orchard.join("pins.toml"), canonical).unwrap();

        for repo in ["seed-vault", "fruit-basket", "recipes"] {
            if omit == Some(repo) {
                continue;
            }
            let body = if divergent == Some(repo) {
                format!("{canonical}# drift\n")
            } else {
                canonical.to_string()
            };
            let dir = root.join(repo);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("pins.toml"), body).unwrap();
        }

        let manifest = RepoManifest::load(&orchard.join("repo-manifest.toml")).unwrap();
        (tmp, orchard, manifest)
    }

    #[test]
    fn matched_seeds_agree() {
        let (_t, root, m) = build(None, None);
        let r = verify_seeds_agree(&m, &root, &[]).expect("agree");
                                                                                                    
        assert_eq!(r.checked, 3);
    }

    #[test]
    fn divergent_copy_fails_closed() {
        let (_t, root, m) = build(Some("fruit-basket"), None);
        assert!(matches!(
            verify_seeds_agree(&m, &root, &[]),
            Err(SeedAgreeError::Divergence(_))
        ));
    }

    #[test]
    fn absent_repo_is_hard_fail_unless_allow_missing() {
        let (_t, root, m) = build(None, Some("recipes"));
        assert!(matches!(
            verify_seeds_agree(&m, &root, &[]),
            Err(SeedAgreeError::RepoAbsent { .. })
        ));
        let r = verify_seeds_agree(&m, &root, &["recipes".to_string()]).expect("allow-missing");
        assert_eq!(r.skipped, vec!["recipes".to_string()]);
        assert_eq!(r.checked, 2);
    }

    #[test]
    fn absent_canonical_is_hard_fail_unless_allow_missing() {
        let (_t, root, m) = build(None, Some("seed-vault"));
        assert!(matches!(
            verify_seeds_agree(&m, &root, &[]),
            Err(SeedAgreeError::CanonicalAbsent(_))
        ));
        let r = verify_seeds_agree(&m, &root, &["seed-vault".to_string()]).expect("allow-missing");
        assert_eq!(r.checked, 0);
        assert_eq!(r.skipped, vec!["seed-vault".to_string()]);
    }
}
