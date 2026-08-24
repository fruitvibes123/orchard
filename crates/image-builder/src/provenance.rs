//! Pin provenance (lifted from `tests/pins_provenance.rs`, 2026-06-23): every consume-pin's sha256 must
//! equal the OWNING repo's committed `published-pins.toml` sha. `consume-pins.toml` is the un-hashed root
//! of the verify chain (its integrity rests on pin-bump review); this turns that link into a TESTED
//! invariant. Driven by the repo-manifest (NOT the old hardcoded `OWNERS` + `fruit-ecosystem/<name>`
//! derivation, which mis-resolved `recipes` — outside fruit-ecosystem — and so never actually checked it).
                                                                                                

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::pin_manifest::PinManifest;
use crate::repo_manifest::RepoManifest;

/// The flat `[artifacts]` name -> sha256 map a publishing repo commits (publish.sh emits `schema-version`
/// + `[artifacts]`). Strict: an unknown top-level key is refused (mirrors the pin-manifest discipline).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedPins {
    #[serde(rename = "schema-version")]
    _schema_version: u32,
    artifacts: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error(
        "owning repo {repo:?} (for {artifacts:?}) is absent at {path} — pass `--allow-missing {repo}` for a partial-checkout dev loop"
    )]
    RepoAbsent {
        repo: String,
        path: String,
        artifacts: Vec<String>,
    },
    #[error("parse {path}: {reason}")]
    Parse { path: String, reason: String },
    #[error(
        "consume-pins <-> published-pins DIVERGENCE (re-run `make publish` in the owning repo, then re-pin consume-pins.toml):\n{0}"
    )]
    Divergence(String),
}

#[derive(Debug, Default)]
pub struct ProvenanceReport {
    /// Number of artifact provenance links verified (consume == published).
    pub checked: usize,
    /// Owning repos skipped because absent + explicitly allow-missing'd.
    pub skipped: Vec<String>,
}

/// Verify every consume-pin's sha == the owning repo's published-pins sha. `repo_root` is the orchard repo
/// root (the manifest's repo paths are relative to it). An owning repo absent at its configured path is a
/// HARD FAIL unless its name is in `allow_missing` (then its artifacts are skipped + recorded). A
/// present-but-divergent published sha is a HARD FAIL. Caller has already run `assert_artifact_set`, so
/// every manifest artifact is present in `consume`.
pub fn verify_provenance(
    manifest: &RepoManifest,
    consume: &PinManifest,
    repo_root: &Path,
    allow_missing: &[String],
) -> Result<ProvenanceReport, ProvenanceError> {
    let mut report = ProvenanceReport::default();
    let mut divergent: Vec<String> = Vec::new();

    for (repo, entry) in &manifest.repos {
        let pub_path = repo_root.join(&entry.path).join("published-pins.toml");
        let text = match std::fs::read_to_string(&pub_path) {
            Ok(t) => t,
            Err(_) => {
                if allow_missing.iter().any(|r| r == repo) {
                    report.skipped.push(repo.clone());
                    continue;
                }
                return Err(ProvenanceError::RepoAbsent {
                    repo: repo.clone(),
                    path: pub_path.display().to_string(),
                    artifacts: entry.artifacts.clone(),
                });
            }
        };
        let published: PublishedPins =
            toml::from_str(&text).map_err(|e| ProvenanceError::Parse {
                path: pub_path.display().to_string(),
                reason: e.to_string(),
            })?;
        for key in &entry.artifacts {
            report.checked += 1;
            let consume_sha = match consume.artifact(key) {
                Ok(p) => &p.sha256,
                Err(_) => {
                    divergent.push(format!(
                        "{key}: owned by {repo} but absent from consume-pins"
                    ));
                    continue;
                }
            };
            match published.artifacts.get(key) {
                Some(pub_sha) if pub_sha == consume_sha => {}
                Some(pub_sha) => divergent.push(format!(
                    "{key}: consume={consume_sha} != {repo}/published={pub_sha}"
                )),
                None => divergent.push(format!(
                    "{key}: in consume-pins but MISSING from {repo}/published-pins.toml"
                )),
            }
        }
    }

    if !divergent.is_empty() {
        return Err(ProvenanceError::Divergence(divergent.join("\n")));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture {
        _tmp: tempfile::TempDir,
        repo_root: PathBuf,
        manifest: RepoManifest,
        consume: PinManifest,
    }

    /// A temp ecosystem: `<tmp>/orchard` (repo_root) with consume-pins + repo-manifest, and sibling repo
    /// dirs `<tmp>/{seed-vault,recipes}` each with a published-pins.toml. `divergent` flips one repo's
    /// published sha; `omit_repo` skips creating one repo dir.
    fn build(divergent: Option<&str>, omit_repo: Option<&str>) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let orchard = root.join("orchard");
        std::fs::create_dir_all(&orchard).unwrap();

        let good = "a".repeat(64);
        std::fs::write(
            orchard.join("consume-pins.toml"),
            format!(
                "schema-version = 1\n[artifacts.grape-src]\nsha256 = \"{good}\"\nkind = \"source\"\n\
                 [artifacts.recipes-app]\nsha256 = \"{good}\"\nkind = \"binary\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            orchard.join("repo-manifest.toml"),
            "schema-version = 1\n\
             [repos.seed-vault]\npath = \"../seed-vault\"\nartifacts = [\"grape-src\"]\n\
             [repos.recipes]\npath = \"../recipes\"\nartifacts = [\"recipes-app\"]\n",
        )
        .unwrap();

        for (repo, key) in [("seed-vault", "grape-src"), ("recipes", "recipes-app")] {
            if omit_repo == Some(repo) {
                continue;
            }
            let sha = if divergent == Some(repo) {
                "b".repeat(64)
            } else {
                good.clone()
            };
            let dir = root.join(repo);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("published-pins.toml"),
                format!("schema-version = 1\n[artifacts]\n{key} = \"{sha}\"\n"),
            )
            .unwrap();
        }

        Fixture {
            manifest: RepoManifest::load(&orchard.join("repo-manifest.toml")).unwrap(),
            consume: PinManifest::load(&orchard.join("consume-pins.toml")).unwrap(),
            repo_root: orchard,
            _tmp: tmp,
        }
    }

    #[test]
    fn matched_provenance_passes() {
        let f = build(None, None);
        let r = verify_provenance(&f.manifest, &f.consume, &f.repo_root, &[]).expect("matched");
        assert_eq!(r.checked, 2);
        assert!(r.skipped.is_empty());
    }

    #[test]
    fn divergent_published_sha_fails_closed() {
        let f = build(Some("seed-vault"), None);
        assert!(matches!(
            verify_provenance(&f.manifest, &f.consume, &f.repo_root, &[]),
            Err(ProvenanceError::Divergence(_))
        ));
    }

    #[test]
    fn absent_repo_is_hard_fail_unless_allow_missing() {
        let f = build(None, Some("recipes"));
        assert!(
            matches!(
                verify_provenance(&f.manifest, &f.consume, &f.repo_root, &[]),
                Err(ProvenanceError::RepoAbsent { .. })
            ),
            "an absent owning repo must fail closed by default"
        );
        let r = verify_provenance(
            &f.manifest,
            &f.consume,
            &f.repo_root,
            &["recipes".to_string()],
        )
        .expect("allow-missing recipes");
        assert_eq!(r.skipped, vec!["recipes".to_string()]);
        assert_eq!(r.checked, 1, "the present repo is still checked");
    }
}
