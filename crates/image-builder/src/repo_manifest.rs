//! The configured owning-repo manifest (`repo-manifest.toml`): `repo -> { path, artifacts }`.
//!
//! Replaces the hardcoded `OWNERS` const + the implicit `fruit-ecosystem/<name>` path derivation that
//! `tests/pins_provenance.rs` used (which mis-resolved `recipes` — that repo lives OUTSIDE
//! `fruit-ecosystem/`, at `../../recipes`). The verify loop is driven BY this manifest, so it is itself a
//! verify root: `market verify` asserts its artifact set EXACTLY equals `consume-pins`'s (fail-closed on
                                                                                                           
//! parse (`deny_unknown_fields`), mirroring `pin_manifest.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::pin_manifest::PinManifest;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    /// The owning repo's root, relative to the orchard repo root (the cwd `market` runs from):
    /// `../seed-vault`, `../fruit-basket`, `../../recipes` (recipes is OUTSIDE fruit-ecosystem).
    pub path: String,
    /// The `consume-pins` artifact keys this repo publishes.
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoManifest {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
                                                                                                       
    /// orchard repo root. It lives in the COOKBOOK launchpad (a sibling repo), NOT orchard — the trail and
    /// the pin store were split apart post-monorepo — so this is a configured cross-repo path
    /// (`../../cookbook/trail`), declared data rather than a magic constant. Optional: a manifest
    /// without it leaves §3a-7 unconfigured (the cert leg then has no trail to resolve).
    #[serde(rename = "cert-trail", default)]
    pub cert_trail: Option<String>,
    pub repos: BTreeMap<String, RepoEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoManifestError {
    #[error("parse repo manifest: {0}")]
    Parse(String),
    #[error("unsupported repo-manifest schema-version {0} (this Orchard supports 1)")]
    Schema(u32),
    #[error("repo-manifest artifact set diverges from consume-pins — missing {missing:?}, extra {extra:?}")]
    ArtifactSetMismatch {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    #[error("artifact {0:?} is owned by more than one repo in the manifest")]
    DuplicateArtifact(String),
}

impl RepoManifest {
    pub fn from_toml_str(s: &str) -> Result<Self, RepoManifestError> {
        let m: RepoManifest =
            toml::from_str(s).map_err(|e| RepoManifestError::Parse(e.to_string()))?;
        if m.schema_version != 1 {
            return Err(RepoManifestError::Schema(m.schema_version));
        }
                                                                                         
        let mut seen = BTreeSet::new();
        for entry in m.repos.values() {
            for a in &entry.artifacts {
                if !seen.insert(a.as_str()) {
                    return Err(RepoManifestError::DuplicateArtifact(a.clone()));
                }
            }
        }
        Ok(m)
    }

    pub fn load(path: &Path) -> Result<Self, RepoManifestError> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| RepoManifestError::Parse(format!("read {}: {e}", path.display())))?;
        Self::from_toml_str(&s)
    }

    /// Fail-closed exact-set lock: the union of all repos' artifacts must EXACTLY equal the
    /// `consume-pins` artifact set. A manifest that forgets an owned artifact (→ that artifact's repo
    /// is silently un-cross-checked) or lists one `consume-pins` doesn't both FAIL — the allowlist shape
                                                                                                       
    pub fn assert_artifact_set(&self, consume: &PinManifest) -> Result<(), RepoManifestError> {
        let manifest_set: BTreeSet<&str> = self
            .repos
            .values()
            .flat_map(|r| r.artifacts.iter().map(String::as_str))
            .collect();
        let consume_set: BTreeSet<&str> = consume.artifacts.keys().map(String::as_str).collect();
        let missing: Vec<String> = consume_set
            .difference(&manifest_set)
            .map(|s| s.to_string())
            .collect();
        let extra: Vec<String> = manifest_set
            .difference(&consume_set)
            .map(|s| s.to_string())
            .collect();
        if !missing.is_empty() || !extra.is_empty() {
            return Err(RepoManifestError::ArtifactSetMismatch { missing, extra });
        }
        Ok(())
    }

    /// The repo that owns `artifact`, if any.
    pub fn owner_of(&self, artifact: &str) -> Option<(&str, &RepoEntry)> {
        self.repos
            .iter()
            .find(|(_, e)| e.artifacts.iter().any(|a| a == artifact))
            .map(|(n, e)| (n.as_str(), e))
    }

    /// Resolve a repo's root path, joined onto the orchard repo root (the cwd `market` runs from).
    pub fn repo_path(&self, name: &str, repo_root: &Path) -> Option<PathBuf> {
        self.repos.get(name).map(|e| repo_root.join(&e.path))
    }

                                                                                                        
    /// the orchard repo root. `None` if the manifest declares no `cert-trail` (§3a-7 then unconfigured).
    pub fn cert_trail_path(&self, repo_root: &Path) -> Option<PathBuf> {
        self.cert_trail.as_ref().map(|p| repo_root.join(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consume(keys_kinds: &[(&str, &str)]) -> PinManifest {
        let mut s = String::from("schema-version = 1\n");
        for (k, kind) in keys_kinds {
            s.push_str(&format!(
                "[artifacts.{k}]\nsha256 = \"{}\"\nkind = \"{kind}\"\n",
                "a".repeat(64)
            ));
        }
        PinManifest::from_toml_str(&s).expect("consume fixture parses")
    }

    const GOOD_MANIFEST: &str = r#"
schema-version = 1
[repos.seed-vault]
path = "../seed-vault"
artifacts = ["grape-src", "dragonfruit-src"]
[repos.recipes]
path = "../../recipes"
artifacts = ["recipes-app"]
"#;

    #[test]
    fn exact_set_lock_passes_when_matched() {
        let m = RepoManifest::from_toml_str(GOOD_MANIFEST).expect("parses");
        let c = consume(&[
            ("grape-src", "source"),
            ("dragonfruit-src", "source"),
            ("recipes-app", "binary"),
        ]);
        assert!(m.assert_artifact_set(&c).is_ok());
    }

    #[test]
    fn exact_set_lock_fires_on_omission() {
        let m = RepoManifest::from_toml_str(GOOD_MANIFEST).expect("parses");
                                                                                                    
        let c = consume(&[
            ("grape-src", "source"),
            ("dragonfruit-src", "source"),
            ("recipes-app", "binary"),
            ("recipes-admin", "binary"),
        ]);
        let err = m.assert_artifact_set(&c).unwrap_err();
        assert!(
            matches!(&err, RepoManifestError::ArtifactSetMismatch { missing, .. }
                if missing.len() == 1 && missing[0] == "recipes-admin"),
            "omission must FAIL naming the missing artifact, got {err:?}"
        );
    }

    #[test]
    fn exact_set_lock_fires_on_extra() {
        let m = RepoManifest::from_toml_str(GOOD_MANIFEST).expect("parses");
                                                                        
        let c = consume(&[("grape-src", "source"), ("dragonfruit-src", "source")]);
        let err = m.assert_artifact_set(&c).unwrap_err();
        assert!(
            matches!(&err, RepoManifestError::ArtifactSetMismatch { extra, .. }
                if extra.len() == 1 && extra[0] == "recipes-app"),
            "extra must FAIL naming the extra artifact, got {err:?}"
        );
    }

    #[test]
    fn cert_trail_is_optional_and_resolves_against_repo_root() {
                                                                   
        let none = RepoManifest::from_toml_str(GOOD_MANIFEST).expect("parses");
        assert!(none.cert_trail.is_none());
        assert!(none.cert_trail_path(Path::new("/x")).is_none());

                                                                  
        let with = RepoManifest::from_toml_str(&format!(
            "cert-trail = \"../../cookbook/trail\"\n{GOOD_MANIFEST}"
        ))
        .expect("parses with cert-trail");
        assert_eq!(
            with.cert_trail_path(Path::new("/home/x/orchard")).unwrap(),
            Path::new("/home/x/orchard/../../cookbook/trail")
        );
    }

    #[test]
    fn duplicate_artifact_across_repos_is_refused() {
        let dup = r#"
schema-version = 1
[repos.a]
path = "../a"
artifacts = ["x"]
[repos.b]
path = "../b"
artifacts = ["x"]
"#;
        assert!(matches!(
            RepoManifest::from_toml_str(dup),
            Err(RepoManifestError::DuplicateArtifact(_))
        ));
    }

    #[test]
    fn rejects_unknown_field_and_bad_schema() {
        let unknown = "schema-version = 1\n[repos.a]\npath = \"../a\"\nartifacts = []\nextra = 1\n";
        assert!(RepoManifest::from_toml_str(unknown).is_err());
        let bad_schema = "schema-version = 2\n[repos.a]\npath = \"../a\"\nartifacts = []\n";
        assert!(matches!(
            RepoManifest::from_toml_str(bad_schema),
            Err(RepoManifestError::Schema(2))
        ));
    }
}
