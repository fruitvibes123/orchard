//! The per-repo `publish-manifest.toml` — grocer's declarative recipe: each artifact's store key, kind,
//! source location, and (binaries only) link shape. Replaces the per-artifact logic hardcoded in the old
//! `publish.sh`. Strict parse (`deny_unknown_fields`, no fail-open serde), mirroring `pin_manifest.rs`.
//!
//! `kind` here is the publish-manifest's SELF-declaration; grocer cross-checks it against `consume-pins`
//! (the authority) before acting on it (`crosscheck.rs`), so this parser enforces only the SHAPE rules
//! (linkage REQUIRED iff binary), never the authority.

use recipes_image_builder::pin_manifest::ArtifactKind;
use serde::Deserialize;

/// Binary link shape — asserted against the ELF at publish for `kind=binary` (increment 2). A static binary
                                                                                       
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Linkage {
    Dynamic,
    Static,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishArtifact {
    /// The store key + consume-pins key.
    pub key: String,
    /// The artifact's kind (cross-checked against consume-pins by `crosscheck.rs` before use).
    pub kind: ArtifactKind,
    /// Where the bytes come from: a dir under the repo (source), a file under `--build-dir` (binary), or a
    /// file under the repo (config). Sanitized + base-checked by `crosscheck.rs`.
    pub source: String,
    /// REQUIRED for `kind=binary`, FORBIDDEN otherwise (enforced in `from_toml_str`).
    pub linkage: Option<Linkage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishManifest {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
    #[serde(default)]
    pub artifact: Vec<PublishArtifact>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("parse publish-manifest: {0}")]
    Parse(String),
    #[error("unsupported publish-manifest schema-version {0} (this grocer supports 1)")]
    Schema(u32),
    #[error(
        "artifact {key:?} is kind=binary but declares no `linkage` (REQUIRED for binaries — /§6)"
    )]
    BinaryNeedsLinkage { key: String },
    #[error(
        "artifact {key:?} is kind={kind:?} but declares `linkage` (only binaries carry linkage)"
    )]
    LinkageOnNonBinary { key: String, kind: ArtifactKind },
    #[error(
        "artifact key {key:?} appears more than once (each store/consume-pins key must be unique)"
    )]
    DuplicateKey { key: String },
}

impl PublishManifest {
    /// Parse + enforce the shape rules. Schema-version must be 1; `linkage` is REQUIRED iff `kind=binary`.
    pub fn from_toml_str(s: &str) -> Result<Self, ManifestError> {
        let m: PublishManifest =
            toml::from_str(s).map_err(|e| ManifestError::Parse(e.to_string()))?;
        if m.schema_version != 1 {
            return Err(ManifestError::Schema(m.schema_version));
        }
                                                                                                     
                                                                                              
                                                                                                             
                                                                                                      
                                                                                                        
                                                                                                 
        let mut seen = std::collections::BTreeSet::new();
        for a in &m.artifact {
            if !seen.insert(a.key.as_str()) {
                return Err(ManifestError::DuplicateKey { key: a.key.clone() });
            }
            match (a.kind, a.linkage) {
                (ArtifactKind::Binary, None) => {
                    return Err(ManifestError::BinaryNeedsLinkage { key: a.key.clone() });
                }
                (ArtifactKind::Source | ArtifactKind::Config, Some(_)) => {
                    return Err(ManifestError::LinkageOnNonBinary {
                        key: a.key.clone(),
                        kind: a.kind,
                    });
                }
                _ => {}
            }
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_source_manifest() {
        let m = PublishManifest::from_toml_str(
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
"#,
        )
        .expect("valid");
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.artifact.len(), 2);
        assert_eq!(m.artifact[0].key, "grape-src");
        assert_eq!(m.artifact[0].kind, ArtifactKind::Source);
        assert!(m.artifact[0].linkage.is_none());
    }

    #[test]
    fn binary_without_linkage_is_refused() {
        let err = PublishManifest::from_toml_str(
            r#"
schema-version = 1
[[artifact]]
key = "recipes-app"
kind = "binary"
source = "release/recipes"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ManifestError::BinaryNeedsLinkage { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn source_with_linkage_is_refused() {
        let err = PublishManifest::from_toml_str(
            r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "source"
source = "crates/grape"
linkage = "dynamic"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ManifestError::LinkageOnNonBinary { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_field_is_refused() {
        let err = PublishManifest::from_toml_str(
            r#"
schema-version = 1
[[artifact]]
key = "grape-src"
kind = "source"
source = "crates/grape"
bogus = "x"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn wrong_schema_version_is_refused() {
        let err = PublishManifest::from_toml_str("schema-version = 2\n").unwrap_err();
        assert!(matches!(err, ManifestError::Schema(2)), "got {err:?}");
    }

    #[test]
    fn binary_with_linkage_parses() {
        let m = PublishManifest::from_toml_str(
            r#"
schema-version = 1
[[artifact]]
key = "recipes-app"
kind = "binary"
source = "release/recipes"
linkage = "dynamic"
"#,
        )
        .expect("valid");
        assert_eq!(m.artifact[0].kind, ArtifactKind::Binary);
        assert_eq!(m.artifact[0].linkage, Some(Linkage::Dynamic));
    }

    #[test]
    fn duplicate_key_is_refused() {
                                                                                                    
                                                                                                         
        let err = PublishManifest::from_toml_str(
            r#"
schema-version = 1
[[artifact]]
key = "dha-epa-config"
kind = "config"
source = "deploy/epa.json"
[[artifact]]
key = "dha-epa-config"
kind = "config"
source = "deploy/epa-other.json"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(&err, ManifestError::DuplicateKey { key } if key.as_str() == "dha-epa-config"),
            "got {err:?}"
        );
    }
}
