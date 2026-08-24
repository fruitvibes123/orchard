                                                                                                      
//! + required-fields everywhere (mirrors the §5.3 fail-closed manifest discipline). The parser is the
//! stricter party; an unknown key, a missing required field, or a malformed sha is a parse error — a
//! fail-open here means an un-pinned input could slip into the signed .img. Validated sha format =
//! exactly 64 lowercase hex (a sha256 digest). NO #[serde(default/flatten/untagged/alias)] anywhere —
//! the grep-guard test (tests/pin_manifest_attrs.rs) enforces that, the project's own G11 pattern.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum ArtifactKind {
    /// A pre-built binary: fetched from the store + staged into the rootfs as-is.
    Binary,
    /// A source drop: vendored into vendor/ + compiled per-bake (rambutan, fb-manifest, Seed-Vault crates).
    Source,
    /// A fetched CONFIG (the `service-manifest` TOML): fetched + sha256-verified like a binary, but
                                                                                                         
    /// I-4) so the vendor loops exclude it by KIND, not by the `*-src` naming convention.
    Config,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPin {
    pub sha256: String,
    pub kind: ArtifactKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinManifest {
    #[serde(rename = "schema-version")]
    pub schema_version: u32,
    pub artifacts: BTreeMap<String, ArtifactPin>,
}

#[derive(Debug, thiserror::Error)]
pub enum PinManifestError {
    #[error("parse pin manifest: {0}")]
    Parse(String),
    #[error("artifact {0:?} has a malformed sha256 (need 64 lowercase hex)")]
    BadSha(String),
    #[error("unsupported pin-manifest schema-version {0} (this Orchard supports 1)")]
    Schema(u32),
    #[error("artifact {0:?} not found in the pin manifest")]
    Missing(String),
}

/// True iff `s` is a canonical sha256 digest string: exactly 64 lowercase hex. `pub(crate)` so the
/// artifact_store gate can self-defend against a malformed pin (F-3b-P1-R1-6) using the SAME check the
/// parser applies — one source of truth for "is this a valid pin".
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PinManifest {
    pub fn from_toml_str(s: &str) -> Result<Self, PinManifestError> {
        let m: PinManifest =
            toml::from_str(s).map_err(|e| PinManifestError::Parse(e.to_string()))?;
        if m.schema_version != 1 {
            return Err(PinManifestError::Schema(m.schema_version));
        }
        for (key, pin) in &m.artifacts {
            if !is_sha256_hex(&pin.sha256) {
                return Err(PinManifestError::BadSha(key.clone()));
            }
        }
        Ok(m)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, PinManifestError> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| PinManifestError::Parse(format!("read {}: {e}", path.display())))?;
        Self::from_toml_str(&s)
    }

    pub fn artifact(&self, key: &str) -> Result<&ArtifactPin, PinManifestError> {
        self.artifacts
            .get(key)
            .ok_or_else(|| PinManifestError::Missing(key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
schema-version = 1
[artifacts.recipes-app]
sha256 = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
kind = "binary"
"#;

    #[test]
    fn parses_a_well_formed_manifest() {
        let m = PinManifest::from_toml_str(GOOD).expect("parses");
        let a = m.artifact("recipes-app").expect("present");
        assert_eq!(a.kind, ArtifactKind::Binary);
        assert_eq!(a.sha256.len(), 64);
    }

    #[test]
    fn rejects_unknown_field() {
                                                                                  
        let one = r#"schema-version = 1
[artifacts.x]
sha256 = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
kind = "binary"
extra = "nope"
"#;
        assert!(
            PinManifest::from_toml_str(one).is_err(),
            "unknown field must be refused"
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        let no_kind = r#"schema-version = 1
[artifacts.x]
sha256 = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
"#;
        assert!(
            PinManifest::from_toml_str(no_kind).is_err(),
            "missing kind must be refused"
        );
        let no_sha = "schema-version = 1\n[artifacts.x]\nkind = \"binary\"\n";
        assert!(
            PinManifest::from_toml_str(no_sha).is_err(),
            "missing sha256 must be refused"
        );
    }

    #[test]
    fn rejects_bad_sha_length() {
        let short = "schema-version = 1\n[artifacts.x]\nsha256 = \"deadbeef\"\nkind = \"binary\"\n";
        assert!(
            PinManifest::from_toml_str(short).is_err(),
            "non-64-hex sha must be refused"
        );
    }
}
