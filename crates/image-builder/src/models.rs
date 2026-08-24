//! The model-weights pin manifest (repo-root `models.toml`) — the sha256-pinned GGUF build inputs for
                                                                                            
//! kernel/rust build-input pins): a strict, sha-validated manifest. The bake reads the operator-supplied
//! GGUF (located out-of-band — it is multi-GiB, never committed), verifies its sha256 against the pin,
//! then wraps it in a minimal squashfs + dm-verity (the weights component of the `.img` — a 5th GPT
//! partition between rootfs-B and persist).
//!
                                                                                                    
//! gates: `boot-gate-hotswap` REQUIRES the small bench fixtures (the 1.5b baked + the 0.5b push size the
//! exact-fit partition and the bench VM), while the prod co-tenant box requires the Qwen3-VL-2B pair.
//! Re-pointing a single pin at prod would have silently broken the hotswap gate. So the manifest is a map
//! of NAMED profiles, selected by the tenant manifest's FILE STEM: a build with
//! `--manifest crates/image-builder/hotswap-tenant.toml` resolves `[profiles.hotswap-tenant]`.
//! **Fail-closed:** an unknown stem is a build ERROR — there is no default profile to fall back to, so a
//! bench box can never be built from prod pins or vice versa.
//!
//! The selector deliberately lives HERE and not in the tenant manifest: that schema is `fb-manifest`, a
//! vendored pinned source drop shared with the box runtime, where a BUILD-only key would be inert — and
//! adding one would drag a cross-repo re-vendor + re-pin into what is otherwise an orchard-only change.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The CANONICAL in-volume filename the bake writes the text-weights GGUF under (regardless of the pin's
/// descriptive `file` provenance name). A tenant's `creatine` reads `CREATINE_MODEL_PATH=/models/model.gguf`
/// (mount dir `/models` + this name), so the env stays CONSTANT across model swaps — only the verity
/// volume + the pin's sha256/hash change. MUST agree with dha's `S-FB-COMPOSITION` contract.
pub const MODEL_GGUF_NAME: &str = "model.gguf";

                                                                                                    
/// resolved profile pins an `mmproj`. Same constant-env rationale as [`MODEL_GGUF_NAME`].
///
/// **Baked now, served later — deliberately.** `creatine-serve` cannot load an mmproj today (its
/// `main.rs` dispatches to `families::load_engine` → `Qwen2Engine::load`, a single-GGUF path;
/// `load_with_mmproj_cached` exists but no serve path reaches it). The pair is baked for SIZE FIDELITY —
                                                                                                                               
/// makes that evidence representative. The volume is then already correct when vision lands: a later
/// creatine bump changes binaries, not the weights volume.
pub const MMPROJ_GGUF_NAME: &str = "mmproj.gguf";

/// The parsed `models.toml`. Strict (`deny_unknown_fields` at every depth + validated sha/size fields) —
/// the same posture as [`crate::pins::Pins`] and every other pin manifest. A fail-open here would let a
                                                                                                         
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Models {
    /// Keyed by tenant-manifest FILE STEM (`hotswap-tenant`, `prod-cotenant`, `dha-tenant`).
    /// `BTreeMap` so iteration/diagnostics are deterministically ordered.
    pub profiles: BTreeMap<String, Profile>,
}

/// One tenant's weights pin set: the GGUF(s) + the model-coupled health probe. `[health]` lives inside
/// the profile because it is MODEL-coupled — its request body names the served model id, so a profile
/// swapping models must swap its probe with it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub weights: WeightsPin,
    /// Hotswap v4: the engine's REAL-inference health probe (`orchard build --weights-anchor runtime`
    /// bakes it as `/etc/recipes/weights-health`; the swap's post-swap gate drives it). REQUIRED for a
    /// RuntimeRecord build; ignored otherwise.
    pub health: Option<HealthPin>,
}

/// The `[health]` probe pin: the engine's loopback port + an inference request that forces a real
                                                                               
/// `/etc/recipes/weights-health` grammar fb-weights parses back.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthPin {
    pub port: u16,
    /// Absolute request path (e.g. `/v1/completions`).
    pub path: String,
    /// One-line JSON request body (newlines would break the baked line grammar — rejected at load).
    pub body: String,
}

                                                                                             
/// out-of-band (multi-GiB, never committed); the bake verifies each located file's `sha256` against its
/// pin, then writes them under the CANONICAL in-volume names so the tenant env stays constant.
///
/// NB `file` is source PROVENANCE — which model this is — NOT the in-volume name (dha
/// `S-FB-COMPOSITION`), and `$CREATINE_MODEL_PATH` is the FILE creatine reads, not the mount directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeightsPin {
    /// The source GGUF's descriptive filename (e.g. `qwen3-vl-2b-instruct-q4km.gguf`).
    pub file: String,
    /// 64 lowercase hex. Verified at bake — a tampered/wrong GGUF fails the build before squashfs.
    pub sha256: String,
    /// Exact byte length. Two jobs: the build fails FAST on a wrong-size file before streaming a hash
    /// over multiple GiB, and the gate's payload floor (§13.5) compares against a PINNED size rather
    /// than a constant hardcoded in a test.
    pub bytes: u64,
    /// The vision projector, for VL models. `None` ⇒ a text-only profile and a single-file volume
                                            
    pub mmproj: Option<GgufPin>,
}

/// A secondary pinned GGUF in the same volume (today: the `mmproj` vision projector).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GgufPin {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelsError {
    #[error("read models.toml at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse models.toml: {0}")]
    Parse(String),
    #[error("models.toml {field} has a malformed sha ({value:?} — need {want})")]
    BadSha {
        field: String,
        value: String,
        want: &'static str,
    },
                                                                                                       
    /// aborts the build rather than silently baking someone else's pins.
    #[error(
        "models.toml has no [profiles.{wanted}] for this build — a weights build resolves its pin \
         profile from the tenant manifest's file stem, and there is NO default profile to fall back \
         on (a bench box must never build from prod pins, or the reverse). Known profiles: {known}. \
         Add a [profiles.{wanted}] section, or build with the matching --manifest."
    )]
    UnknownProfile { wanted: String, known: String },
    /// A weights build with no `--manifest` has no stem to resolve — the reference (recipes) tenant
    /// comes from the pinned `service-manifest` and pins no weights.
    #[error(
        "a weights build (RECIPES_DHA_WEIGHTS_GGUF is set) needs --manifest <tenant>.toml to resolve \
         its models.toml pin profile; the pinned reference tenant declares no weights volume"
    )]
    NoManifestForProfile,
}

impl WeightsPin {
    /// Total pinned payload bytes across every GGUF in the volume — the comparand for the gate's
    /// weights-payload floor (§13.5) and for build-time size checks.
    #[must_use]
    pub fn payload_bytes(&self) -> u64 {
        self.bytes
            .saturating_add(self.mmproj.as_ref().map_or(0, |m| m.bytes))
    }
}

impl Models {
    /// The canonical repo-root manifest path `<repo_root>/models.toml` (mirrors
    /// [`crate::pins::Pins::manifest_path`]).
    pub fn manifest_path(repo_root: &Path) -> PathBuf {
        repo_root.join("models.toml")
    }

    /// Parse + validate from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ModelsError> {
        let m: Models = toml::from_str(s).map_err(|e| ModelsError::Parse(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    /// Load + parse `<repo_root>/models.toml`.
    pub fn load(repo_root: &Path) -> Result<Self, ModelsError> {
        let path = Self::manifest_path(repo_root);
        let s = std::fs::read_to_string(&path).map_err(|source| ModelsError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&s)
    }

                                                                                                 
    /// absent manifest or an unknown stem is an error, never a silent default.
    pub fn profile_for_manifest(
        &self,
        manifest_path: Option<&Path>,
    ) -> Result<&Profile, ModelsError> {
        let path = manifest_path.ok_or(ModelsError::NoManifestForProfile)?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or(ModelsError::NoManifestForProfile)?;
        self.profile(stem)
    }

    /// Resolve a profile by name, fail-closed (see [`ModelsError::UnknownProfile`]).
    pub fn profile(&self, name: &str) -> Result<&Profile, ModelsError> {
        self.profiles
            .get(name)
            .ok_or_else(|| ModelsError::UnknownProfile {
                wanted: name.to_string(),
                known: self
                    .profiles
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            })
    }

    /// Every profile's shas/sizes/health, validated at load so a malformed pin can never reach a bake.
    fn validate(&self) -> Result<(), ModelsError> {
        if self.profiles.is_empty() {
            return Err(ModelsError::Parse(
                "models.toml declares no [profiles.<tenant-manifest-stem>] — a weights build would \
                 have nothing to resolve"
                    .to_string(),
            ));
        }
        for (name, p) in &self.profiles {
            check_gguf(
                &format!("[profiles.{name}.weights]"),
                &p.weights.sha256,
                p.weights.bytes,
            )?;
            if let Some(m) = &p.weights.mmproj {
                check_gguf(
                    &format!("[profiles.{name}.weights.mmproj]"),
                    &m.sha256,
                    m.bytes,
                )?;
            }
            p.validate_health(name)?;
        }
        Ok(())
    }
}

impl Profile {
    /// The `[health]` pin bakes into the strict LINE grammar fb-weights parses back — a value carrying a
    /// newline (or a relative path) would silently corrupt the baked file. Fail-closed at load, the same
    /// posture as the sha validation.
    fn validate_health(&self, profile: &str) -> Result<(), ModelsError> {
        let Some(h) = &self.health else {
            return Ok(());
        };
        if !h.path.starts_with('/') || h.path.contains('\n') {
            return Err(ModelsError::Parse(format!(
                "[profiles.{profile}.health].path must be an absolute, newline-free request path \
                 (got {:?})",
                h.path
            )));
        }
        if h.body.contains('\n') {
            return Err(ModelsError::Parse(format!(
                "[profiles.{profile}.health].body must be one line (the baked weights-health grammar \
                 is line-oriented)"
            )));
        }
        Ok(())
    }
}

/// A malformed sha would silently never match the baked GGUF, dropping integrity coverage with no error
                                                                                                       
/// floor vacuous. Both fail closed at load.
fn check_gguf(field: &str, sha256: &str, bytes: u64) -> Result<(), ModelsError> {
    use crate::pin_manifest::is_sha256_hex;
    if !is_sha256_hex(sha256) {
        return Err(ModelsError::BadSha {
            field: format!("{field}.sha256"),
            value: sha256.to_string(),
            want: "64 lowercase hex",
        });
    }
    if bytes == 0 {
        return Err(ModelsError::Parse(format!(
            "{field}.bytes must be the GGUF's exact non-zero byte length (it gates the fast \
             wrong-size abort and the gate payload floor)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[profiles.dha-tenant.weights]
file = "qwen2.5-7b-instruct-q4_k_m.gguf"
sha256 = "640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760"
bytes = 4683074336
"#;

                                                            
    const VL_SAMPLE: &str = r#"
[profiles.prod-cotenant.weights]
file = "qwen3-vl-2b-instruct-q4km.gguf"
sha256 = "089d75c52f4b7ffc56ba998ffc50aae89fcafc755f9e7208aacca281dca6c2ae"
bytes = 1107409952

[profiles.prod-cotenant.weights.mmproj]
file = "mmproj-qwen3-vl-2b-instruct-f16.gguf"
sha256 = "c3d5afbef5287953acd57b4043d2269456e5761a4eaccb3b71b062996970aea5"
bytes = 819394848
"#;

    #[test]
    fn parses_a_text_only_profile() {
        let m = Models::from_toml_str(SAMPLE).expect("sample parses");
        let p = m.profile("dha-tenant").expect("profile resolves");
        assert_eq!(p.weights.file, "qwen2.5-7b-instruct-q4_k_m.gguf");
        assert_eq!(p.weights.sha256.len(), 64);
        assert!(p.weights.mmproj.is_none());
                                                              
        assert_eq!(p.weights.payload_bytes(), 4_683_074_336);
    }

    #[test]
    fn parses_a_vl_pair_and_sums_the_payload() {
        let m = Models::from_toml_str(VL_SAMPLE).expect("VL sample parses");
        let p = m.profile("prod-cotenant").expect("profile resolves");
        let mm = p.weights.mmproj.as_ref().expect("mmproj pinned");
        assert_eq!(mm.file, "mmproj-qwen3-vl-2b-instruct-f16.gguf");
                                                                               
        assert_eq!(p.weights.payload_bytes(), 1_107_409_952 + 819_394_848);
    }

                                                                                                    
    /// back — the property that keeps a bench box from ever building on prod pins.
    #[test]
    fn resolves_profile_by_manifest_stem_and_fails_closed_on_unknown() {
        let m = Models::from_toml_str(SAMPLE).expect("sample parses");
        let ok = m
            .profile_for_manifest(Some(Path::new("crates/image-builder/dha-tenant.toml")))
            .expect("stem resolves");
        assert_eq!(ok.weights.bytes, 4_683_074_336);

        let err = m
            .profile_for_manifest(Some(Path::new("crates/image-builder/prod-cotenant.toml")))
            .expect_err("an unknown stem must not silently fall back to another tenant's pins");
        assert!(matches!(err, ModelsError::UnknownProfile { .. }), "{err}");
                                                                                        
        assert!(err.to_string().contains("dha-tenant"), "{err}");
    }

    /// A weights build with no `--manifest` has no stem — fail closed, never a default.
    #[test]
    fn a_weights_build_without_a_manifest_fails_closed() {
        let m = Models::from_toml_str(SAMPLE).expect("sample parses");
        assert!(matches!(
            m.profile_for_manifest(None),
            Err(ModelsError::NoManifestForProfile)
        ));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
                                                                                                     
                                                                      
        let unknown = format!("{SAMPLE}[extra]\nx = 1\n");
        assert!(Models::from_toml_str(&unknown).is_err());
    }

    #[test]
    fn rejects_unknown_field_within_weights_table() {
        let sha = "a".repeat(64);
        let body = format!(
            "[profiles.t.weights]\nfile = \"x.gguf\"\nsha256 = \"{sha}\"\nbytes = 1\nbogus = 1\n"
        );
        assert!(
            Models::from_toml_str(&body).is_err(),
            "deny_unknown_fields must apply at depth too"
        );
    }

    #[test]
    fn rejects_unknown_field_within_the_mmproj_table() {
        let sha = "a".repeat(64);
        let body = format!(
            "[profiles.t.weights]\nfile = \"x.gguf\"\nsha256 = \"{sha}\"\nbytes = 1\n\
             [profiles.t.weights.mmproj]\nfile = \"m.gguf\"\nsha256 = \"{sha}\"\nbytes = 1\nbogus = 1\n"
        );
        assert!(
            Models::from_toml_str(&body).is_err(),
            "the new mmproj table must inherit the strict posture, not open a fail-open hole"
        );
    }

    #[test]
    fn rejects_malformed_sha_in_either_gguf() {
        let bad = SAMPLE.replace(
            "640c4732fb42842166db97e032c1fe7e5ff72c85a8982c75b40f74be3555d760",
            "NOTASHA",
        );
        assert!(matches!(
            Models::from_toml_str(&bad),
            Err(ModelsError::BadSha { .. })
        ));

                                                                                                   
                                                                 
        let bad_mm = VL_SAMPLE.replace(
            "c3d5afbef5287953acd57b4043d2269456e5761a4eaccb3b71b062996970aea5",
            "NOTASHA",
        );
        let err = Models::from_toml_str(&bad_mm).expect_err("mmproj sha must be validated");
        assert!(matches!(err, ModelsError::BadSha { .. }), "{err}");
        assert!(err.to_string().contains("mmproj"), "{err}");
    }

    #[test]
    fn rejects_zero_bytes() {
        let sha = "a".repeat(64);
        let body =
            format!("[profiles.t.weights]\nfile = \"x.gguf\"\nsha256 = \"{sha}\"\nbytes = 0\n");
        assert!(
            Models::from_toml_str(&body).is_err(),
            "a zero size would make both the fast wrong-size abort and the gate floor vacuous"
        );
    }

    #[test]
    fn rejects_an_empty_profile_map() {
        assert!(Models::from_toml_str("").is_err());
    }

    #[test]
    fn rejects_a_multiline_health_body() {
        let sha = "a".repeat(64);
        let body = format!(
            "[profiles.t.weights]\nfile = \"x.gguf\"\nsha256 = \"{sha}\"\nbytes = 1\n\
             [profiles.t.health]\nport = 8377\npath = \"/v1/chat/completions\"\nbody = \"a\\nb\"\n"
        );
        assert!(
            Models::from_toml_str(&body).is_err(),
            "the baked weights-health grammar is line-oriented"
        );
    }

    #[test]
    fn manifest_path_is_repo_root_slash_models_toml() {
        assert_eq!(
            Models::manifest_path(std::path::Path::new("/repo")),
            std::path::PathBuf::from("/repo/models.toml")
        );
    }
}
