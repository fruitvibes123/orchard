//! The apk-lock generator (`deploy refresh-apk-lock`): resolve `apk-world.toml`'s runtime closure,
//! pin the named build-inputs, verify each package's Alpine provenance, and emit `pinned-apks.toml`
//! with the COMPUTED sha256s. The closure resolution ([`ClosureResolver`]) and the HTTP fetch
//! ([`crate::Fetcher`]) are seams, so this orchestration is offline-testable; the production
//! resolver shells out to apk in the pinned build container (the `(4/n)` increment). Spec:
                                                                           

use std::process::Command;

use crate::apk_world::ApkWorld;
use crate::{verify_apk_provenance, Fetcher, TrustedKeys};

#[derive(Debug, thiserror::Error)]
pub enum GenError {
    #[error("apk closure resolution failed: {0}")]
    Resolve(String),
    #[error("fetch failed for {pkg}: {reason}")]
    Fetch { pkg: String, reason: String },
    #[error(transparent)]
    Verify(#[from] crate::AcquireError),
}

/// Resolves top-level packages to their full transitive closure as `(name, version)` pairs against
/// the pinned Alpine release. Production = the container apk resolver (`(4/n)`); tests inject a fake.
pub trait ClosureResolver {
    fn resolve_closure(
        &self,
        alpine_version: &str,
        packages: &[String],
    ) -> Result<Vec<(String, String)>, GenError>;
}

/// A resolved + provenance-verified pin (one lock row). `signing_key` is the signer DISCOVERED from
/// the apk's `.SIGN` record (and provenance-verified against it), not a pre-known value.
struct ResolvedPin {
    name: String,
    version: String,
    sha256: String,
    signing_key: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// dl-cdn URLs for a package (`main` then `community`) — mirrors `AlpineApkProvider::apk_urls` so
/// the generator pins from exactly the repos the build later fetches from.
fn apk_urls(alpine_version: &str, name: &str, version: &str) -> [String; 2] {
    let u = |repo: &str| {
        format!("https://dl-cdn.alpinelinux.org/alpine/v{alpine_version}/{repo}/x86_64/{name}-{version}.apk")
    };
    [u("main"), u("community")]
}

/// Fetch + provenance-verify a package, recording the COMPUTED sha256 and the discovered signer.
/// Verify-BEFORE-record (spec threat model): a compromised mirror cannot inject a bad sha256,
/// because the Alpine signature is checked first (`verify_apk_provenance`) — the recorded hash is
/// always over provenance-verified bytes.
fn fetch_verify_pin(
    alpine_version: &str,
    name: &str,
    version: &str,
    fetcher: &dyn Fetcher,
    trusted: &TrustedKeys,
) -> Result<ResolvedPin, GenError> {
    let mut last = "no repository tried".to_string();
    let mut bytes = None;
    for url in apk_urls(alpine_version, name, version) {
        match fetcher.get(&url) {
            Ok(b) => {
                bytes = Some(b);
                break;
            }
            Err(e) => last = e,
        }
    }
    let bytes = bytes.ok_or_else(|| GenError::Fetch {
        pkg: name.to_string(),
        reason: last,
    })?;
    let (signer, _verified) = verify_apk_provenance(&bytes, trusted, name)?;
    Ok(ResolvedPin {
        name: name.to_string(),
        version: version.to_string(),
        sha256: sha256_hex(&bytes),
        signing_key: signer,
    })
}

/// Generate the lock from the world: resolve the runtime closure → `[[package]]`; pin the named
/// build-inputs (their version only, NOT their transitive closure) → `[[build_input]]`. Every
/// package is fetched + provenance-verified before its sha256 is recorded.
pub fn generate_lock(
    world: &ApkWorld,
    resolver: &dyn ClosureResolver,
    fetcher: &dyn Fetcher,
    trusted: &TrustedKeys,
) -> Result<String, GenError> {
    let runtime_closure = resolver.resolve_closure(&world.alpine_version, &world.runtime)?;
    let mut runtime = Vec::with_capacity(runtime_closure.len());
    for (name, version) in &runtime_closure {
        runtime.push(fetch_verify_pin(
            &world.alpine_version,
            name,
            version,
            fetcher,
            trusted,
        )?);
    }

                                                                                                  
                                                                                                      
                                                                                                  
                                                              
    let bi_closure = resolver.resolve_closure(&world.alpine_version, &world.build_inputs)?;
    let mut build_inputs = Vec::new();
    for (name, version) in &bi_closure {
        if world.build_inputs.contains(name) {
            build_inputs.push(fetch_verify_pin(
                &world.alpine_version,
                name,
                version,
                fetcher,
                trusted,
            )?);
        }
    }

    Ok(render_lock(
        &world.alpine_version,
        &mut runtime,
        &mut build_inputs,
    ))
}

/// Render `pinned-apks.toml` deterministically: each section sorted by name (clean diffs), a header
/// marking the file generated. The output re-parses as [`crate::PinnedApks`].
fn render_lock(
    alpine_version: &str,
    runtime: &mut [ResolvedPin],
    build_inputs: &mut [ResolvedPin],
) -> String {
    runtime.sort_by(|a, b| a.name.cmp(&b.name));
    build_inputs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut s = String::new();
    s.push_str("# GENERATED by `orchard refresh-apk-lock` — do NOT edit by hand.\n");
    s.push_str("# The full runtime-link closure of apk-world.toml's `runtime` world, plus the\n");
    s.push_str(
        "# build/boot-input pins. Regenerate on a world change or Alpine bump; the diff is\n",
    );
    s.push_str("# the reviewable surface. Each entry is dual-verified at build time (sha256\n");
    s.push_str("# immutability + Alpine signature, per verify_apk).\n\n");
    s.push_str(&format!("alpine_version = \"{alpine_version}\"\n"));
    for p in runtime.iter() {
        s.push_str(&render_row("package", p));
    }
    for p in build_inputs.iter() {
        s.push_str(&render_row("build_input", p));
    }
    s
}

fn render_row(section: &str, p: &ResolvedPin) -> String {
    format!(
        "\n[[{section}]]\nname = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\nsigning_key = \"{}\"\n",
        p.name, p.version, p.sha256, p.signing_key
    )
}

/// Production [`ClosureResolver`]: resolve the closure with apk inside the pinned build container.
/// Per the apk-3.x notes (resume memory): a fresh `--root --initdb` needs the `v<release>` repos,
/// the container's Alpine keys, AND an explicit `apk update` (the community index won't load
/// otherwise), then `apk add --simulate` whose `Installing` lines we parse. Package names are
/// charset-validated BEFORE the shell-out (an apk-world.toml name can't carry shell metacharacters).
pub struct ContainerResolver {
    pub container_image: String,
}

impl ContainerResolver {
    pub fn new(container_image: String) -> Self {
        Self { container_image }
    }
}

impl ClosureResolver for ContainerResolver {
    fn resolve_closure(
        &self,
        alpine_version: &str,
        packages: &[String],
    ) -> Result<Vec<(String, String)>, GenError> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        for p in packages {
            if !valid_apk_name(p) {
                return Err(GenError::Resolve(format!(
                    "refusing to resolve invalid apk package name {p:?} (shell-injection guard)"
                )));
            }
        }
        if !valid_apk_name(alpine_version) {
            return Err(GenError::Resolve(format!(
                "refusing invalid alpine_version {alpine_version:?}"
            )));
        }
        let pkgs = packages.join(" ");
                                                                                           
        let script = format!(
            "set -e\n\
             R=/r\n\
             apk add --root \"$R\" --initdb >/dev/null 2>&1\n\
             mkdir -p \"$R/etc/apk/keys\"\n\
             cp /etc/apk/keys/* \"$R/etc/apk/keys/\"\n\
             printf '%s\\n' 'https://dl-cdn.alpinelinux.org/alpine/v{alpine_version}/main' 'https://dl-cdn.alpinelinux.org/alpine/v{alpine_version}/community' > \"$R/etc/apk/repositories\"\n\
             apk --root \"$R\" update >/dev/null 2>&1\n\
             apk add --root \"$R\" --simulate {pkgs} 2>&1\n"
        );
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                self.container_image.as_str(),
                "sh",
                "-c",
                script.as_str(),
            ])
            .output()
            .map_err(|e| GenError::Resolve(format!("docker spawn failed: {e}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            return Err(GenError::Resolve(format!(
                "apk resolve in {} failed: {stdout}{}",
                self.container_image,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        parse_installing_lines(&stdout)
    }
}

/// `^[A-Za-z0-9][A-Za-z0-9._+-]*$` — the apk package-name charset (whitelist; the shell-out guard).
fn valid_apk_name(name: &str) -> bool {
    matches!(name.chars().next(), Some(c) if c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Parse apk `--simulate` output: lines shaped `(N/M) Installing <name> (<version>)`. Anchored on
/// the `(N/M)` counter so stray text can't masquerade as a package row.
fn parse_installing_lines(out: &str) -> Result<Vec<(String, String)>, GenError> {
    let mut pkgs = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if !t.starts_with('(') {
            continue;
        }
        if let Some(rest) = t.split(") Installing ").nth(1) {
            if let Some((name, ver)) = rest.split_once(" (") {
                pkgs.push((
                    name.trim().to_string(),
                    ver.trim().trim_end_matches(')').to_string(),
                ));
            }
        }
    }
    if pkgs.is_empty() {
        return Err(GenError::Resolve(
            "apk resolve produced no `Installing` lines".into(),
        ));
    }
    Ok(pkgs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PinnedApks;
    use std::collections::HashMap;

    const MUSL_APK: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/musl-1.2.5-r23.apk"
    ));
    const KEY_6165: &str = "alpine-devel@lists.alpinelinux.org-6165ee59";

    fn trusted() -> TrustedKeys {
        let mut k = HashMap::new();
        k.insert(
            KEY_6165.to_string(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
            ))
            .to_vec(),
        );
        k
    }

    /// Serves the genuine musl apk on any musl URL; 404 otherwise (so a filtered-out package that
    /// is wrongly fetched would error the test).
    struct MuslFetcher;
    impl Fetcher for MuslFetcher {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            if url.contains("musl-1.2.5-r23.apk") {
                Ok(MUSL_APK.to_vec())
            } else {
                Err("HTTP 404".to_string())
            }
        }
    }

    /// Resolver that returns a canned closure for an EXACT requested package set, and errors on any
    /// unexpected input — so a stray/mis-routed resolve call is caught rather than silently served.
    /// `(requested package set → resolved closure)` pairs.
    type ClosureResponses = Vec<(Vec<String>, Vec<(String, String)>)>;
    struct FakeResolver {
        responses: ClosureResponses,
    }
    impl ClosureResolver for FakeResolver {
        fn resolve_closure(
            &self,
            _v: &str,
            packages: &[String],
        ) -> Result<Vec<(String, String)>, GenError> {
            for (input, output) in &self.responses {
                if input.as_slice() == packages {
                    return Ok(output.clone());
                }
            }
            Err(GenError::Resolve(format!(
                "unexpected resolve input: {packages:?}"
            )))
        }
    }

    fn musl_pin(version: &str) -> (String, String) {
        ("musl".to_string(), version.to_string())
    }

    #[test]
    fn parse_installing_lines_extracts_name_and_version() {
                                                                                                       
        let out = "(1/3) Installing musl (1.2.5-r23)\n\
                   (2/3) Installing libssl3 (3.5.6-r0)\n\
                   (3/3) Installing s6-rc (0.5.6.0-r0)\n\
                   OK: 12 MiB in 3 packages\n";
        let pkgs = parse_installing_lines(out).unwrap();
        assert_eq!(
            pkgs,
            vec![
                ("musl".to_string(), "1.2.5-r23".to_string()),
                ("libssl3".to_string(), "3.5.6-r0".to_string()),
                ("s6-rc".to_string(), "0.5.6.0-r0".to_string()),
            ]
        );
    }

    #[test]
    fn parse_installing_lines_errors_when_nothing_resolved() {
        assert!(parse_installing_lines("OK: nothing to do\n").is_err());
    }

    #[test]
    fn valid_apk_name_accepts_real_names_rejects_metacharacters() {
        for ok in [
            "musl",
            "s6-rc",
            "libssl3",
            "busybox-extras",
            "lua5.4-libs",
            "ca-certificates-bundle",
        ] {
            assert!(valid_apk_name(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            "-leading",
            "with space",
            "semi;rm -rf",
            "$(x)",
            "a/b",
            "a&b",
        ] {
            assert!(
                !valid_apk_name(bad),
                "{bad:?} must be rejected (shell-injection guard)"
            );
        }
    }

    #[test]
    fn render_lock_sorts_sections_and_reparses() {
        let mut runtime = vec![
            ResolvedPin {
                name: "zlib".into(),
                version: "1".into(),
                sha256: "aa".into(),
                signing_key: "k".into(),
            },
            ResolvedPin {
                name: "musl".into(),
                version: "2".into(),
                sha256: "bb".into(),
                signing_key: "k".into(),
            },
        ];
        let mut bi = vec![ResolvedPin {
            name: "linux-virt".into(),
            version: "6".into(),
            sha256: "cc".into(),
            signing_key: "k".into(),
        }];
        let out = render_lock("3.23", &mut runtime, &mut bi);
                                                    
        assert!(out.find("name = \"musl\"").unwrap() < out.find("name = \"zlib\"").unwrap());
        assert!(
            out.starts_with("# GENERATED"),
            "carries the generated-file header"
        );
                                                              
        let pins = PinnedApks::from_toml_str(&out).expect("generated lock re-parses");
        assert_eq!(pins.alpine_version, "3.23");
        assert_eq!(pins.packages.len(), 2);
        assert_eq!(pins.packages[0].name, "musl", "sorted");
        assert_eq!(pins.build_inputs.len(), 1);
        assert_eq!(pins.build_inputs[0].name, "linux-virt");
                             
        let again = render_lock("3.23", &mut runtime, &mut bi);
        assert_eq!(out, again);
    }

    #[test]
    fn generate_lock_records_verified_runtime_pin_with_computed_sha_and_discovered_signer() {
        let resolver = FakeResolver {
            responses: vec![
                (vec!["musl".into()], vec![musl_pin("1.2.5-r23")]),
                (vec![], vec![]),                                                    
            ],
        };
        let world = ApkWorld {
            alpine_version: "3.23".into(),
            runtime: vec!["musl".into()],
            build_inputs: vec![],
        };
        let out = generate_lock(&world, &resolver, &MuslFetcher, &trusted()).expect("generates");
        let pins = PinnedApks::from_toml_str(&out).unwrap();
        assert_eq!(pins.packages.len(), 1);
        let musl = &pins.packages[0];
        assert_eq!(musl.name, "musl");
        assert_eq!(musl.version, "1.2.5-r23");
        assert_eq!(
            musl.sha256,
            sha256_hex(MUSL_APK),
            "records the COMPUTED hash of the fetched apk"
        );
        assert_eq!(musl.signing_key, KEY_6165, "records the DISCOVERED signer");
        assert!(pins.build_inputs.is_empty());
    }

    #[test]
    fn generate_lock_keeps_only_named_build_inputs_not_their_transitive_deps() {
                                                                                                 
                                                                                     
        let resolver = FakeResolver {
            responses: vec![
                (vec![], vec![]),                                               
                (
                    vec!["musl".into()],
                    vec![musl_pin("1.2.5-r23"), ("extra-dep".into(), "9".into())],
                ),
            ],
        };
        let world = ApkWorld {
            alpine_version: "3.23".into(),
            runtime: vec![],
            build_inputs: vec!["musl".into()],                                         
        };
        let out = generate_lock(&world, &resolver, &MuslFetcher, &trusted()).expect("generates");
        let pins = PinnedApks::from_toml_str(&out).unwrap();
        assert!(pins.packages.is_empty());
        assert_eq!(
            pins.build_inputs.len(),
            1,
            "only the NAMED build-input, not its transitive dep"
        );
        assert_eq!(pins.build_inputs[0].name, "musl");
    }
}
