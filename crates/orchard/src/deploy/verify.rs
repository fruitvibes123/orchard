//! `orchard build --verify` — the same-operator determinism self-test (R.4 Task 3).
//!
//! Build the `.img` twice over identical inputs, slice-compare the three components
//! (boot / persist-skeleton / rootfs — the O3 layout), and print a verdict-first report + an explicit trust-boundary
//! block. This proves DETERMINISM, not integrity: a compromised build host injects the same bytes
//! both times, so the two builds still match. Compromise detection requires an INDEPENDENT
//! rebuilder comparing hashes — which this command *enables* (by producing a stable, publishable
                                                                                                             
//! Task 3. Cross-operator core comparison is deferred research — out of scope here.)

use std::path::Path;

use recipes_image_builder::{firmware::Firmware, image::Layout};

use crate::deploy::build_image::{BuildImageError, BuildImageOpts, build_image};

/// One `.img` component's reproducibility verdict across the two builds.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentVerdict {
    pub name: &'static str,
    pub reproducible: bool,
}

/// The determinism self-test outcome.
pub struct VerifyOutcome {
    pub components: Vec<ComponentVerdict>,
    /// The `.img` sha256 — the stable, publishable reference hash an independent rebuilder compares.
    pub img_sha256_hex: String,
    /// Whole-`.img` byte-identity across the two builds.
    pub identical: bool,
}

/// Parse the build's `.layout.toml` sidecar into the typed [`Layout`] (the offsets that slice the
/// concatenated `.img` back into components, plus the T6 `image_version`/`min_delegation_ctr` +
/// `firmware`). `Layout` carries no `Deserialize`, so map by hand. `pub(crate)` so the `orchard update`
/// ceremony (`deploy::update`) reads the target `.img`'s baked version + firmware from the same parser.
pub(crate) fn parse_layout(toml_str: &str) -> Result<Layout, String> {
    let v: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("layout toml parse: {e}"))?;
    let t = v
        .get("layout")
        .ok_or("layout toml: missing [layout] table")?;
    let g = |k: &str| -> Result<u64, String> {
        t.get(k)
            .and_then(toml::Value::as_integer)
            .map(|n| n as u64)
            .ok_or_else(|| format!("layout toml: missing or non-integer `{k}`"))
    };
                                                                                                      
                                                                                                
    let g_opt =
        |k: &str| -> Option<u64> { t.get(k).and_then(toml::Value::as_integer).map(|n| n as u64) };
    let firmware = t
        .get("firmware")
        .and_then(toml::Value::as_str)
        .ok_or("layout toml: missing or non-string `firmware`")?
        .parse::<Firmware>()
        .map_err(|e| format!("layout toml: {e}"))?;
    Ok(Layout {
        boot_offset: g("boot_offset")?,
        boot_size: g("boot_size")?,
        persist_skeleton_offset: g("persist_skeleton_offset")?,
        persist_skeleton_size: g("persist_skeleton_size")?,
        rootfs_offset: g("rootfs_offset")?,
        rootfs_size: g("rootfs_size")?,
        rootfs_verity_hash_offset: g("rootfs_verity_hash_offset")?,
        weights_offset: g_opt("weights_offset"),
        weights_size: g_opt("weights_size"),
        weights_verity_hash_offset: g_opt("weights_verity_hash_offset"),
        firmware,
                                                                                                        
                                                                                                           
        image_version: g("image_version")?,
        min_delegation_ctr: g("min_delegation_ctr")?,
    })
}

/// Slice the three components — boot, persist-skeleton, rootfs (`rootfs` = squashfs+verity; the O3
/// pre-baked-partition view) — from both `.img`s and compare each. An out-of-bounds slice (a malformed
/// `.img` that the layout can't describe) counts as NOT reproducible — never a vacuous pass.
fn compare_components(img_a: &[u8], img_b: &[u8], layout: &Layout) -> Vec<ComponentVerdict> {
                                                                                                  
                                                                                                      
                                                                                                     
                                                                
    let size_mismatch = img_a.len() != img_b.len();
    let cmp = |off: u64, len: u64| -> bool {
        if size_mismatch {
            return false;
        }
        let (o, l) = (off as usize, len as usize);
        match (img_a.get(o..o + l), img_b.get(o..o + l)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    };
    let mut comps: Vec<(&str, u64, u64)> = vec![
        ("boot", layout.boot_offset, layout.boot_size),
        (
            "persist-skeleton",
            layout.persist_skeleton_offset,
            layout.persist_skeleton_size,
        ),
        ("rootfs", layout.rootfs_offset, layout.rootfs_size),
    ];
                                                                                             
    if let (Some(off), Some(size)) = (layout.weights_offset, layout.weights_size) {
        comps.push(("weights", off, size));
    }
    comps
        .into_iter()
        .map(|(name, off, len)| ComponentVerdict {
            name,
            reproducible: cmp(off, len),
        })
        .collect()
}

/// Render the operator-facing report (Task 3 output contract): verdict-first, the explicit
/// trust-boundary block, and — on divergence — localize + interpret + the next action. No length
/// cap, no emoji; the trust block is the load-bearing anti-overclaim text.
pub fn render_report(outcome: &VerifyOutcome) -> String {
    let mut s = String::new();
    if outcome.identical {
        s.push_str("DETERMINISM VERIFIED: two builds over identical inputs produced a byte-identical .img.\n\n");
    } else {
        s.push_str("NON-DETERMINISTIC: two builds over identical inputs DIVERGED.\n\n");
    }
    s.push_str("Per-component:\n");
    for c in &outcome.components {
        s.push_str(&format!(
            "  {:10} {}\n",
            c.name,
            if c.reproducible {
                "reproducible"
            } else {
                "DIVERGES"
            }
        ));
    }
    s.push_str(&format!("\n.img sha256: {}\n", outcome.img_sha256_hex));
    s.push_str("\nTrust boundary:\n");
    s.push_str("  - verified here: the .img is the deterministic output of THIS source tree + your keys.\n");
    s.push_str(
        "  - trusted, NOT verified: the pinned rustc/gcc/apk toolchain releases, and that THIS\n",
    );
    s.push_str(
        "    build host is clean. A same-host rebuild proves neither — a compromised builder\n",
    );
    s.push_str("    injects the same bytes both times, so the two builds still match.\n");
    s.push_str(
        "  - to close that gap: rebuild on a DIFFERENT machine and compare. NOTE the .img is\n",
    );
    s.push_str(
        "    OPERATOR-KEYED — your CA (in the kernel), the IMA/EVM keyid + signatures, the HKDF\n",
    );
    s.push_str(
        "    rescue seed, and your domain (in haproxy.cfg) are woven in — so the meaningful\n",
    );
    s.push_str(
        "    INDEPENDENT check is YOU (or another holder of your keys + inputs) rebuilding\n",
    );
    s.push_str(
        "    elsewhere and getting THIS hash. A keyless third party gets a DIFFERENT hash; they\n",
    );
    s.push_str("    can audit that the build PROCESS is deterministic, not reproduce your hash. (A clean\n");
    s.push_str("    key-independent cross-operator core is deferred research.)\n");
    s.push_str("  - out of scope: Diverse Double-Compiling (the trusting-trust / self-reproducing-compiler\n");
    s.push_str("    gap) — research-grade for this musl-Rust + gcc-plugin stack, and below the floor for a\n");
    s.push_str("    box whose substrate is unowned anyway. Revisit only for sovereign hardware.\n");
    if !outcome.identical {
        s.push_str("\nThis is a DETERMINISM bug, not by itself a compromise. Next: re-run to localize the\n");
        s.push_str("DIVERGES component above, then fix the non-determinism (a per-build value leaking into\n");
        s.push_str("the artifact). If the divergent component is `rootfs`, the `repro_component_diff` diagnostic\n");
        s.push_str("splits it further into squashfs vs the verity hash tree. Do NOT publish this image's hash\n");
        s.push_str("as a reference until it builds reproducibly.\n");
    }
    s
}

/// Build the `.img` TWICE over identical inputs — build A into `opts.out_dir` (kept as the real
/// output), build B into a scratch tempdir — then slice-compare. Roughly DOUBLES the build (two
/// kernel compiles); opt-in via `--verify`. Same-operator determinism self-test ONLY.
pub fn verify_build(opts: &BuildImageOpts) -> Result<VerifyOutcome, BuildImageError> {
    use sha2::{Digest, Sha256};

    let a = build_image(opts)?;
    let scratch = tempfile::tempdir().map_err(|source| BuildImageError::Io {
        path: "verify scratch out-dir".into(),
        source,
    })?;
    let opts_b = BuildImageOpts {
        out_dir: scratch.path().to_path_buf(),
        ..opts.clone()
    };
    let b = build_image(&opts_b)?;

    let read = |p: &Path| -> Result<Vec<u8>, BuildImageError> {
        std::fs::read(p).map_err(|source| BuildImageError::Io {
            path: p.display().to_string(),
            source,
        })
    };
    let img_a = read(&a.outputs.img)?;
    let img_b = read(&b.outputs.img)?;
    let layout_str =
        std::fs::read_to_string(&a.outputs.layout).map_err(|source| BuildImageError::Io {
            path: a.outputs.layout.display().to_string(),
            source,
        })?;
    let layout = parse_layout(&layout_str).map_err(BuildImageError::Other)?;

    Ok(VerifyOutcome {
        components: compare_components(&img_a, &img_b, &layout),
        img_sha256_hex: format!("{:x}", Sha256::digest(&img_a)),
        identical: img_a == img_b,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_fixture() -> Layout {
                                                              
        Layout {
            boot_offset: 0,
            boot_size: 4,
            persist_skeleton_offset: 4,
            persist_skeleton_size: 2,
            rootfs_offset: 6,
            rootfs_size: 4,
            rootfs_verity_hash_offset: 2,
            weights_offset: None,
            weights_size: None,
            weights_verity_hash_offset: None,
            firmware: Firmware::Seabios,
            image_version: 5,
            min_delegation_ctr: 1_700_000_099,
        }
    }

    #[test]
    fn parse_layout_reads_all_offsets() {
        let toml = "[layout]\n\
                    boot_offset = 0\nboot_size = 4\n\
                    persist_skeleton_offset = 4\npersist_skeleton_size = 2\n\
                    rootfs_offset = 6\nrootfs_size = 4\n\
                    rootfs_verity_hash_offset = 2\n\
                    image_version = 5\nmin_delegation_ctr = 1700000099\n\
                    firmware = \"seabios\"\n";
        assert_eq!(parse_layout(toml).unwrap(), layout_fixture());
    }

    #[test]
    fn parse_layout_errors_on_missing_field() {
        assert!(parse_layout("[layout]\nboot_offset = 0\n").is_err());
    }

    #[test]
    fn identical_imgs_are_all_reproducible() {
        let img: Vec<u8> = (0..10).collect();
        let v = compare_components(&img, &img, &layout_fixture());
        assert!(v.iter().all(|c| c.reproducible));
        assert_eq!(
            v.iter().map(|c| c.name).collect::<Vec<_>>(),
            ["boot", "persist-skeleton", "rootfs"]
        );
    }

    #[test]
    fn divergence_localizes_to_the_changed_component() {
        let img_a: Vec<u8> = (0..10).collect();
        let mut img_b = img_a.clone();
        img_b[7] = 0xff;                                           
        let v = compare_components(&img_a, &img_b, &layout_fixture());
        let by = |n| v.iter().find(|c| c.name == n).unwrap().reproducible;
        assert!(by("boot"));
        assert!(by("persist-skeleton"));
        assert!(!by("rootfs"));
    }

    #[test]
    fn out_of_bounds_slice_is_not_a_vacuous_pass() {
        let full: Vec<u8> = vec![0; 10];
        let short: Vec<u8> = vec![0; 5];                            
        let v = compare_components(&full, &short, &layout_fixture());
        assert!(v.iter().any(|c| !c.reproducible));
    }

    #[test]
    fn size_mismatch_reports_all_components_diverging() {
                                                                                                   
                                                                                                     
        let img_a: Vec<u8> = (0..10).collect();
        let img_b: Vec<u8> = (0..12).collect();
        let v = compare_components(&img_a, &img_b, &layout_fixture());
        assert!(v.iter().all(|c| !c.reproducible));
    }

    fn outcome(rootfs_ok: bool, identical: bool) -> VerifyOutcome {
        VerifyOutcome {
            components: vec![
                ComponentVerdict {
                    name: "boot",
                    reproducible: true,
                },
                ComponentVerdict {
                    name: "persist-skeleton",
                    reproducible: true,
                },
                ComponentVerdict {
                    name: "rootfs",
                    reproducible: rootfs_ok,
                },
            ],
            img_sha256_hex: "abc123".into(),
            identical,
        }
    }

    #[test]
    fn report_verified_carries_the_trust_boundary_block_and_no_publish_warning() {
        let r = render_report(&outcome(true, true));
        assert!(r.contains("DETERMINISM VERIFIED"));
        assert!(r.contains("abc123"));
        assert!(r.contains("verified here"));
        assert!(r.contains("trusted, NOT verified"));
        assert!(r.contains("INDEPENDENT"));
        assert!(r.contains("OPERATOR-KEYED"));                                                                
        assert!(r.contains("Diverse Double-Compiling"));                          
        assert!(!r.contains("Do NOT publish"));                                        
    }

    #[test]
    fn report_divergence_localizes_and_warns_against_publishing() {
        let r = render_report(&outcome(false, false));
        assert!(r.contains("NON-DETERMINISTIC"));
        assert!(r.contains("rootfs"));
        assert!(r.contains("DIVERGES"));
        assert!(r.contains("not by itself a compromise"));
        assert!(r.contains("repro_component_diff"));                                      
        assert!(r.contains("Do NOT publish"));
    }

    /// Integration: `verify_build` self-tests determinism against the REAL container — builds the
    /// `.img` TWICE (~doubles a full build). Same prereqs as `build_image::build_twice_is_byte_identical`
    /// (docker + the recipes-imgbuild:dev container + staged keys/kernel). #[ignore]'d like the other
    /// container-bound builds; run with `--ignored`.
    #[test]
    #[ignore = "needs docker + the container + staged keys/kernel; two full .img builds (slow)"]
    fn verify_build_reports_reproducible() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")                                                           
            .canonicalize()
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        let opts = BuildImageOpts {
            keys_dir: "/tmp/recipes-test-keys".into(),
            kernel_src: crate::deploy::build_image::default_kernel_xz(&repo_root).unwrap(),
            syslinux_src: crate::deploy::build_image::default_syslinux_src(&repo_root).unwrap(),
            repo_root,
            out_dir: out.path().to_path_buf(),
            domain: "recipes.example.org".into(),
            container_image: "recipes-imgbuild:dev".into(),
            allow_dirty: true,
            recovery_pubkey: None,
            operator_pubkey: None,
            firmware: Firmware::Seabios,
            net: None,
            sb_required: false,
            manifest_path: None,
            image_version: 0,
            runtime_weights: false,
        };
        let outcome = verify_build(&opts).expect("verify build");
        assert!(outcome.identical, "the box must build reproducibly (R.4)");
        assert!(outcome.components.iter().all(|c| c.reproducible));
        assert_eq!(outcome.img_sha256_hex.len(), 64, "sha256 hex is 64 chars");
    }
}
