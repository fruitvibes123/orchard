//! The hand-maintained `apk-world.toml` (intent), parsed by the lock generator
//! (`deploy refresh-apk-lock`). Mirrors Cargo.toml-vs-Cargo.lock: this declares the
//! top-level intent + the release branch; [`crate::PinnedApks`] (`pinned-apks.toml`) is
                                                                                                             

use crate::AcquireError;

/// The parsed `apk-world.toml`: the operator's top-level package intent.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ApkWorld {
    /// The Alpine release branch the closure resolves within (e.g. `"3.23"`); the dl-cdn
    /// URLs interpolate it as `v<alpine_version>`.
    pub alpine_version: String,
    /// Runtime-services world: each entry's full runtime-link closure is resolved into the
    /// rootfs squashfs (the lock's `[[package]]` rows).
    #[serde(default)]
    pub runtime: Vec<String>,
    /// Build/boot inputs (e.g. `linux-virt` → kernel config-virt; `syslinux` → deploy bootloader):
    /// pinned individually (NO closure resolution) and NEVER extracted into the rootfs (the lock's
                                                          
    #[serde(default)]
    pub build_inputs: Vec<String>,
}

impl ApkWorld {
    pub fn from_toml_str(s: &str) -> Result<Self, AcquireError> {
        toml::from_str(s).map_err(|e| AcquireError::Format(format!("apk-world.toml: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_runtime_and_build_inputs() {
        let world = ApkWorld::from_toml_str(
            r#"
alpine_version = "3.23"
runtime = ["musl", "haproxy"]
build_inputs = ["linux-virt", "syslinux"]
"#,
        )
        .unwrap();
        assert_eq!(world.alpine_version, "3.23");
        assert_eq!(world.runtime, ["musl", "haproxy"]);
        assert_eq!(world.build_inputs, ["linux-virt", "syslinux"]);
    }

    #[test]
    fn sections_default_empty() {
        let world = ApkWorld::from_toml_str("alpine_version = \"3.23\"\n").unwrap();
        assert!(world.runtime.is_empty());
        assert!(world.build_inputs.is_empty());
    }

    /// The COMMITTED `apk-world.toml` must encode the settled closure-cut decisions: services-only
    /// runtime; chrony/dropbear-ssh/libressl dropped (2026-05-27); s6-rc/s6-linux-init dropped by the
    /// signed-exec init redesign (2026-05-29); linux-virt + syslinux are build-inputs. Regression-locks
    /// the decisions in CI.
    #[test]
    fn committed_world_reflects_the_closure_decisions() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/apk-world.toml");
        let world = ApkWorld::from_toml_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            world.alpine_version, "3.23",
            "resolves against the v3.23 branch"
        );

        for svc in [
            "musl",
            "busybox",
            "busybox-extras",
            "dropbear",
            "haproxy",
            "nftables",
            "s6",
            "s6-portable-utils",
                                                                                           
            "libgcc",
            "sqlite-libs",
        ] {
            assert!(
                world.runtime.contains(&svc.to_string()),
                "runtime world must include {svc}"
            );
        }
                                                                                     
        for cut in [
            "chrony",
            "dropbear-ssh",
            "libressl",
            "linux-virt",
            "syslinux",
                                                                                                   
                                                                                          
            "s6-rc",
            "s6-linux-init",
        ] {
            assert!(
                !world.runtime.contains(&cut.to_string()),
                "{cut} must NOT be in the runtime world (closure-cut decision 2026-05-27)"
            );
        }
                                                                               
        assert!(world.build_inputs.contains(&"linux-virt".to_string()));
        assert!(world.build_inputs.contains(&"syslinux".to_string()));
    }

                                                                                                    
    /// lock is the world's full runtime-link closure, so it ⊇ the world). A DIRECT coverage gate in CI —
    /// otherwise a world entry dropped from the lock surfaces only when a real build's acquire step fails
    /// (and the build is not in `make verify`). Catches a world/lock drift before `deploy build`.
    #[test]
    fn the_pinned_lock_covers_every_runtime_world_package() {
        let world = ApkWorld::from_toml_str(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/apk-world.toml"))
                .unwrap(),
        )
        .unwrap();
        let lock = crate::PinnedApks::from_toml_str(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/pinned-apks.toml"))
                .unwrap(),
        )
        .unwrap();
        let locked: std::collections::HashSet<&str> =
            lock.packages.iter().map(|p| p.name.as_str()).collect();
        for pkg in &world.runtime {
            assert!(
                locked.contains(pkg.as_str()),
                "apk-world runtime `{pkg}` is NOT in pinned-apks.toml — the lock does not cover the \
                 world; regenerate via `deploy refresh-apk-lock`"
            );
        }
    }
}
