                                                                                                      
//!
//! `#[ignore]` + a docker precondition: under `cargo test` these report "ignored" (honest); under
//! `--ignored` (via `make boot-gate-per-uid`) they bake in the pinned `recipes-imgbuild:dev` container
//! and assert on REAL produced bytes. This is the REPRESENTATIVE-tree proof of the ownership mechanism
//! (nested dirs, a rel symlink, a suid file, a non-0:0 staged file) — the SAME shape the R1 spec-audit
//! probed. The ~3000-inode real-tree + the QEMU boot legs are the operator-run `make boot-gate` after a
//! full `orchard build`; this catches a byte-identity/owner regression WITHOUT a full build.
//!
//! Legs: (1) D5 byte-identity — the `Ownership::Map` recipe (chown-root-0:0 + per-inode `m` lines) bakes
//! byte-for-byte identical to `-all-root`; (3) owner+mode — a declared `OwnerException` bakes the file
//! `uid=gid=5000 mode=0600` on disk (`unsquashfs` stat); (8) byte-repro — the Map bake is deterministic.
//!
//! Run: `cargo test -p recipes-image-builder --test per_uid_baking -- --ignored`  (or `make boot-gate-per-uid`)

use recipes_image_builder::config;
use recipes_image_builder::config_render::render_dha_configs;
use recipes_image_builder::ima_evm_signer::{pseudo_manifest, ImaEvmSigner};
use recipes_image_builder::ownership::{OwnerException, OwnershipMap};
use recipes_image_builder::squashfs::{pack_shell_cmd, Ownership};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const IMAGE: &str = "recipes-imgbuild:dev";
const EPOCH: u64 = 1_700_000_000;

/// A throwaway SKID-bearing P-256 leaf (rcgen) — the signer only needs a SKID + a key here; the sig
/// framing/fidelity is proven by `ima_evm_signer`'s differential oracle, not this bake test.
fn test_keypair() -> (String, Vec<u8>) {
    let mut params = rcgen::CertificateParams::new(vec!["recipes-ima-test".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    (kp.serialize_pem(), cert.der().to_vec())
}

/// Stage a representative tree: nested dirs, a relative symlink, a suid file, and a file staged with a
/// NON-0:0 host owner is not needed (tempfile is host-owned already) — the point is the map forces 0:0.
fn stage_representative(root: &Path) {
    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/conf"), b"k=v\n").unwrap();
    std::fs::set_permissions(
        root.join("etc/conf"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::write(root.join("usr/bin/tool"), b"\x7fELFfake").unwrap();
    std::fs::set_permissions(
        root.join("usr/bin/tool"),
        std::fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    std::os::unix::fs::symlink("../../etc/conf", root.join("usr/bin/link")).unwrap();
                                                         
    for d in ["etc", "usr", "usr/bin"] {
        std::fs::set_permissions(root.join(d), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Bake `staging` in-container with the `ownership` recipe (Map = chown-root-0:0 + drop `-all-root`;
/// AllRoot = `-all-root`, no chown), injecting `pseudo` via `-pf`. Returns the packed squashfs bytes.
/// The command is the PRODUCTION `squashfs::pack_shell_cmd` — single-sourced with
                                                                                                       
fn bake(staging: &Path, pseudo: &str, ownership: Ownership) -> Vec<u8> {
    let out_dir = tempfile::tempdir().unwrap();
    let pf_dir = tempfile::tempdir().unwrap();
    let pf = pf_dir.path().join("xattr.pseudo");
    std::fs::write(&pf, pseudo).unwrap();
    let cmd = pack_shell_cmd(
        Path::new("/staging"),
        Path::new("/out/o.sqfs"),
        EPOCH,
        ownership,
        Some(Path::new("/pf")),
    );
    let status = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/staging", staging.display()))
        .arg("-v")
        .arg(format!("{}:/out", out_dir.path().display()))
        .arg("-v")
        .arg(format!("{}:/pf:ro", pf.display()))
        .args([IMAGE, "sh", "-c", &cmd])
        .status()
        .expect("docker run mksquashfs");
    assert!(status.success(), "mksquashfs bake ({ownership:?}) failed");
    std::fs::read(out_dir.path().join("o.sqfs")).expect("read packed squashfs")
}

/// Build the m+x pseudo-manifest for `staging` with the given owner exceptions (pure host-Rust).
fn build_pseudo(staging: &Path, exceptions: &[OwnerException]) -> String {
    let (pem, der) = test_keypair();
    let signer = ImaEvmSigner::new(&pem, &der).unwrap();
    let map = OwnershipMap::build(staging, exceptions).unwrap();
    pseudo_manifest(staging, &signer, &map).unwrap()
}

                                                                                                         
/// representative tree — same squashfs bytes, so same verity root hash + same IMA/EVM xattr table.
#[test]
#[ignore = "boot-gate: needs docker + recipes-imgbuild:dev; run via `make boot-gate-per-uid`"]
fn d5_map_bake_is_byte_identical_to_all_root() {
    let s_map = tempfile::tempdir().unwrap();
    let s_all = tempfile::tempdir().unwrap();
    stage_representative(s_map.path());
    stage_representative(s_all.path());
                                                                                               
    let pseudo = build_pseudo(s_map.path(), &[]);
    let map_bytes = bake(s_map.path(), &pseudo, Ownership::Map);
    let all_bytes = bake(s_all.path(), &pseudo, Ownership::AllRoot);
    assert_eq!(
        map_bytes,
        all_bytes,
        "Map (chown-root + m-lines) must bake byte-identical to -all-root (D5); \
         lengths {} vs {}",
        map_bytes.len(),
        all_bytes.len()
    );
}

                                                                                                         
/// per `build_pseudo` would differ by RFC-6979 over a different key, which is the signer unit test's job,
/// not the bake's), baked twice on the same staging → identical bytes (the sorted map pins the order).
#[test]
#[ignore = "boot-gate: needs docker + recipes-imgbuild:dev; run via `make boot-gate-per-uid`"]
fn map_bake_is_byte_reproducible() {
    let staging = tempfile::tempdir().unwrap();
    stage_representative(staging.path());
    let exc = [OwnerException {
        rel_path: "etc/conf".into(),
        uid: 5000,
        gid: 5000,
    }];
    let pseudo = build_pseudo(staging.path(), &exc);
    let a = bake(staging.path(), &pseudo, Ownership::Map);
    let b = bake(staging.path(), &pseudo, Ownership::Map);
    assert_eq!(
        a, b,
        "the Map bake is byte-reproducible (same staging + pseudo → same bytes)"
    );
}

                                                                                                           
/// as a REAL file on disk (synthetic owner, NOT the dha box.json — F-8a). Verified via `unsquashfs` stat.
#[test]
#[ignore = "boot-gate: needs docker + recipes-imgbuild:dev; run via `make boot-gate-per-uid`"]
fn owner_exception_bakes_uid_gid_mode_on_disk() {
    let staging = tempfile::tempdir().unwrap();
    stage_representative(staging.path());
                                                                          
    std::fs::write(staging.path().join("etc/gate.json"), b"{}").unwrap();
    std::fs::set_permissions(
        staging.path().join("etc/gate.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let exc = [OwnerException {
        rel_path: "etc/gate.json".into(),
        uid: 5000,
        gid: 5000,
    }];
    let pseudo = build_pseudo(staging.path(), &exc);
    let sqfs = bake(staging.path(), &pseudo, Ownership::Map);

                                                                                   
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("o.sqfs"), &sqfs).unwrap();
    let out = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work", work.path().display()))
        .args([
            IMAGE,
            "sh",
            "-c",
            "cd /tmp && rm -rf ex && unsquashfs -no-xattrs -d ex /work/o.sqfs >/dev/null && stat -c '%u %g %a' ex/etc/gate.json ex/etc/conf",
        ])
        .output()
        .expect("docker run unsquashfs");
    assert!(
        out.status.success(),
        "unsquashfs + stat failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap().trim(),
        "5000 5000 600",
        "declared owner file bakes 5000:5000 mode 0600"
    );
    assert_eq!(
        lines.next().unwrap().trim(),
        "0 0 644",
        "a non-declared sibling stays 0:0 (default)"
    );
}

                                                                                                         

fn dha_manifest() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(include_str!("../dha-tenant.toml"), &config::os_identities())
        .expect("the dha manifest validates")
}

fn non_dha_manifest() -> fb_manifest::ValidatedManifest {
    fb_manifest::parse_and_validate(include_str!("../toy-tenant.toml"), &config::os_identities())
        .expect("the toy manifest validates")
}

/// Task 4 — the dha manifest renders `etc/dha/{box.json,runtime.json}` as REAL `dha`-owned (uid 110)
                                                                                                     
/// delegate_uid → OwnerException → baked 0600 dha:dha). The rendered JSON carries the EXACT top-level
/// keys dha's `OrchestratorRuntime` / box `Config` deserialize (`deny_unknown_fields`), with
/// parent_cgroup + budget DERIVED from the resource_domain.
#[test]
fn dha_configs_render_0600_dha_owned_and_deserializable() {
    let staging = tempfile::tempdir().unwrap();
    let exc = render_dha_configs(staging.path(), &dha_manifest()).unwrap();
    assert_eq!(exc.len(), 2);
    assert!(exc.iter().all(|e| e.uid == 110 && e.gid == 110));                        
    let box_json = staging.path().join("etc/dha/box.json");
    let rt_json = staging.path().join("etc/dha/runtime.json");
                                                                                                            
    for p in [&box_json, &rt_json] {
        let mode = std::fs::metadata(p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{p:?} is 0600");
        assert_eq!(mode & 0o111, 0, "{p:?} is non-executable");
    }
                                                                                                    
                                                                                                          
                                                                                                          
    let rt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rt_json).unwrap()).unwrap();
    let keys: std::collections::BTreeSet<&str> =
        rt.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    assert_eq!(
        keys,
        [
            "parent_cgroup",
            "max_jobs",
            "max_conns",
            "socket_path",
            "client",
            "budget",
            "client_oom_score_adj",
            "creatine",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(rt["parent_cgroup"], "/sys/fs/cgroup/dha/work");                                     
    assert_eq!(
        rt["budget"]["memory_max_bytes"].as_u64().unwrap(),
        33_554_432
    );                       
    assert_eq!(rt["budget"]["pids_max"].as_u64().unwrap(), 64);                     
    assert_eq!(rt["client"]["kind"], "epa");
    assert_eq!(rt["client"]["program"], "/usr/bin/epa");
    assert_eq!(rt["client"]["config"], "/opt/dha/epa.json");                                          
    assert_eq!(rt["client_oom_score_adj"].as_i64().unwrap(), 1000);
    assert_eq!(rt["creatine"]["uds"], "/run/creatine/creatine.sock");
    assert_eq!(rt["socket_path"], "/run/dha/orchestrator.sock");
                                                                      
    let bj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&box_json).unwrap()).unwrap();
    assert_eq!(bj["sensitive"], true);
    assert_eq!(bj["tier_b"], false);
    assert_eq!(bj["root"], "/persist/dha");
    assert_eq!(bj["secrets"], "/run/dha-secrets");
    assert_eq!(bj["git"], false);
    assert_eq!(bj["creatine_mode"], "uds");
}

                                                                                                     
/// exceptions; `etc/dha` is never created (the opt-in property at the render layer).
#[test]
fn non_dha_manifest_renders_no_configs() {
    let staging = tempfile::tempdir().unwrap();
    assert!(render_dha_configs(staging.path(), &non_dha_manifest())
        .unwrap()
        .is_empty());
    assert!(!staging.path().join("etc/dha").exists());
}

                                                                                                          

                                                                                                            
/// modes (uds-pipe 0755 binary transport; the three probe scripts 0644; epa.json 0600 owned by `dha`).
/// A HOST test pinning the shipped entries so an accidental edit (a dropped file, a wrong mode, a lost
/// owner) fails here, not at the boot-gate. (V8 — dha-epa-config's target matches the client config — is
/// exercised implicitly: `dha_manifest()` would fail `parse_and_validate` if it were dropped.)
#[test]
fn dha_tenant_declares_the_five_staged_files() {
    let m = dha_manifest();
    let got: Vec<(&str, &str, u32, Option<&str>)> = m
        .manifest()
        .staged_files
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| {
            (
                s.key.as_str(),
                s.target.as_str(),
                s.mode,
                s.owner.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("uds-pipe", "/opt/dha/uds-pipe", 0o755, None),
            ("dha-intake-probe", "/opt/dha/intake-probe.sh", 0o644, None),
            (
                "dha-real-job-probe",
                "/opt/dha/real-job-probe.sh",
                0o644,
                None
            ),
            (
                "dha-ac-i-selftest",
                "/opt/dha/ac-i-selftest.sh",
                0o644,
                None
            ),
            ("dha-epa-config", "/opt/dha/epa.json", 0o600, Some("dha")),
        ]
    );
}

                                                                                                       
/// staged files bake onto the rootfs with their declared modes (0755 / 0644×3 / 0600) + owners (root×4;
/// `epa.json` uid=gid=110 via the OwnerException → `m`-line + EVM h_misc path the sibling legs probe),
/// and their bytes equal the store's (the sha256 the pin gates on). This is the FIRST produced-bytes
                                                                                                      
/// already in consume-pins; the four `dha-*` config keys enroll at the pin gate, Task 8), docker-gated
/// like the sibling per-uid legs.
#[test]
#[ignore = "boot-gate: needs docker + recipes-imgbuild:dev; run via `make boot-gate-per-uid`"]
fn ac1_staged_files_bake_modes_owners_and_bytes() {
    use recipes_image_builder::artifact_store::DirStore;
    use recipes_image_builder::pin_manifest::PinManifest;
    use recipes_image_builder::staged_files::stage_manifest_files;
    use sha2::{Digest, Sha256};

                                                                                                         
                                                                                                     
    let store_dir = tempfile::tempdir().unwrap();
    let store = DirStore::new(store_dir.path());
    let entries: [(&str, &str, &[u8]); 5] = [
        ("uds-pipe", "binary", b"\x7fELF-uds-pipe-bytes"),
        ("dha-intake-probe", "config", b"#!/bin/sh\n# intake probe\n"),
        (
            "dha-real-job-probe",
            "config",
            b"#!/bin/sh\n# real-job probe\n",
        ),
        (
            "dha-ac-i-selftest",
            "config",
            b"#!/bin/sh\n# ac-i selftest\n",
        ),
        ("dha-epa-config", "config", b"{\"epa\":true}\n"),
    ];
    let mut pins_toml = String::from("schema-version = 1\n");
    for (key, kind, bytes) in entries {
        store.put(key, bytes).unwrap();
        let sha = hex::encode(Sha256::digest(bytes));
        pins_toml.push_str(&format!(
            "[artifacts.{key}]\nsha256 = \"{sha}\"\nkind = \"{kind}\"\n"
        ));
    }
    let pins = PinManifest::from_toml_str(&pins_toml).unwrap();
    let uds_sha = hex::encode(Sha256::digest(entries[0].2));
    let epa_sha = hex::encode(Sha256::digest(entries[4].2));

                                                                                     
    let staging = tempfile::tempdir().unwrap();
    stage_representative(staging.path());
    let exceptions = stage_manifest_files(staging.path(), &dha_manifest(), &pins, &store).unwrap();
    assert_eq!(exceptions.len(), 1, "only epa.json is owner-declared");
    assert_eq!((exceptions[0].uid, exceptions[0].gid), (110, 110));

                                                                                                     
    let pseudo = build_pseudo(staging.path(), &exceptions);
    let sqfs = bake(staging.path(), &pseudo, Ownership::Map);
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("o.sqfs"), &sqfs).unwrap();
    let script = "cd /tmp && rm -rf ex && unsquashfs -no-xattrs -d ex /work/o.sqfs >/dev/null && \
        for f in uds-pipe intake-probe.sh real-job-probe.sh ac-i-selftest.sh epa.json; do \
          stat -c '%n %u %g %a' ex/opt/dha/$f; done && \
        sha256sum ex/opt/dha/uds-pipe ex/opt/dha/epa.json";
    let out = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work", work.path().display()))
        .args([IMAGE, "sh", "-c", script])
        .output()
        .expect("docker run unsquashfs");
    assert!(
        out.status.success(),
        "unsquashfs+stat failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
                                                                             
    for (name, expect) in [
        ("uds-pipe", "0 0 755"),
        ("intake-probe.sh", "0 0 644"),
        ("real-job-probe.sh", "0 0 644"),
        ("ac-i-selftest.sh", "0 0 644"),
        ("epa.json", "110 110 600"),
    ] {
        assert!(
            text.contains(&format!("/opt/dha/{name} {expect}")),
            "expected `ex/opt/dha/{name} {expect}` in:\n{text}"
        );
    }
                                                                                                      
    assert!(
        text.contains(&uds_sha),
        "baked uds-pipe bytes must equal the store's ({uds_sha}):\n{text}"
    );
    assert!(
        text.contains(&epa_sha),
        "baked epa.json bytes must equal the store's ({epa_sha}):\n{text}"
    );
}
