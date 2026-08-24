//! The ATTENDED docker-rung sign e2e (debt-burndown spec AC-C2/AC-D2, the docker half).
//!
//! Proves the wrapped-custody path end to end on the REAL container rung: a wrapped key set
//! routes to `SignPlan::Docker`, `docker_sign_manifest_bytes` round-trips an in-memory weights
//! manifest AND an update manifest through ONE pinned-container invocation each, and the returned
//! bundles verify under their purposes against the set's root — with the weights bundle's
//! delegation ctr equal to `read_weights_ctr` (the public-bundle independence property, L-2,
//! end to end).
//!
//! ATTENDED BY DESIGN (plan T4): `docker_sign_argv` runs the container `-it` and the in-container
//! `read_passphrase` is isatty-FAIL-CLOSED — that is a security control (the host never buffers
//! the passphrase), NOT a test inconvenience; never pipe stdin or weaken it (Safeguards
//! discipline). Run this in the T10 attended gate window; the fixture wrap passphrase to type at
//! the container prompt is `pw`. The UNATTENDED proof layer stays the non-docker unit tests
//! (AC-C4/AC-D3 + the routing tests) — this split is recorded honestly, no unattended e2e exists.
//!
//! Run: `RECIPES_DOCKER_SIGN_GATE=1 cargo test -p orchard --test docker_sign_gate -- --ignored`
//! (needs docker + the cached `recipes-imgbuild:dev` image + an attended terminal).

use dragonfruit::Purpose;
use sha2::{Digest, Sha256};
use std::path::Path;

fn require_gate_env() {
    if std::env::var_os("RECIPES_DOCKER_SIGN_GATE").is_none() {
        panic!(
            "docker sign gate invoked (--ignored) without RECIPES_DOCKER_SIGN_GATE=1 — this \
             attended e2e needs docker + the cached pinned image + an operator at the terminal \
             (wrap passphrase: pw). A gate must never pass without asserting the real path."
        );
    }
}

/// Both manifest kinds through the real docker rung: one container invocation per purpose,
/// operator types `pw` at each prompt.
#[test]
#[ignore = "docker gate: needs RECIPES_DOCKER_SIGN_GATE=1 + docker + the cached pinned image + an ATTENDED terminal"]
fn wrapped_custody_signs_weights_and_update_manifests_in_the_container() {
    require_gate_env();
    use orchard::deploy::artifact_keys::{
        Custody, generate_artifact_keys, read_weights_ctr, unix_now,
    };
    use orchard::deploy::artifact_sign::{SignPlan, docker_sign_manifest_bytes, plan_signing};

                                                                                              
                                                                                         
                                                                            
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root above crates/orchard")
        .to_path_buf();
    std::env::set_current_dir(&repo_root).expect("chdir to the workspace root");

    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    generate_artifact_keys(&keys, 365, false, Custody::Wrapped { passphrase: b"pw" }).unwrap();

                                                                           
    let plan = plan_signing(&keys, &dir.path().join("no-pin")).unwrap();
    assert!(
        matches!(plan, SignPlan::Docker),
        "wrapped set must plan Docker"
    );

    let root_pub = orchard::deploy::artifact_keys::read_root_pub(&keys).unwrap();

                                                                                             
                                                                                       
    let weights_manifest = format!(
        "verity-root-hash={}\nverity-offset=4096\nimage-sha256={}\nimage-size=8192\n",
        "ab".repeat(32),
        "cd".repeat(32)
    )
    .into_bytes();
    let update_manifest = b"format = 1\nfirmware = seabios-gpt\nversion = 2\n".to_vec();

    for (purpose, manifest, name) in [
        (Purpose::Weights, &weights_manifest, "weights-manifest"),
        (Purpose::UpdateImage, &update_manifest, "update-manifest"),
    ] {
        eprintln!("== docker sign ({purpose:?}) — type the wrap passphrase `pw` at the prompt ==");
        let sig = docker_sign_manifest_bytes(&keys, purpose, manifest, name)
            .unwrap_or_else(|e| panic!("docker sign ({purpose:?}) failed: {e}"));
        assert_eq!(sig.len(), 254, "{purpose:?}: bundle must be 254 bytes");

        let bf = dragonfruit::BundleFile::from_bytes(&sig).unwrap();
        let hash: [u8; 32] = Sha256::digest(manifest).into();
        dragonfruit::verify_bundle(&bf.as_bundle(), &root_pub, unix_now(), &hash, purpose)
            .unwrap_or_else(|e| panic!("{purpose:?}: bundle must verify: {e:?}"));

        if purpose == Purpose::Weights {
                                                                                         
                                                                                          
            let d = dragonfruit::Delegation::from_canonical(&bf.delegation_bytes).unwrap();
            let public_ctr = read_weights_ctr(&keys)
                .unwrap()
                .expect("wrapped set still yields the public ctr");
            assert_eq!(
                d.monotonic_ctr, public_ctr,
                "bundle ctr vs public-bundle ctr"
            );
        }
    }
}
