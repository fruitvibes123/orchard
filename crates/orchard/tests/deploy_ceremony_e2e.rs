                                                                                         
//!
//! Its own binary and its own make target (`make boot-gate-ceremony`), per the battery
//! convention: `#[ignore]`d so `cargo test` never pretends to run it, and PANICS without its env
                                                                                            
//!
                                                                                                
//! by this file's own text:
//! - it never re-enters the battery that contains it (`make boot-gate` does not invoke this
//!   binary, and `boot-gate-ceremony` does not invoke `boot-gate`);
//! - it never pre-seeds a gate record no gate run emitted (D17's no-preseed);
//! - `make boot-gate` and its leg list are byte-unchanged by this cycle.
//!
                                                                                                      
//! the leg's own registry entry (`ceremony_e2e_opts`), so the leg's declared hermetic mode is the
//! mode it actually boots — then drives a fixture-authored profile carrying the interview's
//! parameter set → `orchard run` with the judgment flags re-typed → S8 emits the record binding the
                                                                                                      
//! image to the child as an env var and booted NOTHING, so S9's preflight and S10's install hit an
//! unreachable `127.0.0.1:2222` and the run stopped at an owed step before any assertion. The image
                                                                                               
//! refusal has its own arm in `ceremony_gate`).
//!
//! Environment reproducibility (the RUN's contract, NOT this file's to solve): the ceremony REBUILDS
//! the image at S7, so its produced bytes equal `RECIPES_CEREMONY_IMG` only when the tenant handoff
//! (`/tmp/recipes-build-handoff`), the operator key set (`keys_dir`) and the pins match what that
//! image was built from. `make boot-gate-ceremony` sets that up; this binary fails closed on an
//! absent handoff and leaves the key/pin reproducibility to the environment.

use std::path::{Path, PathBuf};

use orchard::ceremony::leg_registry::ceremony_e2e_opts;

/// The env contract, parallel to `deploy_prod_e2e`'s (`orchard_guide.md` §12): the images and
/// keys one ceremony produced, plus the Debian guest the takeover installs onto.
fn gate_env() -> (PathBuf, PathBuf, PathBuf) {
    let need = |k: &str| -> PathBuf {
        match std::env::var(k) {
            Ok(v) if !v.is_empty() => PathBuf::from(v),
            _ => panic!(
                "deploy_ceremony_e2e invoked (--ignored) without {k}. This gate needs \
                 RECIPES_CEREMONY_IMG (a test-domain .img built by THIS ceremony), \
                 RECIPES_CEREMONY_PRIVKEY (its operator key) and \
                 RECIPES_PROD_E2E_DEBIAN_IMG (the Debian guest), plus /dev/kvm and \
                 cloud-localds. Run it via `make boot-gate-ceremony`. A boot gate must never \
                 pass without asserting."
            ),
        }
    };
    (
        need("RECIPES_CEREMONY_IMG"),
        need("RECIPES_CEREMONY_PRIVKEY"),
        need("RECIPES_PROD_E2E_DEBIAN_IMG"),
    )
}

/// The profile this fixture authors. ONE oracle with the Task-8 interview arm: both compose the
/// same parameter set, so a profile the interview would write and a profile this gate runs cannot
/// drift apart silently. `ssh_identity` is the PROVISIONING key of the booted Debian guest (the
/// pre-kexec connection the ceremony makes as `debian`); `port` is that guest's forwarded sshd port.
/// The operator key the ceremony bakes and reconnects the installed box with is the box's own,
/// under `keys_dir`, not this one.
fn write_fixture_profile(dir: &Path, img: &Path, ssh_identity: &Path, port: u16) -> PathBuf {
    let path = dir.join("boxes/ceremony-e2e.toml");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mk boxes");
    let profile = format!(
        "ip = \"127.0.0.1\"\n\
         port = {port}\n\
         domain = \"prod.test\"\n\
         net = \"mode=dhcp\"\n\
         provisioning_user = \"debian\"\n\
         firmware = \"seabios\"\n\
         container_image = \"recipes-imgbuild:dev\"\n\
         tenant_repo = \"recipes\"\n\
         tenant_source_ref = \"ceremony-e2e-fixture\"\n\
         gate_target = \"boot-gate-ceremony-legs\"\n\
         out_dir = \"{out}\"\n\
         keys_dir = \"{keys}\"\n\
         ssh_identity = \"{ssh_identity}\"\n\
         schema_version = 1\n",
        out = img.parent().unwrap_or(Path::new("/tmp")).display(),
        keys = dir.join("keys").display(),
        ssh_identity = ssh_identity.display(),
    );
                                                                                               
                                    
    assert!(
        orchard::deploy::profile::scan_for_forbidden_content(&profile).is_none(),
        "the fixture profile must carry no destructive intent, key material or typed token"
    );
    orchard::deploy::profile::load_str(&profile).expect("the fixture profile parses");
    std::fs::write(&path, profile).expect("write the fixture profile");
    path
}

#[test]
#[ignore = "boot gate: needs RECIPES_CEREMONY_{IMG,PRIVKEY} + RECIPES_PROD_E2E_DEBIAN_IMG + the tenant handoff + /dev/kvm + cloud-localds; run via `make boot-gate-ceremony`"]
fn the_ceremony_installs_a_serving_box_from_a_profile_on_produced_bytes() {
    let (img, _operator_privkey, debian_img) = gate_env();
                                                                                           
                                                                                                 
                                                                                                    
                                                                     
    if let orchard::ceremony::probes::ProbeResult::Unmet(why)
    | orchard::ceremony::probes::ProbeResult::Unevaluable(why) =
        orchard::ceremony::handoff::shape(Path::new(orchard::ceremony::spine::HANDOFF_ROOT))
    {
        panic!(
            "the tenant handoff tree is not present, so S5 would owe and the ceremony could not \
             reach its install: {why}. Build the tenant first (its release binaries must match the \
             ones RECIPES_CEREMONY_IMG was built from, or S7's rebuild will not reproduce it)."
        );
    }

    let work = tempfile::Builder::new()
        .prefix("ceremony-e2e-")
        .tempdir()
        .expect("workdir");

                                                                                              
                                                                                                    
                                                                                                    
                                                                                                   
                                                                                                  
                                                                                                     
                       
    let opts = ceremony_e2e_opts();
    let console = work.path().join("guest-console.log");
    let (_guest_guard, _guest_workdir, provisioning_privkey) =
        orchard::deploy::prod_e2e::boot_provisioned_guest(&debian_img, &opts, &console)
            .expect("boot the Debian guest the ceremony installs onto");

                                                                                               
                                                                                                   
                                                                                            
                                                                                                   
                                                                                               
                       
    let checkout = work.path().join("checkout");
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("the orchard worktree root");
    let add = std::process::Command::new("git")
        .current_dir(here)
        .args([
            "worktree",
            "add",
            "--detach",
            &checkout.display().to_string(),
            "HEAD",
        ])
        .output()
        .expect("git worktree add");
    assert!(
        add.status.success(),
        "could not cut the disposable checkout: {}",
        String::from_utf8_lossy(&add.stderr)
    );
                                                                                                
                                                                   
    let profile =
        write_fixture_profile(work.path(), &img, &provisioning_privkey, opts.forward_port);

                                                                                                   
                                                                                               
                                                                                                 
                                                                                     
    let state_dir = work.path().join("state");
    let records_dir =
        orchard::ceremony::records::records_dir_of(&state_dir.join("records"), &profile);
                                                                                                
                                                                  
    assert!(
        !orchard::ceremony::gate_record::profile_gate_record_path(&records_dir).exists(),
        "the fixture pre-seeded a gate record"
    );

                                                                                                  
                                                                                                  
                                                                                                    
                                                                                       
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"))
        .current_dir(work.path())
        .env(orchard::ceremony::records::STATE_DIR_ENV, &state_dir)
        .args([
            "--repo-root",
            &checkout.display().to_string(),
            "run",
            &profile.display().to_string(),
            "--target",
            "127.0.0.1",
            "--image-version",
            "1",
            "--wipe-confirmed",
            "--commit",
        ])
        .output()
        .expect("spawn the ceremony");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the ceremony did not complete: exit {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code()
    );

                                                                                                    
                                               
    let adopted = orchard::ceremony::gate_record::profile_gate_record_path(&records_dir);
    let record = orchard::ceremony::gate_record::read_gate_record(&adopted)
        .expect("the gate record was emitted and adopted");
    assert_eq!(
        record.gate_target, "boot-gate-ceremony-legs",
        "the fixture gates on the LEGS target — naming the target that contains this very leg \
         would recurse"
    );
    assert!(
        !record.leg.is_empty(),
        "the record binds the legs that ran, not an empty set"
    );
    let provenance =
        orchard::ceremony::gate_record::read(&img).expect("the image carries its provenance");
    assert_eq!(
        record.staged, provenance.produced,
        "the record attests THIS image's bytes"
    );

                                                                                               
                                                                
    let again = std::process::Command::new(env!("CARGO_BIN_EXE_orchard"))
        .current_dir(work.path())
        .env(orchard::ceremony::records::STATE_DIR_ENV, &state_dir)
        .args([
            "--repo-root",
            &checkout.display().to_string(),
            "run",
            &profile.display().to_string(),
            "--target",
            "127.0.0.1",
            "--image-version",
            "1",
            "--porcelain",
        ])
        .output()
        .expect("spawn the convergence run");
    let text = String::from_utf8_lossy(&again.stdout);
    assert!(
        again.status.success(),
        "the convergence run exited nonzero: {text}"
    );
    assert!(
        text.lines().filter(|l| l.starts_with("step\t")).count() >= 11,
        "every step reported: {text}"
    );
    assert!(
        !text.contains("action=run"),
        "a converged profile re-runs nothing: {text}"
    );

                                                                                           
                                                                          
    let _ = std::process::Command::new("git")
        .current_dir(here)
        .args([
            "worktree",
            "remove",
            "--force",
            &checkout.display().to_string(),
        ])
        .status();
}
