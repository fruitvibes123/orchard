//! The `orchard` binary — the operator-host build/deploy factory CLI.
//!
                                                                                     
//! 2026-06-13): `recipes-admin deploy <sub>` is now `orchard <sub>`, and
//! `recipes-admin derive-rescue-host-keys --image` is now `orchard derive-rescue-offline`.
//! Operator-host only — never baked into the box image.

                                                                                          
                                                                                      
  
                                                                                  
                                                                                                
                                                                                                
                                                                                           
                                                        
  
                                                                                                
                                                                              
                                                                                                
                                                                                      
                                                                                                 
                                                                                  
                                                                                                   
                                                                                                
                                                                          
                                                                                     
                                                                                           
                                                                                                
                                                                                                
                                                                                
                                                                                              
                                                                                                   
                                                                         
                                                                                      
                                                                                                
                                                                                           
                                                                                             
                                                               
                                                                                    
                                                                                              
                                                                                                 
                                 
                                                                                             
                                                                                  
                                                   
                                                        
                                                                                                  
                             
#![deny(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use orchard::ceremony::emit_stdout;
use orchard::cli::{MarketSub, OrchardCmd, RedelegatePurposeArg, StoreSub, WeightsAnchorArg};

                                                                                                  
/// input — a set env var refuses with the flag cure. Detection-only read: nothing consumes the
/// value (the lib reads no env; `resolve_weights_input` takes the flag values). The refusal fires
/// on all three build-capable arms (build, dryrun, prod inline-build); only `build` carries the
/// flags, so the cure names the build-then-hand-off route.
fn refuse_stale_weights_env() -> Result<(), orchard::ceremony::refusal::Refusal> {
    use orchard::ceremony::refusal::{Refusal, RefusalId};
    for (var, cure) in [
        ("RECIPES_DHA_WEIGHTS_GGUF", "--dha-weights-gguf"),
        ("RECIPES_DHA_MMPROJ_GGUF", "--dha-mmproj-gguf"),
    ] {
        if std::env::var_os(var).is_some() {
                                                                                    
                                                                              
            return Err(Refusal::new(
                RefusalId::WeightsEnvRefused,
                format!(
                    "{var} is set, but a process-env input that changes produced bytes is refused \
                    "
                ),
            )
                                                                                             
                                                                                               
            .with_cure_extra(format!("the set var is {var}; its flag is {cure}")));
        }
    }
    Ok(())
}

fn default_keys_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
                                                                                
                                                                                                   
                                                                                                     
                                                                                                      
                                                                                          
    let base = orchard::deploy::context::non_empty_var_os("XDG_CONFIG_HOME")
        .or_else(|| orchard::deploy::context::non_empty_var_os("HOME").map(|h| h.join(".config")))
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "no config base for the keys dir: set HOME or XDG_CONFIG_HOME, or pass --output-dir \
             <DIR> (refusing to write the operator key set into a CWD-relative .config)"
                .into()
        })?;
    Ok(base.join("recipes-deploy").join("keys"))
}

                                                                     
/// the inline `deploy prod` build both call this, so they can't diverge. Signs the
/// three box-consumed artifacts when an artifact key set is present, else prints
/// the un-adopted/UNSIGNED notice.
fn report_artifact_signing(
    repo_root: &std::path::Path,
    keys_dir: &std::path::Path,
    img: &std::path::Path,
    vmlinuz: &std::path::Path,
    initramfs: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
                                                                                    
                                                                               
                                                                                
                                                                                              
                                                                                        
                                                                                             
    let pin_path = orchard::deploy::pinned_artifact_root_path(repo_root);
    match orchard::deploy::artifact_sign::sign_build_outputs(
        keys_dir, &pin_path, img, vmlinuz, initramfs,
    )? {
        Some(sigs) => {
            for s in sigs {
                println!("  signed → {}", s.display());
            }
        }
        None => println!(
            "  artifact signing: no artifact key set in {} \
             (run `deploy generate-keys --artifact-signing …`) — built UNSIGNED",
            keys_dir.display()
        ),
    }
    Ok(())
}

fn run_deploy(
    cmd: OrchardCmd,
    ctx_flags: orchard::deploy::context::ContextFlags,
    ceremony_lock: Option<&orchard::ceremony::lock::CeremonyLock>,
) -> Result<(), Box<dyn std::error::Error>> {
    use orchard::deploy::keys::{self, GenMode, GenerateKeysOpts, ImportPaths};
    match cmd {
        OrchardCmd::Guide {
            profile,
            repo_form_dir,
        } => {
            use orchard::ceremony::interview;
                                                                                            
            interview::require_interactive_stdin()?;
            let prof = if profile.as_path().exists() {
                load_profile(profile.as_path())?
            } else {
                orchard::deploy::profile::Profile::default()
            };
            let ctx = orchard::deploy::context::resolve_context(&ctx_flags, Some(&prof))?;
            let records = orchard::ceremony::records::RunRecords::open(
                profile.as_path(),
                orchard::ceremony::records::mint_run_id(),
            )?
            .with_checkout(&ctx.repo_root);
            let measured = orchard::ceremony::admission::measure(&ctx.repo_root);
            let mut io = TerminalInterviewer;
            let conducted = match interview::conduct(
                &mut io,
                &profile,
                &prof,
                &ctx,
                &records,
                &measured,
                repo_form_dir.as_ref(),
            )? {
                interview::Conclusion::Authorized(c) => c,
                interview::Conclusion::Abandoned {
                    profile_written: true,
                } => {
                    emit_stdout(
                        "interview ended; the profile was written, the run was not authorized.\n",
                    );
                    return Ok(());
                }
                interview::Conclusion::Abandoned {
                    profile_written: false,
                } => {
                    emit_stdout("interview ended; nothing was written or authorized.\n");
                    return Ok(());
                }
            };
            interview::execute_authorized_run(
                &conducted,
                &ctx,
                ceremony_lock,
                &mut orchard::ceremony::runner::ProcessExecutor,
            )
            .map_err(Into::into)
        }
        OrchardCmd::Run {
            profile,
            target,
            image_version,
            commit,
            wipe_confirmed,
            porcelain,
            repo_form_dir,
        } => {
            use orchard::ceremony::admission::RunInvocation;
            use orchard::ceremony::runner::{ProcessExecutor, Reporter, run_ceremony};
            let prof = load_profile(profile.as_path())?;
            let ctx = orchard::deploy::context::resolve_context(&ctx_flags, Some(&prof))?;
            let mut judgment = std::collections::BTreeMap::new();
                                                                                                
                                                                                              
                                                                                        
            if let Some(v) = image_version {
                judgment.insert("image_version".to_string(), v.to_string());
            }
            let inv = RunInvocation {
                profile_path: profile.clone(),
                target,
                judgment,
                commit,
                wipe_confirmed,
                porcelain,
                repo_form_dir,
            };
            let mut records = orchard::ceremony::records::RunRecords::open(
                profile.as_path(),
                orchard::ceremony::records::mint_run_id(),
            )?
            .with_checkout(&ctx.repo_root);
            let admitted = orchard::ceremony::admission::admit(&inv, &ctx, &prof, &records)?;
                                                                                              
                                                                                                
                                             
            if !porcelain {
                emit_stdout(&orchard::ceremony::summary::render(&admitted, &inv, &ctx));
            }
                                                                                        
                                                                                            
                                                                                
            let is_tty = {
                use std::io::IsTerminal as _;
                !porcelain && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
            };
            let reporter = Reporter { porcelain };
            let prompt = || {
                use std::io::Write as _;
                print!(
                    "commit the ceremony's declared paths? [y = commit / e = edit the message / \
                     N = print the command] "
                );
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                line.trim().chars().next().unwrap_or('n')
            };
            let editor = std::env::var_os("EDITOR");
            let mut deps = orchard::ceremony::runner::RunnerDeps {
                exec: &mut ProcessExecutor,
                reporter: &reporter,
                lock_token: ceremony_lock.map(|l| l.token()),
                is_tty,
                prompt: &prompt,
                editor: editor.as_deref(),
            };
            run_ceremony(&admitted, &inv, &ctx, &prof, &mut records, &mut deps)
        }
        OrchardCmd::DeriveRescueOffline {
            image,
            print_fingerprint,
            pubkey,
            hostname,
        } => orchard::oneshots_offline::derive_rescue_offline(
            &image,
            print_fingerprint,
            pubkey,
            hostname.as_deref(),
        ),
        OrchardCmd::GenerateKeys {
            porcelain: _,
            force,
            output_dir,
            subject,
            regenerate_master_key,
            artifact_signing,
            delegation_window_days,
            artifact_keys_only,
            secure_boot,
            sb_rsa,
            sb_db_fingerprint_path,
            signing_key_token,
            import_image_signing,
            import_image_signing_cert,
            import_signing_ca,
            import_signing_ca_cert,
            import_ima,
            import_ima_cert,
        } => {
                                                                                                   
                                                                                                        
                                                                                                       
                                                                                                   
                                                                        
                                                                                        
                                                         
            if let Some(rung_raw) = secure_boot {
                use orchard::deploy::secure_boot_keys::{
                    SbRsaBits, SecureBootKeysOpts, SecureBootRung, generate_secure_boot_keys,
                };
                let rung = SecureBootRung::parse(&rung_raw).ok_or_else(|| {
                    format!("--secure-boot {rung_raw:?}: want software | one-signer | two-signers")
                })?;
                let bits = SbRsaBits::parse(&sb_rsa)
                    .ok_or_else(|| format!("--sb-rsa {sb_rsa:?}: want 3072 | 2048"))?;
                let db_fingerprint_path = match sb_db_fingerprint_path {
                    Some(p) => p,
                    None => repo_sb_db_fingerprint_path(&resolved_root(&ctx_flags)?)?,
                };
                let opts = SecureBootKeysOpts {
                    keys_dir: match output_dir {
                        Some(d) => d,
                        None => default_keys_dir()?,
                    },
                    db_fingerprint_path,
                    rung,
                    bits,
                    force,
                    subject_ou: subject,
                };
                generate_secure_boot_keys(&opts)?;
                emit_stdout(&format!(
                    "deploy generate-keys --secure-boot: wrote the PK/KEK/db family to \
                     {}/secure-boot + pinned the PK/KEK/db fingerprints into {}\n",
                    opts.keys_dir.display(),
                    opts.db_fingerprint_path.display()
                ));
                                                                                                     
                                                                                                       
                emit_stdout(&orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::generate_keys_secure_boot_next_steps(
                        &opts.db_fingerprint_path,
                    ),
                ));
                return Ok(());
            }
            let mode = if let Some(slot) = signing_key_token {
                GenMode::Token { slot }
            } else if let Some(is_key) = import_image_signing {
                                                                            
                GenMode::Import(ImportPaths {
                    image_signing_key: is_key,
                    image_signing_cert: import_image_signing_cert.unwrap(),
                    signing_ca_key: import_signing_ca.unwrap(),
                    signing_ca_cert: import_signing_ca_cert.unwrap(),
                    ima_key: import_ima.unwrap(),
                    ima_cert: import_ima_cert.unwrap(),
                })
            } else {
                GenMode::Generate
            };
                                                                 
                                                                                    
            let fingerprints_path = if regenerate_master_key {
                PathBuf::new()
            } else {
                repo_fingerprints_path(&resolved_root(&ctx_flags)?)?
            };
            let opts = GenerateKeysOpts {
                output_dir: match output_dir {
                    Some(d) => d,
                    None => default_keys_dir()?,
                },
                subject_ou: subject,
                force,
                mode,
                regenerate_master_key,
                fingerprints_path,
            };

                                                                                    
                                                                                    
                                                                                   
            if let Some(rung) = artifact_signing {
                use orchard::deploy::artifact_keys;

                                                                      
                                                                                       
                                                                                     
                                                                              
                if artifact_keys_only {
                                                                                           
                                                                                          
                                                                                         
                                                                                             
                                                    
                    orchard::deploy::dumpable::set_process_non_dumpable().map_err(|e| {
                        format!(
                            "generate-keys (in-container): refusing to mint seeds in a \
                             dumpable process (PR_SET_DUMPABLE failed): {e}"
                        )
                    })?;
                                                                           
                                                                                              
                                                                                          
                                                                                         
                    match rung.as_str() {
                        "software" => {
                            artifact_keys::generate_artifact_keys(
                                &opts.output_dir,
                                delegation_window_days,
                                force,
                                artifact_keys::Custody::Raw,
                            )?;
                        }
                        "docker" => {
                            let pass = orchard::deploy::tty::read_new_passphrase(
                                "Set a passphrase to wrap the artifact-signing keys: ",
                                "Confirm passphrase: ",
                            )?;
                            artifact_keys::generate_artifact_keys(
                                &opts.output_dir,
                                delegation_window_days,
                                force,
                                artifact_keys::Custody::Wrapped { passphrase: &pass },
                            )?;
                        }
                        other => {
                            return Err(format!(
                                "--artifact-keys-only supports the software|docker rungs, not {other:?}"
                            )
                            .into());
                        }
                    }
                    emit_stdout(&format!(
                        "deploy generate-keys: artifact keys minted to {} \
                         (keys-only; the committed pin is written host-side)\n",
                        opts.output_dir.display()
                    ));
                    return Ok(());
                }

                if !keys::signing_set_exists(&opts.output_dir) {
                    keys::generate_keys(&opts)?;                                     
                }
                                                                                           
                                                                                          
                                                                                             
                                                                                                    
                                                                                                 
                                                                                                 
                let root = resolved_root(&ctx_flags)?;
                let _ = repo_fingerprints_path(&root)?;
                let pin_path = orchard::deploy::pinned_artifact_root_path(&root);
                match rung.as_str() {
                    "software" => {
                        let root = artifact_keys::provision_software_rung(
                            &opts.output_dir,
                            &pin_path,
                            delegation_window_days,
                            force,
                        )?;
                        emit_stdout(&format!(
                            "deploy generate-keys: artifact-signing `software` rung — \
                             root pin ed25519:{} → {}\n",
                            hex::encode(root),
                            pin_path.display()
                        ));
                    }
                    "docker" => {
                                                                                   
                                                                                           
                                                                                           
                                                      
                                                                                       
                                                                                          
                                                                        
                        let image_id =
                            artifact_keys::resolve_image_id(artifact_keys::IMGBUILD_TAG)?;
                                                                                                  
                                                                                                   
                                                                                         
                                                                                            
                        orchard::ceremony::emit_stderr(&format!(
                            "resolved {} → {image_id} (this operation runs by that id)\n",
                            artifact_keys::IMGBUILD_TAG
                        ));
                        let argv = artifact_keys::docker_keygen_argv(
                            &image_id,
                            &opts.output_dir,
                            delegation_window_days,
                            force,
                        )?;
                        orchard::ceremony::emit_stderr(&format!(
                            "artifact keygen in the pinned container: {}\n",
                            argv.join(" ")
                        ));
                        let status = std::process::Command::new(&argv[0])
                            .args(&argv[1..])
                            .status()?;
                        if !status.success() {
                            return Err(format!("docker artifact keygen exited {status}").into());
                        }
                                                                                             
                                                                                            
                                                                                                  
                        let root_pub = artifact_keys::read_root_pub(&opts.output_dir)?;
                        orchard::deploy::fingerprints::set_artifact_root_pin(&pin_path, &root_pub)?;
                        emit_stdout(&format!(
                            "deploy generate-keys: artifact-signing `docker` rung — keys minted \
                             in-container (passphrase-wrapped at rest); root pin ed25519:{} → {} \
                             (written host-side)\n",
                            hex::encode(root_pub),
                            pin_path.display()
                        ));
                    }
                    other => {
                        return Err(keys::DeployKeyError::HardwareRungNotYetAvailable(
                            other.to_string(),
                        )
                        .into());
                    }
                }
                emit_stdout(&orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::generate_keys_next_steps(),
                ));
                return Ok(());
            }

            keys::generate_keys(&opts)?;
            if regenerate_master_key {
                emit_stdout(&format!(
                    "deploy generate-keys: rotated rescue-seed-master.key in {}\n",
                    opts.output_dir.display()
                ));
                                                                                                
                                                                                               
                                     
            } else {
                emit_stdout(&format!(
                    "deploy generate-keys: wrote key set to {} + fingerprints to {}\n",
                    opts.output_dir.display(),
                    opts.fingerprints_path.display()
                ));
                emit_stdout(&orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::generate_keys_next_steps(),
                ));
            }
            Ok(())
        }
        OrchardCmd::SignSb {
            img,
            keys_dir,
            secure_boot,
            container_image,
        } => {
            use orchard::deploy::secure_boot_keys::SecureBootRung;
            use orchard::deploy::sign_sb::{SignSbOpts, sign_sb};
            let rung = SecureBootRung::parse(&secure_boot).ok_or_else(|| {
                format!("--secure-boot {secure_boot:?}: want software | one-signer | two-signers")
            })?;
            let opts = SignSbOpts {
                img,
                keys_dir: match keys_dir {
                    Some(d) => d,
                    None => default_keys_dir()?,
                },
                rung,
                container_image,
                db_fingerprint_path: repo_sb_db_fingerprint_path(&resolved_root(&ctx_flags)?)?,
            };
            sign_sb(&opts)?;
            println!(
                "deploy sign-sb: db-signed loader+kernel spliced into {} (ESP), signed-PE \
                 sidecars written, .sha256 recomputed. NOTE: the operator ed25519 .img \
                 signature is the documented un-wired forward-debt — once wired it signs \
                 this post-splice image.",
                opts.img.display()
            );
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::sign_sb_next_steps(&opts.img),
                )
            );
            Ok(())
        }
        OrchardCmd::BuildInstallerUsb {
            from,
            install_to,
            container_image,
        } => {
            use orchard::deploy::installer_usb_cmd::{InstallerUsbCliOpts, build_installer_usb};
            let opts = InstallerUsbCliOpts {
                from,
                install_to,
                container_image,
                                                                                          
                repo_root: resolved_root(&ctx_flags)?,
            };
            let out = build_installer_usb(&opts)?;
            println!(
                "deploy build-installer-usb: wrote {} (+ {}). The installer loader is UNSIGNED — \
                 run `deploy sign-installer-usb` to db-sign + splice it before enrolling/booting.",
                out.img.display(),
                out.sha256.display()
            );
            Ok(())
        }
        OrchardCmd::SignInstallerUsb {
            img,
            keys_dir,
            secure_boot,
            container_image,
        } => {
            use orchard::deploy::secure_boot_keys::SecureBootRung;
            use orchard::deploy::sign_installer_usb::{SignInstallerUsbOpts, sign_installer_usb};
            let rung = SecureBootRung::parse(&secure_boot).ok_or_else(|| {
                format!("--secure-boot {secure_boot:?}: want software | one-signer | two-signers")
            })?;
            let opts = SignInstallerUsbOpts {
                usb_img: img,
                keys_dir: match keys_dir {
                    Some(d) => d,
                    None => default_keys_dir()?,
                },
                rung,
                container_image,
                db_fingerprint_path: repo_sb_db_fingerprint_path(&resolved_root(&ctx_flags)?)?,
            };
            sign_installer_usb(&opts)?;
            println!(
                "deploy sign-installer-usb: db-signed installer loader spliced into {} (USB ESP), \
                 signed-loader sidecar written, .sha256 recomputed. The kernel was already signed at \
                 sign-sb time; enroll the matching PK/KEK/db, then boot the USB under enforcing SB.",
                opts.usb_img.display()
            );
            Ok(())
        }
        OrchardCmd::UpdateCertFingerprints {
            image_signing,
            signing_ca,
            ima,
        } => {
            use orchard::deploy::fingerprints::{CertFingerprintUpdate, update_cert_fingerprints};
            let toml_path = repo_fingerprints_path(&resolved_root(&ctx_flags)?)?;
            update_cert_fingerprints(
                &toml_path,
                &CertFingerprintUpdate {
                    image_signing,
                    signing_ca,
                    ima,
                },
            )?;
            println!(
                "deploy update-cert-fingerprints: updated {}",
                toml_path.display()
            );
            Ok(())
        }
        OrchardCmd::Redelegate {
            keys_dir,
            purpose,
            window_days,
        } => {
            use dragonfruit::Purpose;
            use orchard::deploy::keys::DeployKeyError;
            use orchard::deploy::redelegate::redelegate;
            let keys_dir = match keys_dir {
                Some(d) => d,
                None => default_keys_dir()?,
            };
            let purposes: &[Purpose] = match purpose {
                RedelegatePurposeArg::All => &[Purpose::UpdateImage, Purpose::RootHash],
                RedelegatePurposeArg::UpdateImage => &[Purpose::UpdateImage],
                RedelegatePurposeArg::RootHash => &[Purpose::RootHash],
                RedelegatePurposeArg::Weights => &[Purpose::Weights],
            };
                                                                                       
                                                                                    
                                                                                        
                                                                                        
            let minted = match redelegate(&keys_dir, purposes, window_days, None) {
                Ok(minted) => minted,
                Err(DeployKeyError::Passphrase { .. }) => {
                    let pass = orchard::deploy::tty::read_passphrase(
                        "Passphrase for the wrapped artifact keys: ",
                    )?;
                    redelegate(&keys_dir, purposes, window_days, Some(&pass))?
                }
                Err(e) => return Err(format!("redelegate: {e}").into()),
            };
            for m in &minted {
                println!(
                    "orchard redelegate: minted {:?} delegation -> {} \
                     (monotonic_ctr={}, window {window_days}d)",
                    m.purpose,
                    m.path.display(),
                    m.monotonic_ctr
                );
            }
            println!(
                "orchard redelegate: box trust anchor UNCHANGED (no rebake owed). \
                 next: orchard build (bakes min_delegation_ctr from the UpdateImage \
                 delegation) / orchard update"
            );
            Ok(())
        }
        OrchardCmd::Update {
            host,
            image,
            keys_dir,
            identity,
            port,
            confirmed,
            host_fingerprint,
        } => {
            use orchard::deploy::host_pins::HostPinOpts;
            use orchard::deploy::update::{
                Authorize, CeremonyOpts, SshUpdateOps, prepare_local_image, run_ceremony,
            };
            let keys_dir = match keys_dir {
                Some(d) => d,
                None => default_keys_dir()?,
            };
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                                                                                             
                                                                                               
                                                                                          
                                                                                            
                                            
            let pin_path = repo_root()
                .map(|r| orchard::deploy::pinned_artifact_root_path(&r))
                .unwrap_or_else(|_| keys_dir.join("no-committed-pin"));
                                                                                                         
                                                         
            let prepared = prepare_local_image(&image, &keys_dir)?;
            let pin_dir = default_keys_dir()?
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
                                                                                                   
                                                                                                      
                                                                                                     
                                  
            let ops = SshUpdateOps::new(host.clone(), port, identity, is_tty)
                .with_post_flip_key(prepared.post_flip_hostkey.clone());
            let cer = CeremonyOpts {
                host: &host,
                keys_dir: &keys_dir,
                authorize: if confirmed {
                    Authorize::Confirmed
                } else {
                    Authorize::Interactive
                },
                host_pin: HostPinOpts {
                    host_fingerprint: host_fingerprint.as_deref(),
                    is_tty,
                    pin_dir: &pin_dir,
                },
            };
            let outcome = run_ceremony(&prepared, &pin_path, &cer, &ops)?;
            let orchard::deploy::update::CeremonyOutcome { report, pin } = &outcome;
            println!("orchard update: {}", report.summary());
            match pin {
                orchard::deploy::update::PinAction::Superseded { to } => println!(
                    "orchard update: host pin superseded to the image-derived runtime key {to} \
                     (the old pin is archived beside the store)"
                ),
                orchard::deploy::update::PinAction::SupersedeFailed { detail } => println!(
                    "orchard update: WARNING — committed, but the host pin could not be rotated \
                     ({detail}); the next contact will refuse against the stale pin until resolved \
                     by hand (re-pin to the pushed image's derived fingerprint)"
                ),
                orchard::deploy::update::PinAction::Unchanged => {}
            }
                                                                                                       
                                                                                          
                                                                                          
                                                                                         
                                                                                                    
            if outcome.is_success() {
                Ok(())
            } else {
                Err(outcome.exit_reason().into())
            }
        }
        OrchardCmd::DeployModel {
            host,
            model,
            keys_dir,
            identity,
            port,
            container_image,
            confirmed,
            host_fingerprint,
        } => {
            use orchard::deploy::deploy_model::{
                ModelPushReport, SshModelOps, prepare_model_push, run_model_ceremony,
            };
            use orchard::deploy::host_pins::HostPinOpts;
            use orchard::deploy::update::{Authorize, CeremonyOpts};
            let keys_dir = match keys_dir {
                Some(d) => d,
                None => default_keys_dir()?,
            };
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let root = resolved_root(&ctx_flags)?;           
                                                                                    
                                                            
            let pin_path = orchard::deploy::pinned_artifact_root_path(&root);
                                                                                              
                               
            let prepared = prepare_model_push(&model, &container_image, &root)?;
            let pin_dir = default_keys_dir()?
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let ops = SshModelOps::new(host.clone(), port, identity, is_tty);
            let cer = CeremonyOpts {
                host: &host,
                keys_dir: &keys_dir,
                authorize: if confirmed {
                    Authorize::Confirmed
                } else {
                    Authorize::Interactive
                },
                host_pin: HostPinOpts {
                    host_fingerprint: host_fingerprint.as_deref(),
                    is_tty,
                    pin_dir: &pin_dir,
                },
            };
            match run_model_ceremony(&prepared, &pin_path, &cer, &ops)? {
                ModelPushReport::Committed => {
                    println!("orchard deploy-model: COMMITTED (the box serves the new model)");
                    Ok(())
                }
                ModelPushReport::Refused { detail } => {
                    println!("orchard deploy-model: REFUSED — {detail}");
                    Err("deploy-model refused".into())
                }
                ModelPushReport::Degraded { detail } => {
                    println!("orchard deploy-model: DEGRADED — {detail}");
                    Err("deploy-model degraded".into())
                }
            }
        }
        OrchardCmd::Status {
            host,
            image,
            ssh_identity,
            keys_dir,
            host_fingerprint,
            port,
        } => {
            use orchard::deploy::status::{StatusArgs, run};
            let pin_dir = default_keys_dir()?
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
                                                                                                     
                                                                                                    
                                                                                                   
                                                                                    
            let committed_pin = resolved_root(&ctx_flags)
                .ok()
                .filter(|r| repo_fingerprints_path(r).is_ok())
                .map(|r| orchard::deploy::pinned_artifact_root_path(&r))
                .filter(|p| p.exists());
            let args = StatusArgs {
                host,
                port,
                image,
                ssh_identity,
                keys_dir,
                committed_pin,
                host_fingerprint,
                pin_dir,
                is_tty,
            };
                                                                                                         
            let exit = run(&args);
            use std::io::Write as _;
            std::io::stdout().flush().ok();
                                                                                        
            #[allow(clippy::disallowed_methods)]
            std::process::exit(exit.code());
        }
        OrchardCmd::RotateKey {
            host,
            new_identity,
            ssh_identity,
            host_fingerprint,
            port,
        } => {
            use orchard::deploy::rotate_key::{RotateKeyArgs, run};
            let pin_dir = default_keys_dir()?
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("host-pins");
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let args = RotateKeyArgs {
                host,
                port,
                new_identity,
                ssh_identity,
                host_fingerprint,
                pin_dir,
                is_tty,
            };
                                                                                                        
            let outcome = run(&args);
            use std::io::Write as _;
            std::io::stdout().flush().ok();
                                                                                           
            #[allow(clippy::disallowed_methods)]
            std::process::exit(outcome.code());
        }
        OrchardCmd::SignBackup { file, output_dir } => {
            let keys_dir = match output_dir {
                Some(d) => d,
                None => default_keys_dir()?,
            };
                                                                                         
                                                                                      
                                                                                       
                                                                                
                                                                      
            let pin_path = repo_root()
                .map(|r| orchard::deploy::pinned_artifact_root_path(&r))
                .unwrap_or_else(|_| keys_dir.join("no-committed-pin"));
            let sig =
                orchard::deploy::artifact_sign::sign_backup_routed(&keys_dir, &pin_path, &file)?;
            println!(
                "deploy sign-backup: signed {} → {} (purpose=backup)",
                file.display(),
                sig.display()
            );
            Ok(())
        }
        OrchardCmd::SignInContainer {
            keys_dir,
            img,
            vmlinuz,
            initramfs,
            backup,
            weights,
            update_image,
        } => {
            use orchard::deploy::artifact_keys::sign_in_container_pairs;
            use orchard::deploy::artifact_sign::sign_in_container_leaf;
                                                                                           
                                                                                             
                                                                                           
                                                                                             
                                                                                             
                                                                              
            orchard::deploy::dumpable::set_process_non_dumpable().map_err(|e| {
                format!(
                    "sign-in-container: refusing to unwrap a seed in a dumpable process \
                     (PR_SET_DUMPABLE failed): {e}"
                )
            })?;
                                                                                  
                                                                                               
            let pass = orchard::deploy::tty::read_passphrase(
                "Passphrase to unwrap the artifact-signing worker key: ",
            )?;
                                                                                        
                                                                                          
                                                                                          
                                                                                        
            let targets =
                sign_in_container_pairs(img, vmlinuz, initramfs, backup, weights, update_image);
            if targets.is_empty() {
                return Err("sign-in-container: no artifact given \
                            (pass --img/--vmlinuz/--initramfs/--backup/--weights/--update-image)"
                    .into());
            }
            let sigs = sign_in_container_leaf(&keys_dir, pass.as_slice(), &targets)?;
            for ((_, purpose), sig) in targets.iter().zip(sigs) {
                println!("  signed → {} (purpose={purpose:?})", sig.display());
            }
            Ok(())
        }
        OrchardCmd::RestoreImage {
            data,
            db,
            operator_pubkey,
            root,
            db_target,
            db_owner,
            out,
            container_image,
            manifest_full,
        } => {
            use recipes_image_builder::build_tools_host::HostBuildTools;
            use recipes_image_builder::restore_image::{
                RestoreImageSpec, check_restore_identity, plan_size, stage_restore,
            };
                                                                                               
                                                                                                  
                                                                                           
            let pubkey_line =
                orchard::deploy::build_image::read_validated_pubkey("operator", &operator_pubkey)?;
            let data_bytes =
                std::fs::read(&data).map_err(|e| format!("read --data {}: {e}", data.display()))?;
            let db_bytes =
                std::fs::read(&db).map_err(|e| format!("read --db {}: {e}", db.display()))?;
            let spec = RestoreImageSpec {
                data_tar_gz: &data_bytes,
                db: &db_bytes,
                operator_pubkey: pubkey_line.as_bytes(),
                root: &root,
                db_target: &db_target,
                db_owner,
            };
            let staged = stage_restore(&spec)?;
            let plan = plan_size(staged.content_bytes, staged.file_count)?;
            let tools = HostBuildTools::new(container_image, resolved_root(&ctx_flags)?);           
            let img = tools.bake_restore_image(&staged, plan)?;
            check_restore_identity(&img)?;
            std::fs::write(&out, &img)
                .map_err(|e| format!("write --out {}: {e}", out.display()))?;

                                                                                                
                                                                                                            
                                                                                                         
                                                                                                         
            let db_rel = format!("{root}/{db_target}");
            print!(
                "{}",
                orchard::deploy::report::restore_manifest_rollup(
                    &staged.manifest,
                    staged.resolved_db_owner,
                    &db_rel,
                    manifest_full,
                )
            );
            let (du, dg) = staged.resolved_db_owner;
            println!("resolved db-owner: {du}:{dg}");
            println!(
                "size plan: {} blocks ({} MiB) / {} inodes (explicit -N)",
                plan.blocks,
                plan.blocks * 4096 / (1024 * 1024),
                plan.inodes
            );
                                                                                                   
                                                                  
            let digest = orchard::deploy::artifact_sign::streaming_sha256(&out)?;
            println!(
                "restore image: {} ({} bytes, sha256 {})",
                out.display(),
                img.len(),
                hex::encode(digest)
            );
            println!("sign it: orchard sign-backup {}", out.display());
            Ok(())
        }
        OrchardCmd::Build {
            porcelain: _,
            profile,
            domain,
            keys_dir,
            out_dir,
            ksrc,
            syslinux_src,
            container_image,
            allow_dirty,
            verify,
            recovery_pubkey,
            operator_pubkey,
            firmware,
            net,
            secure_boot,
            manifest,
            substrate,
            image_version,
            weights_anchor,
            #[cfg(feature = "ceremony-seed-unclassified-flag")]
                ceremony_seed_unclassified: _,
            dha_weights_gguf,
            dha_mmproj_gguf,
        } => {
            use orchard::deploy::build_image::{
                BuildImageOpts, build_image, check_substrate_flag, default_kernel_xz,
                default_syslinux_src,
            };
                                                                                               
            refuse_stale_weights_env()?;
                                                                                                        
                                                                                                   
                                                                                                      
                                                                                                      
                                                                                                    
                                                                                                  
                                                        
            use orchard::deploy::profile::{
                BUILD_NOTED_KEYS, build_manifest_weights, noted_keys_present, pick, require_present,
            };
            let profile = profile.map(|p| load_profile(&p)).transpose()?;
            let prof = profile.as_ref();
            if let Some(p) = prof {
                let ignored = noted_keys_present(p, BUILD_NOTED_KEYS);
                if !ignored.is_empty() {
                    emit_stdout(&format!(
                        "note: the profile's key(s) [{}] are not consumed by `build` — ignored \
                         here.\n",
                        ignored.join(", ")
                    ));
                }
            }
            let domain_merged = pick(domain, prof.and_then(|p| p.domain.clone()), None);
            let domain =
                require_present("domain", "--domain", "domain", domain_merged.as_ref())?.clone();
            let out_dir = pick(out_dir, prof.and_then(|p| p.out_dir.clone()), None)
                .unwrap_or_else(|| PathBuf::from(orchard::deploy::build_image::DEFAULT_OUT_DIR));
                                                                                              
                                                          
            let hint_domain = domain.clone();
            let net = pick(net, prof.and_then(|p| p.net.clone()), None);
            let keys_dir = pick(keys_dir, prof.and_then(|p| p.keys_dir.clone()), None);
                                                                                                     
                                                                                                
                                                                                            
            let (manifest, dha_weights_gguf) =
                build_manifest_weights(manifest, dha_weights_gguf, prof);
                                                                                               
                                                                        
            let firmware = match (firmware, prof.and_then(|p| p.firmware.clone())) {
                (Some(f), _) => f,
                (None, Some(s)) => orchard::cli::parse_firmware(&s)
                    .map_err(|e| format!("profile `firmware`: {e}"))?,
                (None, None) => orchard::deploy::build_image::Firmware::Seabios,
            };
            let image_version =
                pick(image_version, prof.and_then(|p| p.image_version), Some(0)).unwrap_or(0);
            let container_image = pick(
                container_image,
                prof.and_then(|p| p.container_image.clone()),
                Some("recipes-imgbuild:dev".to_string()),
            )
            .unwrap_or_default();
                                                                                                   
                                                                                    
            check_substrate_flag(firmware, substrate.as_deref())?;
                                                                                     
            let ctx = orchard::deploy::context::resolve_context(&ctx_flags, prof)?;
            let root = ctx.repo_root.to_path_buf();
            let kernel_src = match ksrc {
                Some(p) => p,
                None => default_kernel_xz(&root)?,
            };
            let syslinux_src = match syslinux_src {
                Some(p) => p,
                None => default_syslinux_src(&root)?,
            };
            let opts = BuildImageOpts {
                keys_dir: match keys_dir {
                    Some(d) => d,
                    None => default_keys_dir()?,
                },
                repo_root: root,
                artifact_store: ctx.artifact_store.into(),
                kernel_src,
                syslinux_src,
                out_dir,
                domain,
                container_image,
                allow_dirty,
                recovery_pubkey,
                operator_pubkey,
                firmware,
                net,
                sb_required: secure_boot,
                manifest_path: manifest,
                image_version,
                runtime_weights: weights_anchor == WeightsAnchorArg::Runtime,
                dha_weights_gguf,
                dha_mmproj_gguf,
            };
            if verify {
                use orchard::deploy::verify::{render_report, verify_build};
                let outcome = verify_build(&opts)?;
                print!("{}", render_report(&outcome));
                if !outcome.identical {
                    return Err("determinism self-test FAILED: the two builds diverged \
                                (see the per-component report above)"
                        .into());
                }
                Ok(())
            } else {
                let out = build_image(&opts)?;
                println!(
                    "deploy build: wrote {} (+ .layout.toml + .sha256); verity root hash {}",
                    out.outputs.img.display(),
                    out.root_hash
                );
                                                                                     
                                                                                         
                                                                           
                report_artifact_signing(
                    &opts.repo_root,
                    &opts.keys_dir,
                    &out.outputs.img,
                    &out.outputs.vmlinuz,
                    &out.outputs.initramfs,
                )?;
                print!(
                    "{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::build_next_steps(
                            &out.outputs.img,
                            &hint_domain,
                            &opts.repo_root,
                        ),
                    )
                );
                Ok(())
            }
        }
        OrchardCmd::Dryrun {
            keep_running,
            image,
            domain,
            allow_dirty,
            memory_mb,
        } => {
            use orchard::deploy::dryrun::{DryrunOpts, boot_and_verify};
            let opts = DryrunOpts {
                keep_running,
                memory_mb,
                ..DryrunOpts::default()
            };
            let img = match image {
                Some(prebuilt) => prebuilt,
                None => {
                    use orchard::deploy::build_image::{
                        BuildImageOpts, build_image, default_kernel_xz, default_syslinux_src,
                    };
                                                                                                  
                    refuse_stale_weights_env()?;
                    let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                    let root = ctx.repo_root.to_path_buf();
                    let bopts = BuildImageOpts {
                        keys_dir: default_keys_dir()?,
                        kernel_src: default_kernel_xz(&root)?,
                        syslinux_src: default_syslinux_src(&root)?,
                        repo_root: root,
                        artifact_store: ctx.artifact_store.into(),
                        out_dir: PathBuf::from("/tmp"),
                        domain,
                        container_image: "recipes-imgbuild:dev".to_string(),
                        allow_dirty,
                        recovery_pubkey: None,
                        operator_pubkey: None,
                        firmware: orchard::deploy::build_image::Firmware::Seabios,
                                                                                           
                                                                                         
                        net: None,
                        sb_required: false,
                        manifest_path: None,
                                                                                                        
                                                                                                          
                        image_version: 0,
                        runtime_weights: false,
                        dha_weights_gguf: None,
                        dha_mmproj_gguf: None,
                    };
                    let out = build_image(&bopts)?;
                    println!(
                        "deploy dryrun: built {} (verity root hash {})",
                        out.outputs.img.display(),
                        out.root_hash
                    );
                    out.outputs.img
                }
            };
            boot_and_verify(&img, &opts)?;
            println!(
                "deploy dryrun: PASS — image booted; dropbear accepted the operator pubkey, \
                 recipes answered, rootfs is read-only."
            );
            Ok(())
        }
        OrchardCmd::Doctor {
            for_verb,
            image,
            keys_dir,
        } => {
            use orchard::deploy::doctor::{Probes, Scope, render, run_checks};
            let keys_dir = match keys_dir {
                Some(d) => d,
                None => default_keys_dir()?,
            };
                                                                                                    
                                                                            
            let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None);
            match &ctx {
                                                                                                      
                                                                                                
                Ok(c) => emit_stdout(&orchard::deploy::context::render_context(c)),
                Err(e) => emit_stdout(&format!("context: could not resolve — {e}\n")),
            }
            emit_stdout("\n");
                                                                                                    
            let repo = ctx
                .map(|c| c.repo_root.to_path_buf())
                .unwrap_or_else(|_| PathBuf::from("."));
            let scope = match for_verb.as_deref() {
                Some("build") => Scope::Build,
                Some("dryrun") => Scope::Dryrun,
                Some("prod") => Scope::Prod {
                    image: image.clone(),
                },
                Some("boot-gate") => Scope::BootGate,
                _ => Scope::Full,
            };
            let probes = Probes::gather(&scope, &keys_dir, &repo);
            let checks = run_checks(&probes, &scope);
            emit_stdout(&render(&checks, &scope));
                                                                                                         
                                                                                    
            if matches!(scope, Scope::BootGate) {
                emit_stdout(&format!(
                    "\n{}",
                    orchard::deploy::epilogue::next_steps(
                        &orchard::deploy::epilogue::boot_gate_env_skeleton(image.as_deref()),
                    )
                ));
            }
            Ok(())                                                    
        }
        OrchardCmd::Prod {
            porcelain: _,
            provisioning_user,
            ip,
            profile,
            pubkey,
            image,
            ssh_identity,
            box_login_identity,
            port,
            host_fingerprint,
            known_hosts,
            runtime_hostkey_fingerprint,
            image_stage_dir,
            wipe_confirmed,
            reconnect_timeout_secs,
            restore_from,
            restore_min_ctr,
            artifact_pin,
            reclaim_tail,
            reclaim_timeout_secs,
            domain,
            keys_dir,
            out_dir,
            ksrc,
            syslinux_src,
            container_image,
            allow_dirty,
            recovery_pubkey,
            net,
        } => {
            use orchard::deploy::build_image::{
                BuildImageOpts, build_image, default_kernel_xz, default_syslinux_src,
            };
            use orchard::deploy::prod::{WipeConfirmed, validate_target_host};
            use orchard::deploy::prod_orchestrate::{
                DEPLOY_LOCK_DIR, DeployProdOpts, ProcessOps, acquire_deploy_lock, deploy_prod,
                install_cancel_handler,
            };
            let ip = validate_target_host(&ip)?;
                                                                                                      
                                                                                                   
                                                                                                     
                                                                               
            use orchard::deploy::profile::{
                PROD_NOTED_KEYS, ip_cross_check, noted_keys_present, pick, require_present,
            };
            let profile = profile.map(|p| load_profile(&p)).transpose()?;
            let prof = profile.as_ref();
            ip_cross_check(&ip, prof.and_then(|p| p.ip.as_deref()))?;
                                                                                                     
                                                                                                  
            if let Some(p) = prof {
                let ignored = noted_keys_present(p, PROD_NOTED_KEYS);
                if !ignored.is_empty() {
                    println!(
                        "note: the profile's key(s) [{}] are not consumed by `prod` — ignored here.",
                        ignored.join(", ")
                    );
                }
            }
            let mut profile_sourced: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            if pubkey.is_none() && prof.and_then(|p| p.operator_pubkey.as_ref()).is_some() {
                profile_sourced.insert("operator_pubkey".into());
            }
            let pubkey_merged = pick(pubkey, prof.and_then(|p| p.operator_pubkey.clone()), None);
            let pubkey = require_present(
                "operator pubkey",
                "--pubkey",
                "operator_pubkey",
                pubkey_merged.as_ref(),
            )?
            .clone();
            let ssh_identity_merged = pick(
                ssh_identity,
                prof.and_then(|p| p.ssh_identity.clone()),
                None,
            );
            let ssh_identity = require_present(
                "ssh identity",
                "--ssh-identity",
                "ssh_identity",
                ssh_identity_merged.as_ref(),
            )?
            .clone();
            if port.is_none() && prof.and_then(|p| p.port).is_some() {
                profile_sourced.insert("port".into());
            }
            let port = pick(port, prof.and_then(|p| p.port), None).unwrap_or(22);
            let out_dir = pick(out_dir, prof.and_then(|p| p.out_dir.clone()), None)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            let domain = pick(domain, prof.and_then(|p| p.domain.clone()), None);
            let net = pick(net, prof.and_then(|p| p.net.clone()), None);
            let keys_dir = pick(keys_dir, prof.and_then(|p| p.keys_dir.clone()), None);
            let box_login_identity = pick(
                box_login_identity,
                prof.and_then(|p| p.box_login_identity.clone()),
                None,
            );
            let host_fingerprint = pick(
                host_fingerprint,
                prof.and_then(|p| p.host_fingerprint.clone()),
                None,
            );
            let runtime_hostkey_fingerprint = pick(
                runtime_hostkey_fingerprint,
                prof.and_then(|p| p.runtime_hostkey_fingerprint.clone()),
                None,
            );
            let recovery_pubkey = pick(
                recovery_pubkey,
                prof.and_then(|p| p.recovery_pubkey.clone()),
                None,
            );
                                                                                                
            let container_image = pick(
                container_image,
                prof.and_then(|p| p.container_image.clone()),
                Some("recipes-imgbuild:dev".to_string()),
            )
            .unwrap_or_default();
                                                                                    
            install_cancel_handler();
                                                                
            let _lock = acquire_deploy_lock(&std::path::PathBuf::from(DEPLOY_LOCK_DIR), &ip)?;
                                                                                            
                                                                                             
                                                                                              
                                                                                         
            let artifact_root_pin = orchard::deploy::artifact_verify::read_root_pin(
                &match keys_dir.clone() {
                    Some(d) => d,
                    None => default_keys_dir()?,
                },
                artifact_pin,
            )?;
                                                                                                
            let image = match image {
                Some(p) => p,
                None => {
                                                                                                      
                                                                                                     
                                                                                                     
                                                                                                 
                                                                                                    
                    let firmware = match prof.and_then(|p| p.firmware.clone()) {
                        Some(s) => orchard::cli::parse_firmware(&s)
                            .map_err(|e| format!("profile `firmware`: {e}"))?,
                        None => orchard::deploy::build_image::Firmware::Seabios,
                    };
                                                                                      
                                                                                                
                                                                              
                    let domain = orchard::deploy::profile::require_present(
                        "deployment domain",
                        "--domain",
                        "domain",
                        domain.as_ref(),
                    )
                    .map_err(|e| {
                        format!("{e}; or pass --image <prebuilt .img> to skip the inline build")
                    })?
                    .clone();
                                                                                                  
                    refuse_stale_weights_env()?;
                    let ctx = orchard::deploy::context::resolve_context(&ctx_flags, prof)?;
                    let root = ctx.repo_root.to_path_buf();
                    let kernel_src = match ksrc {
                        Some(p) => p,
                        None => default_kernel_xz(&root)?,
                    };
                    let syslinux_src = match syslinux_src {
                        Some(p) => p,
                        None => default_syslinux_src(&root)?,
                    };
                    let opts = BuildImageOpts {
                        keys_dir: match keys_dir {
                            Some(d) => d,
                            None => default_keys_dir()?,
                        },
                        repo_root: root,
                        artifact_store: ctx.artifact_store.into(),
                        kernel_src,
                        syslinux_src,
                        out_dir,
                        domain,
                        container_image,
                        allow_dirty,
                        recovery_pubkey,
                        operator_pubkey: Some(pubkey.clone()),
                        firmware,
                        net,
                        sb_required: false,
                        manifest_path: None,
                                                                                                   
                                                                                                          
                                                                                                  
                        image_version: 0,
                        runtime_weights: false,
                        dha_weights_gguf: None,
                        dha_mmproj_gguf: None,
                    };
                    let out = build_image(&opts)?;
                    println!("deploy prod: built {}", out.outputs.img.display());
                                                                                   
                                                                         
                                                                                     
                                                                                  
                                                                           
                    report_artifact_signing(
                        &opts.repo_root,
                        &opts.keys_dir,
                        &out.outputs.img,
                        &out.outputs.vmlinuz,
                        &out.outputs.initramfs,
                    )?;
                    out.outputs.img
                }
            };
                                                                                               
                                                                                                 
                                                                                            
            {
                use orchard::deploy::artifact_verify::preflight_verify_triple;
                let vmlinuz = image.with_extension("vmlinuz");
                let initramfs = image.with_extension("initramfs");
                let msg = preflight_verify_triple(
                    artifact_root_pin.as_ref(),
                    &image,
                    &vmlinuz,
                    &initramfs,
                )
                .map_err(|e| format!("deploy prod artifact preflight: {e}"))?;
                println!("deploy prod artifact preflight: {msg}");
            }
                                                                                       
            let box_login_identity = match box_login_identity {
                Some(p) => p,
                None => {
                    let p = pubkey.with_extension("");
                    if !p.is_file() {
                        return Err(format!(
                            "--box-login-identity not given and the conventional private half \
                             {} does not exist",
                            p.display()
                        )
                        .into());
                    }
                    p
                }
            };
                                                                                   
            let workdir = tempfile::Builder::new().prefix("recipes-prod-").tempdir()?;
            let provisioning_known_hosts = match &known_hosts {
                Some(p) => p.clone(),
                None => workdir.path().join("known_hosts_provisioning"),
            };
            let mut ops = ProcessOps {
                ip: ip.clone(),
                ssh_port: port,
                ssh_identity,
                box_login_identity,
                                                                                                
                        
                provisioning_user: pick(
                    provisioning_user,
                    prof.and_then(|p| p.provisioning_user.clone()),
                    None,
                )
                .unwrap_or_else(|| {
                    orchard::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER.to_string()
                }),
                provisioning_known_hosts,
                reconnect_known_hosts: workdir.path().join("known_hosts_box"),
                step_started: None,
            };
            deploy_prod(
                &mut ops,
                DeployProdOpts {
                    ip,
                    pubkey,
                    image,
                    host_fingerprint,
                    known_hosts,
                    runtime_hostkey_fingerprint,
                    image_stage_dir,
                    wipe_confirmed: WipeConfirmed::from_flag(wipe_confirmed),
                    reconnect_timeout_secs,
                    restore_from,
                    restore_min_ctr,
                    artifact_pin: artifact_root_pin,
                    profile_sourced,
                    reclaim_tail,
                    reclaim_reboot_timeout_secs: reclaim_timeout_secs,
                },
            )?;
            Ok(())
        }
        OrchardCmd::ReclaimTail {
            provisioning_user,
            ip,
            image,
            ssh_identity,
            host_fingerprint,
            port,
            confirmed,
            reclaim_timeout_secs,
        } => {
            use orchard::deploy::prod::validate_target_host;
            use orchard::deploy::prod_orchestrate::{
                DEPLOY_LOCK_DIR, ProcessOps, acquire_deploy_lock, install_cancel_handler,
            };
            use orchard::deploy::reclaim::ceremony::{StandaloneOpts, reclaim_tail_standalone};
            let ip = validate_target_host(&ip)?;
            if !confirmed {
                return Err(
                    orchard::deploy::reclaim::consent::RECLAIM_STANDALONE_PRECONFIRM.into(),
                );
            }
            install_cancel_handler();
                                                                                  
            let _lock = acquire_deploy_lock(&std::path::PathBuf::from(DEPLOY_LOCK_DIR), &ip)?;
            let workdir = tempfile::Builder::new()
                .prefix("recipes-reclaim-")
                .tempdir()?;
            let mut ops = ProcessOps {
                ip: ip.clone(),
                ssh_port: port,
                ssh_identity: ssh_identity.clone(),
                                                                                              
                box_login_identity: ssh_identity,
                provisioning_user: provisioning_user.unwrap_or_else(|| {
                    orchard::deploy::prod_orchestrate::DEFAULT_PROVISIONING_USER.to_string()
                }),
                provisioning_known_hosts: workdir.path().join("known_hosts_provisioning"),
                reconnect_known_hosts: workdir.path().join("known_hosts_box"),
                step_started: None,
            };
            reclaim_tail_standalone(
                &mut ops,
                &StandaloneOpts {
                    ip,
                    image,
                    host_fingerprint,
                    timeout_secs: reclaim_timeout_secs,
                },
            )?;
            Ok(())
        }
        OrchardCmd::RefreshApkLock { container_image } => {
            use orchard::deploy::refresh_apk_lock::{RefreshApkLockOpts, refresh_apk_lock};
            let opts = RefreshApkLockOpts {
                repo_root: resolved_root(&ctx_flags)?,
                container_image,
            };
            let path = refresh_apk_lock(&opts)?;
            println!("deploy refresh-apk-lock: regenerated {}", path.display());
            Ok(())
        }
        OrchardCmd::SyncPins { check } => {
            use orchard::deploy::sync_pins::{SyncPinsOpts, sync_pins};
            let opts = SyncPinsOpts {
                repo_root: resolved_root(&ctx_flags)?,
                check,
            };
            println!("{}", sync_pins(&opts)?);
            Ok(())
        }
        OrchardCmd::Vendor {
            store,
            porcelain: _,
        } => {
                                                                                                 
                                                                                       
            let flags = ctx_flags
                .clone()
                .with_store_override("vendor --store", store)?;
            let ctx = orchard::deploy::context::resolve_context(&flags, None)?;
            println!(
                "{}",
                orchard::deploy::vendor_cmd::vendor(&ctx.repo_root, &ctx.artifact_store)?
            );
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::vendor_next_steps(),
                )
            );
            Ok(())
        }
        OrchardCmd::Admit {
            box_profile,
            repo_form_dir,
        } => run_admit(box_profile, repo_form_dir, &ctx_flags),
        OrchardCmd::Prime {
            porcelain: _,
            kbuild_dir,
            syslinux_dir,
        } => {
            use recipes_image_builder::pins::Pins;
            use recipes_image_builder::sources::{
                self, KERNEL_TAR_CEILING, KERNEL_XZ_CAP, SYSLINUX_TAR_CEILING, SYSLINUX_XZ_CAP,
            };
                                                                                               
                                                                             
            let root = resolved_root(&ctx_flags)?;
            let pins = Pins::load(&root)?;
            std::fs::create_dir_all(&kbuild_dir)?;
            std::fs::create_dir_all(&syslinux_dir)?;

            let kernel_staged = pins.kernel_tarball_path(&kbuild_dir);
            sources::prime_source(
                &recipes_image_builder::HttpFetcher::with_body_cap(KERNEL_XZ_CAP),
                &sources::kernel_xz_url(&pins.kernel.version)?,
                &pins.kernel.sha256,
                KERNEL_TAR_CEILING,
                &kernel_staged,
            )?;
            println!(
                "prime: kernel staged at {} (sha256 {})",
                kernel_staged.display(),
                pins.kernel.sha256
            );

            let syslinux_staged = pins.syslinux_tarball_path(&syslinux_dir);
            sources::prime_source(
                &recipes_image_builder::HttpFetcher::with_body_cap(SYSLINUX_XZ_CAP),
                &sources::syslinux_xz_url(&pins.syslinux.version)?,
                &pins.syslinux.sha256,
                SYSLINUX_TAR_CEILING,
                &syslinux_staged,
            )?;
            println!(
                "prime: syslinux staged at {} (sha256 {})",
                syslinux_staged.display(),
                pins.syslinux.sha256
            );
            print!(
                "{}",
                orchard::deploy::epilogue::next_steps(
                    &orchard::deploy::epilogue::prime_next_steps(),
                )
            );
            Ok(())
        }
        OrchardCmd::Market { sub } => match sub {
            MarketSub::Verify {
                certs,
                all,
                allow_missing,
                cert_presence,
            } => {
                use orchard::deploy::market::{VerifyOpts, cert_presence_dry_run, verify};
                let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                let opts = VerifyOpts {
                    repo_root: ctx.repo_root.into(),
                    repo_manifest: ctx.repo_manifest.into(),
                    artifact_store: ctx.artifact_store.into(),
                    certs,
                    all,
                    allow_missing,
                };
                let out = if cert_presence {
                    cert_presence_dry_run(&opts)?
                } else {
                    verify(&opts)?
                };
                println!("{out}");
                Ok(())
            }
            MarketSub::Outdated {
                exit_drift,
                all_packages,
            } => {
                use orchard::deploy::market::{
                    ExitDrift, OutdatedOpts, outdated, outdated_exit_code,
                };
                let when = match exit_drift.as_deref() {
                    None => ExitDrift::Never,
                    Some("gone") => ExitDrift::OnGone,
                    Some("any") => ExitDrift::OnAny,
                    Some(other) => {
                        return Err(
                            format!("--exit-drift takes `gone` or `any`, got `{other}`").into()
                        );
                    }
                };
                let report = outdated(&OutdatedOpts {
                    repo_root: resolved_root(&ctx_flags)?,
                    all_packages,
                    fetch: Box::new(recipes_image_builder::HttpFetcher::new()),
                })?;
                println!("{}", report.text);
                let code = outdated_exit_code(when, &report);
                if code != 0 {
                    use std::io::Write as _;
                    std::io::stdout().flush().ok();
                                                                                                        
                    #[allow(clippy::disallowed_methods)]
                    std::process::exit(code);
                }
                Ok(())
            }
            MarketSub::Upgrade {
                porcelain: _,
                source,
                binary,
                config,
                apks,
                kernel,
                rust,
                all,
                dry_run,
                container_image,
                build_dir,
                commit,
                no_commit,
            } => {
                use orchard::deploy::market::{VerifyOpts, verify};
                use orchard::deploy::market_exec::{ShellStepExec, Stage, execute, resolve_layout};
                use orchard::deploy::market_upgrade::{UpgradeError, plan, render_plan};
                use recipes_image_builder::pin_manifest::PinManifest;
                use recipes_image_builder::repo_manifest::RepoManifest;
                let target = parse_upgrade_target(source, binary, config, apks, kernel, rust, all)?;
                let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                let root = ctx.repo_root.to_path_buf();
                let consume = PinManifest::load(&root.join("consume-pins.toml"))?;
                let manifest = RepoManifest::load(&ctx.repo_manifest)?;
                let steps = plan(&target, &manifest, &consume)?;
                println!("{}", render_plan(&target, &steps));
                if dry_run {
                                                                                                 
                                                                                                 
                                                              
                    if matches!(
                        target,
                        orchard::deploy::market_upgrade::Target::Apks
                            | orchard::deploy::market_upgrade::Target::All
                    ) {
                        println!(
                            "{}",
                            orchard::deploy::market::apks_dry_run_preview(
                                &root,
                                &recipes_image_builder::HttpFetcher::new(),
                            )
                        );
                    }
                    println!("market upgrade: --dry-run (nothing staged, nothing swapped)");
                    return Ok(());
                }
                                                                                                   
                                                                                             
                                                                                             
                                                                                                 
                                                  
                let container_image = match container_image {
                    some @ Some(_) => some,
                    None if matches!(
                        target,
                        orchard::deploy::market_upgrade::Target::Apks
                            | orchard::deploy::market_upgrade::Target::All
                    ) =>
                    {
                        Some(orchard::deploy::market::default_apks_container_image(
                            &recipes_image_builder::pins::Pins::load(&root)?,
                        ))
                    }
                    None => None,
                };
                                                                                                         
                                                                                                       
                let store = ctx.artifact_store.to_path_buf();
                let layout = resolve_layout(
                    &manifest,
                    root.clone(),
                    store,
                    ctx.repo_manifest.to_path_buf(),
                );
                                                                                                
                                                                                          
                let kernel_fetcher = recipes_image_builder::HttpFetcher::with_body_cap(
                    orchard::deploy::kernel_bump::KERNEL_XZ_CAP,
                );
                                                                                                      
                                                                                                        
                                                                          
                let rust_fetcher = recipes_image_builder::HttpFetcher::with_body_cap(
                    orchard::deploy::rust_bump::RUST_MANIFEST_CAP,
                );
                let container_builder = orchard::deploy::market_exec::DockerContainerBuilder {
                    source_date_epoch: 0,
                };
                let mut exec = ShellStepExec {
                    layout: &layout,
                    manifest: &manifest,
                    consume: &consume,
                    apk_container_image: container_image,
                    build_dir,
                    kernel_fetcher: Some(&kernel_fetcher),
                    rust_fetcher: Some(&rust_fetcher),
                    container_builder: Some(&container_builder),
                    rebuilt_digest: None,
                };
                let verify_staged = |stage: &Stage| {
                    let opts = VerifyOpts {
                                                                                                
                                                                                                
                                                                                  
                        repo_root: stage.verify_root().to_path_buf(),
                        repo_manifest: orchard::deploy::context::manifest_default(
                            stage.verify_root(),
                        ),
                        artifact_store: ctx.artifact_store.to_path_buf(),
                        certs: false,
                        all: false,
                        allow_missing: vec![],
                    };
                    verify(&opts)
                        .map(|_| ())
                        .map_err(|e| UpgradeError::StagedVerify(e.to_string()))
                };
                let report = execute(&steps, &layout, &mut exec, &verify_staged)?;
                                                                                         
                                                                                                 
                                                                                               
                                                    
                use orchard::deploy::git_commit::{
                    CommitOpts, Consent, EditOutcome, GitCommit as _, ShellGit, UpgradeFlags,
                    compose_message, consent_from, edit_message_with, plan_commit,
                    render_ready_command,
                };
                let cplan = plan_commit(&report.swapped, &layout);
                println!(
                    "market upgrade: staged + verified + SWAPPED {} path(s):",
                    report.swapped.len()
                );
                for p in &cplan.orchard {
                    println!("  [orchard]  {}", p.display());
                }
                for (name, (_, paths)) in &cplan.siblings {
                    for p in paths {
                        println!("  [{name}]  {}", p.display());
                    }
                }
                for p in &cplan.excluded {
                    println!(
                        "  [store]    {}  (store bytes, bound by their pins — not a git target)",
                        p.display()
                    );
                }

                                                                                                
                                                                                      
                                                                      
                use orchard::deploy::git_commit::diff_stat;
                if let Some(stat) = diff_stat(&root, &cplan.orchard) {
                    println!("--- diff --stat (orchard) ---");
                    println!("{stat}");
                }
                for (name, (repo_root_path, paths)) in &cplan.siblings {
                    if let Some(stat) = diff_stat(repo_root_path, paths) {
                        println!("--- diff --stat ({name}) ---");
                        println!("{stat}");
                    }
                }

                let mut message = compose_message(&target, &root, &cplan.orchard);
                println!("--- composed commit message ---");
                println!("{message}");
                println!("-------------------------------");

                let is_tty = {
                    use std::io::IsTerminal as _;
                    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
                };
                let flags = UpgradeFlags {
                    commit,
                    no_commit,
                    dry_run,
                };
                let mut consent = consent_from(&flags, is_tty, || {
                    use std::io::Write as _;
                    print!(
                        "commit the orchard paths? [y = commit / e = edit the message / N = print the command] "
                    );
                    std::io::stdout().flush().ok();
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).ok();
                    line.trim().chars().next().unwrap_or('n')
                });

                                                                                               
                                                                                                 
                                             
                if consent == Consent::EditThenCommit {
                    match edit_message_with(std::env::var_os("EDITOR").as_deref(), &message) {
                        EditOutcome::Edited(edited) => {
                            message = edited;
                            consent = Consent::Commit;
                        }
                        EditOutcome::Aborted => {
                            println!(
                                "market upgrade: edit aborted (no $EDITOR, editor failed, or empty message) — not committing."
                            );
                            consent = Consent::PrintOnly;
                        }
                    }
                }

                                                                                                 
                                            
                let msgfile = {
                    use std::io::Write as _;
                    let mut f = tempfile::NamedTempFile::new()?;
                    f.write_all(message.as_bytes())?;
                    f.flush()?;
                    let (_, path) = f.keep()?;
                    path
                };

                match consent {
                    Consent::Commit => {
                        if cplan.orchard.is_empty() {
                            println!(
                                "market upgrade: nothing to commit in orchard (no orchard-repo paths in the swap)."
                            );
                        } else {
                            ShellGit
                                .commit(&root, &cplan.orchard, &message, CommitOpts::default())
                                .map_err(|e| -> Box<dyn std::error::Error> {
                                                                                                  
                                                                                        
                                    format!(
                                        "{e}\nthe re-pin itself is swapped + verified; commit by hand:\n  {}",
                                        render_ready_command(&root, &msgfile, &cplan.orchard)
                                    )
                                    .into()
                                })?;
                            println!(
                                "market upgrade: committed {} path(s) in orchard.",
                                cplan.orchard.len()
                            );
                        }
                    }
                    Consent::PrintOnly | Consent::EditThenCommit => {
                        if !cplan.orchard.is_empty() {
                            println!(
                                "market upgrade: NOT committed (no consent given) — the re-pin is done; commit when ready:"
                            );
                            println!(
                                "  {}",
                                render_ready_command(&root, &msgfile, &cplan.orchard)
                            );
                        }
                    }
                }
                if !cplan.siblings.is_empty() {
                    println!(
                        "sibling repos await their own commit (market never commits across repos):"
                    );
                    for (name, (repo_root_path, paths)) in &cplan.siblings {
                        println!(
                            "  [{name}] {}",
                            render_ready_command(repo_root_path, &msgfile, paths)
                        );
                    }
                }
                Ok(())
            }
            MarketSub::Store { sub } => match sub {
                StoreSub::Status { all, full } => {
                    use orchard::deploy::store_admin::{render_status, scan_store};
                    use recipes_image_builder::repo_manifest::RepoManifest;
                    let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                    let root = ctx.repo_root;
                    let manifest = RepoManifest::load(&ctx.repo_manifest)?;
                    let store = ctx.artifact_store;
                    let scan = scan_store(&store, &manifest, &root)?;
                    println!("{}", render_status(&scan, &store, all, full));
                    Ok(())
                }
                StoreSub::Prune { delete, full } => {
                    use orchard::deploy::store_admin::{prune, render_prune, scan_store};
                    use recipes_image_builder::repo_manifest::RepoManifest;
                    let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                    let root = ctx.repo_root;
                    let manifest = RepoManifest::load(&ctx.repo_manifest)?;
                    let store = ctx.artifact_store;
                    let scan = scan_store(&store, &manifest, &root)?;
                    let report = prune(&store, &scan, delete)?;
                    print!("{}", render_prune(&report, delete, &store, full));
                    if report.refused.is_some() {
                        use std::io::Write as _;
                        std::io::stdout().flush().ok();
                                                                                                   
                        #[allow(clippy::disallowed_methods)]
                        std::process::exit(1);
                    }
                    Ok(())
                }
                StoreSub::Migrate => {
                    use orchard::deploy::store_admin::{migrate, render_migrate};
                    let ctx = orchard::deploy::context::resolve_context(&ctx_flags, None)?;
                    let store = ctx.artifact_store;
                    let report = migrate(&store)?;
                    print!("{}", render_migrate(&report, &store));
                    Ok(())
                }
            },
        },
    }
}

/// Resolve the operator's `market upgrade` flags into EXACTLY one target (0 or >1 is a usage error).
fn parse_upgrade_target(
    source: Option<String>,
    binary: Option<String>,
    config: Option<String>,
    apks: bool,
    kernel: Option<String>,
    rust: Option<String>,
    all: bool,
) -> Result<orchard::deploy::market_upgrade::Target, Box<dyn std::error::Error>> {
    use orchard::deploy::market_upgrade::Target;
    let mut chosen: Vec<Target> = Vec::new();
    if let Some(s) = source {
        chosen.push(Target::Source(s));
    }
    if let Some(b) = binary {
                                                                                                             
                                                                                                        
                                                                     
        chosen.push(Target::Binary(b));
    }
    if let Some(c) = config {
                                                                                                           
                                                                                 
        chosen.push(Target::Config(c));
    }
    if apks {
        chosen.push(Target::Apks);
    }
    if let Some(k) = kernel {
        chosen.push(Target::Kernel(k));
    }
    if let Some(r) = rust {
                                                                                                        
                                                                                                 
                                                                                                  
        chosen.push(Target::Rust(r));
    }
    if all {
                                                                                                 
        chosen.push(Target::All);
    }
    match chosen.len() {
        1 => Ok(chosen.into_iter().next().unwrap()),
        0 => Err("market upgrade: pick exactly one target \
                  (--source/--binary/--config/--apks/--kernel/--rust/--all)"
            .into()),
        n => Err(format!("market upgrade: pick exactly ONE target, got {n}").into()),
    }
}

/// Resolve `<root>/crates/image-builder/pinned-cert-fingerprints.toml` under the C5-RESOLVED repo
                                                                                           
/// CWD: the pin WRITERS (generate-keys, update-cert-fingerprints) and the build-side READERS must
/// name the SAME checkout, and `--print-context` must not report a `repo_root` these verbs then
/// ignore. `resolved_root`'s default IS the CWD, so an operator running from the repo root with no
/// `--repo-root` sees the historical behaviour; `--repo-root B` now reaches these verbs.
fn repo_fingerprints_path(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let crate_dir = root.join("crates/image-builder");
    if !crate_dir.is_dir() {
        return Err(format!(
            "run `deploy generate-keys` against a recipes repo root \
             ({}/crates/image-builder/ not found)",
            root.display()
        )
        .into());
    }
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).map_err(|_| {
        format!(
            "the resolved repo root {} has no Cargo.toml",
            root.display()
        )
    })?;
    if !cargo.contains("[workspace]") {
        return Err(format!(
            "{}/Cargo.toml is not the recipes workspace root",
            root.display()
        )
        .into());
    }
    Ok(crate_dir.join("pinned-cert-fingerprints.toml"))
}

/// The committed Secure Boot db-cert fingerprint pin (the enrollment anchor; SB-loader
                                                                               
fn repo_sb_db_fingerprint_path(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let crate_dir = root.join("crates/image-builder");
    if !crate_dir.is_dir() {
        return Err(format!(
            "run `deploy generate-keys --secure-boot`/`deploy sign-sb` against a recipes \
             repo root ({}/crates/image-builder/ not found)",
            root.display()
        )
        .into());
    }
    Ok(crate_dir.join("pinned-secure-boot-db.toml"))
}

/// Resolve the recipes repo root for `deploy build` (pins, trust anchors, build-kernel.sh live
                                                                                      
fn repo_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !PathBuf::from("crates/image-builder").is_dir() {
        return Err(
            "run `deploy build` from the recipes repo root (./crates/image-builder/ not found)"
                .into(),
        );
    }
                                                                                        
                                                                                         
    #[allow(clippy::disallowed_methods)]
    let cwd = std::env::current_dir()?;
    Ok(cwd)
}

                                                                                       
/// context-consuming pin verbs (prime, sync-pins, market outdated, refresh-apk-lock), so
/// `--print-context` tells the truth for them and a worktree outside `fruit-ecosystem/` resolves.
/// Distinct from the legacy CWD-contract `repo_root()`, which the build/deploy verbs that operate
/// on the checkout you invoke from still use.
fn resolved_root(
    ctx_flags: &orchard::deploy::context::ContextFlags,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(orchard::deploy::context::resolve_context(ctx_flags, None)?
        .repo_root
        .into())
}

                                                                                            
/// sibling: wires the id to a producer, so a skew exits refusal-with-cure at the chokepoint, not
/// failed). Any other parse error stays a plain string (an operator-fixable failure).
fn load_profile(
    path: &std::path::Path,
) -> Result<orchard::deploy::profile::Profile, Box<dyn std::error::Error>> {
    use orchard::ceremony::refusal::{Refusal, RefusalId};
    use orchard::deploy::profile::SCHEMA_SKEW_PREFIX;
    orchard::deploy::profile::load(path).map_err(|e| -> Box<dyn std::error::Error> {
        match e.strip_prefix(SCHEMA_SKEW_PREFIX) {
            Some(detail) => Box::new(Refusal::new(
                RefusalId::ProfileSchemaSkew,
                detail.to_string(),
            )),
            None => e.into(),
        }
    })
}

/// `orchard admit` (§1.5): ratify a box's declared space. Measure each named checkout's git
/// configuration (every scope-qualified key; the value at the program-valued keys git executes
/// inside the gate's commands), show the diff, write after an explicit typed authorize (§1.4).
/// Never runs a ceremony.
fn run_admit(
    box_profile: orchard::ceremony::Utf8PathBuf,
    repo_form_dir: Option<orchard::ceremony::Utf8PathBuf>,
    ctx_flags: &orchard::deploy::context::ContextFlags,
) -> Result<(), Box<dyn std::error::Error>> {
    use orchard::ceremony::admission::{RunInvocation, read_ratified};
    use orchard::ceremony::gate_commit::declared_space_body;
    use std::collections::BTreeSet;
    let prof = load_profile(box_profile.as_path())?;
    let ctx = orchard::deploy::context::resolve_context(ctx_flags, Some(&prof))?;
    let inv = RunInvocation {
        profile_path: box_profile,
        repo_form_dir,
        ..Default::default()
    };

    let mut checkouts: Vec<(&str, std::path::PathBuf)> =
        vec![("executing", ctx.repo_root.to_path_buf())];
    match orchard::ceremony::runner::tenant_repo_root(&ctx, &prof) {
        Ok(root) => checkouts.push(("tenant-repo", root)),
        Err(_) => emit_stdout(
            "admit: no tenant-repo sibling resolved from the repo-manifest; ratifying the \
             executing checkout only\n",
        ),
    }

                                                 
    let mut plans: Vec<(&str, orchard::ceremony::Utf8PathBuf, String, bool)> = Vec::new();
    let mut any_delta = false;
    for (checkout, root) in &checkouts {
        let body = declared_space_body(root)
            .map_err(|e| format!("cannot measure the {checkout} checkout's declared space: {e}"))?;
        let file = inv.ratified_file(&ctx.repo_root, checkout);
                                                                           
        let ratified_body = match read_ratified(&file) {
            Ok(body) => body,
            Err(e) => {
                return Err(format!(
                    "admit: cannot read the ratified file for {checkout}: {e}; nothing written"
                )
                .into());
            }
        };
        let ratified = ratified_body.as_deref().unwrap_or("");
        let r: BTreeSet<&str> = ratified.lines().filter(|l| !l.is_empty()).collect();
        let m: BTreeSet<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        let added: Vec<&str> = m.difference(&r).copied().collect();
        let removed: Vec<&str> = r.difference(&m).copied().collect();
        let has_delta = !added.is_empty() || !removed.is_empty();
        any_delta |= has_delta;
        match ratified_body {
            None => emit_stdout(&format!(
                "declared space for {checkout} ({}): no ratified file, first ratification\n",
                root.display()
            )),
            Some(_) => emit_stdout(&format!(
                "declared space for {checkout} ({}):\n",
                root.display()
            )),
        }
        if has_delta {
            for l in &added {
                emit_stdout(&format!("  +{l}\n"));
            }
            for l in &removed {
                emit_stdout(&format!("  -{l}\n"));
            }
        } else {
            emit_stdout("  (no change)\n");
        }
        plans.push((checkout, file, body, has_delta));
    }

    if !any_delta {
        emit_stdout(
            "admit: every named checkout already matches its ratified declared space; nothing \
             written\n",
        );
        return Ok(());
    }

    use std::io::Write as _;
    print!("type `admit` to write the shown declared space, anything else to abort: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    if line.trim() != "admit" {
        emit_stdout("admit: aborted; nothing written\n");
        return Ok(());
    }

    for (_checkout, file, body, has_delta) in &plans {
        if !has_delta {
            continue;
        }
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = file.with_extension("keys.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, file.as_path())?;
        emit_stdout(&format!("admit: wrote {}\n", file.display()));
    }
    Ok(())
}

/// The mapping site from ceremony conclusion to process code. `main()` itself stays an OPEN
/// `ExitCode`-typed surface by std's entry contract — the type cannot close it (test-check
                                                                                         
/// byte-exactly by `enforcement_config::main_body_stays_the_frozen_concluded_map`; any edit
/// reddens that arm and is re-frozen consciously. The body maps a `Concluded` (the conclusion
/// witness, ceremony/conclude.rs: producible only by that module's two producers, which render
/// stderr and emit the records the derived choice carries) through the frozen class→code table,
/// once.
fn main() -> std::process::ExitCode {
    let concluded = ceremony_main();
    std::process::ExitCode::from(
        u8::try_from(orchard::ceremony::porcelain::exit_code(concluded.class())).unwrap_or(1),
    )
}

fn ceremony_main() -> orchard::ceremony::conclude::Concluded {
    use orchard::ceremony::conclude::{conclude, porcelain_of};
                                                                                    
                                                                                                   
                                                                                                
                                                                                                  
                                                                                                  
                                                                                         
                                                                                                   
                                                                                                    
                                                                                              
                                                                                                   
                                                                                                   
                                                                                                     
                                                                                                    
                                                                                                     
                                                  
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let broken_pipe = info
            .location()
            .map(|l| l.file().ends_with("stdio.rs"))
            .unwrap_or(false)
            && info
                .payload()
                .downcast_ref::<String>()
                .map(|s| s.contains("Broken pipe"))
                .unwrap_or(false);
        if broken_pipe {
            #[allow(clippy::disallowed_methods)]
            std::process::exit(141);
        }
        default_hook(info);
    }));
                                                                                     
                                                                                     
                                                                                
                                                                                     
                                                                               
                                                                                   
                                                
    if let Err(e) = orchard::deploy::dumpable::set_process_non_dumpable() {
        orchard::ceremony::emit_stderr(&format!(
            "warning: could not mark the process non-dumpable (PR_SET_DUMPABLE): {e} — \
             continuing (host paths hold no seed material)\n"
        ));
    }
                                                                                               
                                                                                             
                                                                                                   
                                                                    
                                              
    #[allow(clippy::disallowed_methods)]
    let cli = match orchard::ceremony::conclude::parse_or_usage() {
        Ok(cli) => cli,
        Err(concluded) => return concluded,
    };
                                                                                                 
                                                                                                  
                                                                                                
                                                                                                 
                                                      
    #[allow(clippy::disallowed_methods)]
    let choice = porcelain_of(&cli.command, cli.print_context);
    let ctx_flags = orchard::deploy::context::ContextFlags {
        repo_root: cli.repo_root,
        artifact_store: cli.artifact_store,
        repo_manifest: cli.repo_manifest,
        context_file: cli.context,
    };
    let print_context = cli.print_context;
    let command = cli.command;
    let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                                                                                               
                                                                                 
        if print_context {
            let flags = fold_verb_context_overrides(ctx_flags, &command)?;
            let profile = profile_path_of(&command).map(load_profile).transpose()?;
            let ctx = orchard::deploy::context::resolve_context(&flags, profile.as_ref())?;
            emit_stdout(&orchard::deploy::context::render_context(&ctx));
            return Ok(());
        }
                                                                                        
                                                                                                   
                                                                                             
                                                                                                  
                                                                                               
                                                                                                    
                                                       
        let ceremony_lock = orchard::ceremony::lock::acquire_for(&command)?;
        run_deploy(command, ctx_flags, ceremony_lock.as_ref())
    })();
                                                     
                                                                                                 
                                                                                                  
                                                                                                 
                                                                                            
                                                                                                
                                                                                                  
                                                             
    #[allow(clippy::disallowed_methods)]
    conclude(choice, outcome)
}

/// The operator-facing [`Interviewer`]: prompts on stdout, reads a line from stdin. Both go
/// through the EPIPE-safe emitter, so a closed consumer ends the interview rather than panicking
/// it.
struct TerminalInterviewer;

impl orchard::ceremony::interview::Interviewer for TerminalInterviewer {
    fn ask(&mut self, prompt: &str) -> Option<String> {
        emit_stdout(prompt);
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
                                                                   
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
        }
    }

    fn say(&mut self, text: &str) {
        emit_stdout(text);
    }
}

/// The verb's profile path, when its variant consults a profile tier in the context chain.
                                                                                        
/// and `guide` when they landed with a POSITIONAL profile, so `--print-context run/guide` reported
                                                                                    
/// (`Option`); `run`/`guide` the positional. A new profile-carrying verb is now a compile error
/// until it decides here.
fn profile_path_of(cmd: &OrchardCmd) -> Option<&std::path::Path> {
    match cmd {
        OrchardCmd::Build { profile, .. } | OrchardCmd::Prod { profile, .. } => profile.as_deref(),
        OrchardCmd::Guide { profile, .. } | OrchardCmd::Run { profile, .. } => {
            Some(profile.as_path())
        }
        OrchardCmd::DeriveRescueOffline { .. }
        | OrchardCmd::GenerateKeys { .. }
        | OrchardCmd::Redelegate { .. }
        | OrchardCmd::Update { .. }
        | OrchardCmd::DeployModel { .. }
        | OrchardCmd::Status { .. }
        | OrchardCmd::RotateKey { .. }
        | OrchardCmd::SignBackup { .. }
        | OrchardCmd::SignInContainer { .. }
        | OrchardCmd::SignSb { .. }
        | OrchardCmd::UpdateCertFingerprints { .. }
        | OrchardCmd::RestoreImage { .. }
        | OrchardCmd::BuildInstallerUsb { .. }
        | OrchardCmd::SignInstallerUsb { .. }
        | OrchardCmd::Dryrun { .. }
        | OrchardCmd::Doctor { .. }
        | OrchardCmd::ReclaimTail { .. }
        | OrchardCmd::RefreshApkLock { .. }
        | OrchardCmd::SyncPins { .. }
        | OrchardCmd::Vendor { .. }
        | OrchardCmd::Prime { .. }
        | OrchardCmd::Admit { .. }
        | OrchardCmd::Market { .. } => None,
                                                                                                 
                                                                                      
        #[cfg(feature = "ceremony-seed-unclassified-verb")]
        OrchardCmd::CeremonySeedUnclassified => None,
    }
}

/// Fold verb-local context overrides (today: `vendor --store`) into the flag tier, refusing a
                                                                                       
                                                                                       
/// compile error until it declares its fold here, rather than silently resolving with the flag
/// ignored.
fn fold_verb_context_overrides(
    flags: orchard::deploy::context::ContextFlags,
    cmd: &OrchardCmd,
) -> Result<orchard::deploy::context::ContextFlags, Box<dyn std::error::Error>> {
    match cmd {
        OrchardCmd::Vendor { store, .. } => {
            Ok(flags.with_store_override("vendor --store", store.clone())?)
        }
        OrchardCmd::Guide { .. }
        | OrchardCmd::Run { .. }
        | OrchardCmd::DeriveRescueOffline { .. }
        | OrchardCmd::GenerateKeys { .. }
        | OrchardCmd::Redelegate { .. }
        | OrchardCmd::Update { .. }
        | OrchardCmd::DeployModel { .. }
        | OrchardCmd::Status { .. }
        | OrchardCmd::RotateKey { .. }
        | OrchardCmd::SignBackup { .. }
        | OrchardCmd::SignInContainer { .. }
        | OrchardCmd::SignSb { .. }
        | OrchardCmd::UpdateCertFingerprints { .. }
        | OrchardCmd::Build { .. }
        | OrchardCmd::RestoreImage { .. }
        | OrchardCmd::BuildInstallerUsb { .. }
        | OrchardCmd::SignInstallerUsb { .. }
        | OrchardCmd::Dryrun { .. }
        | OrchardCmd::Doctor { .. }
        | OrchardCmd::Prod { .. }
        | OrchardCmd::ReclaimTail { .. }
        | OrchardCmd::RefreshApkLock { .. }
        | OrchardCmd::SyncPins { .. }
        | OrchardCmd::Prime { .. }
        | OrchardCmd::Admit { .. }
        | OrchardCmd::Market { .. } => Ok(flags),
        #[cfg(feature = "ceremony-seed-unclassified-verb")]
        OrchardCmd::CeremonySeedUnclassified => Ok(flags),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use orchard::cli::Cli;

                                                                                                  
    #[test]
    fn help_shows_the_group_legend() {
        let mut cmd = <Cli as clap::CommandFactory>::command();
        let help = cmd.render_long_help().to_string().to_lowercase();
        for group in ["setup", "build", "verify", "deploy", "maintain"] {
            assert!(help.contains(group), "legend missing {group}: {help}");
        }
    }

    #[test]
    fn doctor_for_boot_gate_parses_with_image() {
                                                                                                     
        let cli = Cli::try_parse_from([
            "orchard",
            "doctor",
            "--for",
            "boot-gate",
            "--image",
            "/tmp/x.img",
        ])
        .expect("`doctor --for boot-gate --image` must parse");
        match cli.command {
            OrchardCmd::Doctor {
                for_verb, image, ..
            } => {
                assert_eq!(for_verb.as_deref(), Some("boot-gate"));
                assert_eq!(image.as_deref(), Some(std::path::Path::new("/tmp/x.img")));
            }
            _ => panic!("expected the Doctor variant"),
        }
    }

    #[test]
    fn doctor_rejects_a_bogus_scope() {
        assert!(
            Cli::try_parse_from(["orchard", "doctor", "--for", "bogus"]).is_err(),
            "an out-of-set --for must fail at parse (fail-closed value_parser)"
        );
    }

    #[test]
    fn status_requires_ssh_identity() {
                                                                                       
        let cli = Cli::try_parse_from([
            "orchard",
            "status",
            "box.example",
            "--ssh-identity",
            "/k/id",
        ])
        .expect("`status <host> --ssh-identity` must parse");
        match cli.command {
            OrchardCmd::Status {
                host,
                ssh_identity,
                port,
                image,
                ..
            } => {
                assert_eq!(host, "box.example");
                assert_eq!(ssh_identity, std::path::PathBuf::from("/k/id"));
                assert_eq!(port, 22);
                assert!(image.is_none());
            }
            _ => panic!("expected the Status variant"),
        }
                                                                             
        assert!(
            Cli::try_parse_from(["orchard", "status", "box.example"]).is_err(),
            "--ssh-identity is REQUIRED (I-6)"
        );
    }

    #[test]
    fn rotate_key_requires_both_identities() {
                                                                                                        
        let cli = Cli::try_parse_from([
            "orchard",
            "rotate-key",
            "box.example",
            "--new-identity",
            "/k/new",
            "--ssh-identity",
            "/k/cur",
        ])
        .expect("both identities parse");
        match cli.command {
            OrchardCmd::RotateKey {
                host,
                new_identity,
                ssh_identity,
                port,
                ..
            } => {
                assert_eq!(host, "box.example");
                assert_eq!(new_identity, std::path::PathBuf::from("/k/new"));
                assert_eq!(ssh_identity, std::path::PathBuf::from("/k/cur"));
                assert_eq!(port, 22);
            }
            _ => panic!("expected the RotateKey variant"),
        }
                                                    
        assert!(
            Cli::try_parse_from([
                "orchard",
                "rotate-key",
                "box.example",
                "--ssh-identity",
                "/k/cur"
            ])
            .is_err(),
            "--new-identity is REQUIRED"
        );
        assert!(
            Cli::try_parse_from([
                "orchard",
                "rotate-key",
                "box.example",
                "--new-identity",
                "/k/new"
            ])
            .is_err(),
            "--ssh-identity is REQUIRED"
        );
    }

    #[test]
    fn prod_with_profile_and_wipe_parses_without_pubkey() {
                                                                                                   
                                                                                                        
        let r = Cli::try_parse_from([
            "orchard",
            "prod",
            "203.0.113.5",
            "--profile",
            "boxes/rezepte.toml",
            "--wipe-confirmed",
        ]);
        assert!(r.is_ok(), "must parse: {:?}", r.err());
    }

    #[test]
    fn prod_without_pubkey_or_profile_still_refuses_at_parse() {
                                                                                                          
        let r = Cli::try_parse_from(["orchard", "prod", "203.0.113.5", "--wipe-confirmed"]);
        assert!(r.is_err(), "no pubkey and no profile must fail at parse");
    }

    #[test]
    fn build_without_domain_or_profile_still_refuses_at_parse() {
        let r = Cli::try_parse_from(["orchard", "build"]);
        assert!(r.is_err(), "no domain and no profile must fail at parse");
    }

    #[test]
    fn build_accepts_the_optional_substrate_cross_check_flag() {
        let cli = Cli::try_parse_from([
            "orchard",
            "build",
            "--domain",
            "ex.com",
            "--substrate",
            "vps-kvm",
        ])
        .expect("build --substrate parses");
        match cli.command {
            OrchardCmd::Build {
                substrate,
                firmware,
                ..
            } => {
                assert_eq!(substrate.as_deref(), Some("vps-kvm"));
                                                                                              
                                                                     
                assert_eq!(firmware, None);
            }
            _ => panic!("expected the Build subcommand"),
        }
                                                                    
        match Cli::try_parse_from(["orchard", "build", "--domain", "ex.com"])
            .unwrap()
            .command
        {
            OrchardCmd::Build { substrate, .. } => assert_eq!(substrate, None),
            _ => panic!("expected the Build subcommand"),
        }
    }

    #[test]
    fn restore_image_parses_db_owner_and_defaults() {
        let cli = Cli::try_parse_from([
            "orchard",
            "restore-image",
            "--data",
            "/b/data-1.tar.gz",
            "--db",
            "/b/db-1.sqlite",
            "--operator-pubkey",
            "/k/op.pub",
            "--db-owner",
            "100:100",
            "--out",
            "/tmp/restore-1.persist.img",
        ])
        .expect("`restore-image` with --db-owner must parse");
        match cli.command {
            OrchardCmd::RestoreImage {
                db_owner,
                root,
                db_target,
                ..
            } => {
                assert_eq!(db_owner, Some((100, 100)));
                assert_eq!(root, "recipes", "default tenant root");
                assert_eq!(db_target, "recipes.db", "default db target");
            }
            _ => panic!("expected the RestoreImage subcommand"),
        }
                                                                                 
        for bad in ["nonsense", "100", "100:", ":100", "-1:100", "100:1x"] {
            assert!(
                Cli::try_parse_from([
                    "orchard",
                    "restore-image",
                    "--data",
                    "/d",
                    "--db",
                    "/d2",
                    "--operator-pubkey",
                    "/k",
                    "--out",
                    "/o",
                    "--db-owner",
                    bad,
                ])
                .is_err(),
                "accepted --db-owner {bad:?}"
            );
        }
    }

    #[test]
    fn prod_restore_min_ctr_requires_restore_from() {
                                                                                                   
                                      
        assert!(
            Cli::try_parse_from([
                "orchard",
                "prod",
                "--pubkey",
                "/k/op.pub",
                "--ssh-identity",
                "/k/id",
                "--image",
                "/i/r.img",
                "--wipe-confirmed",
                "--restore-min-ctr",
                "7",
                "203.0.113.5",
            ])
            .is_err(),
            "--restore-min-ctr without --restore-from must refuse"
        );
        let cli = Cli::try_parse_from([
            "orchard",
            "prod",
            "--pubkey",
            "/k/op.pub",
            "--ssh-identity",
            "/k/id",
            "--image",
            "/i/r.img",
            "--wipe-confirmed",
            "--restore-from",
            "/b/restore-1.persist.img",
            "--restore-min-ctr",
            "7",
            "203.0.113.5",
        ])
        .expect("the restore pair parses");
        match cli.command {
            OrchardCmd::Prod {
                restore_from,
                restore_min_ctr,
                ..
            } => {
                assert_eq!(
                    restore_from.as_deref(),
                    Some(std::path::Path::new("/b/restore-1.persist.img"))
                );
                assert_eq!(restore_min_ctr, Some(7));
            }
            _ => panic!("expected Prod"),
        }
    }

    #[test]
    fn build_installer_usb_parses_from_and_install_to() {
        let cli = Cli::try_parse_from([
            "orchard",
            "build-installer-usb",
            "--from",
            "/out/recipes-image-deadbeef.img",
            "--install-to",
            "nvme0n1",
        ])
        .expect("`build-installer-usb --from --install-to` must parse");
        match cli.command {
            OrchardCmd::BuildInstallerUsb {
                from, install_to, ..
            } => {
                assert_eq!(from, PathBuf::from("/out/recipes-image-deadbeef.img"));
                assert_eq!(install_to.as_deref(), Some("nvme0n1"));
            }
            _ => panic!("expected the BuildInstallerUsb subcommand"),
        }
    }

    #[test]
    fn build_installer_usb_install_to_is_optional() {
        let cli = Cli::try_parse_from(["orchard", "build-installer-usb", "--from", "/out/x.img"])
            .expect("`build-installer-usb` without `--install-to` must parse");
        match cli.command {
            OrchardCmd::BuildInstallerUsb { install_to, .. } => assert_eq!(install_to, None),
            _ => panic!("expected the BuildInstallerUsb subcommand"),
        }
    }

    #[test]
    fn sign_installer_usb_parses_img_and_defaults_to_the_software_rung() {
        let cli = Cli::try_parse_from([
            "orchard",
            "sign-installer-usb",
            "--img",
            "/out/recipes-installer-usb-deadbeef.img",
        ])
        .expect("`sign-installer-usb --img` must parse");
        match cli.command {
            OrchardCmd::SignInstallerUsb {
                img, secure_boot, ..
            } => {
                assert_eq!(
                    img,
                    PathBuf::from("/out/recipes-installer-usb-deadbeef.img")
                );
                assert_eq!(secure_boot, "software");                    
            }
            _ => panic!("expected the SignInstallerUsb subcommand"),
        }
    }

    #[test]
    fn parse_upgrade_target_resolves_every_leg_incl_rust_and_all() {
        use orchard::deploy::market_upgrade::Target;
                                                                                                              
        match parse_upgrade_target(None, Some("fb-acme".into()), None, false, None, None, false) {
            Ok(Target::Binary(k)) => assert_eq!(k, "fb-acme"),
            other => panic!("--binary must resolve to Target::Binary, got {other:?}"),
        }
        match parse_upgrade_target(None, None, None, false, None, Some("1.97.0".into()), false) {
            Ok(Target::Rust(v)) => assert_eq!(v, "1.97.0"),
            other => panic!("--rust must resolve to Target::Rust, got {other:?}"),
        }
        match parse_upgrade_target(None, None, None, false, None, None, true) {
            Ok(Target::All) => {}
            other => panic!("--all must resolve to Target::All, got {other:?}"),
        }
                                                                 
        match parse_upgrade_target(
            None,
            None,
            Some("dha-epa-config".into()),
            false,
            None,
            None,
            false,
        ) {
            Ok(Target::Config(k)) => assert_eq!(k, "dha-epa-config"),
            other => panic!("--config must resolve to Target::Config, got {other:?}"),
        }
                                                                              
        assert!(
            parse_upgrade_target(None, None, None, false, None, Some("1.97.0".into()), true)
                .is_err()
        );
    }
}
