//! Orchard — the operator-host build/deploy factory CLI library.
//!
//! Lifted out of the `recipes` crate's `deploy` feature in the OS-extraction
                                                                                    
//! the offline host-key precompute. This crate is operator-host ONLY — it never ships
//! in the box image, and it is the sole home of `dragonfruit[sign]` (the CRUX "box
//! never signs" confinement, made structural by the crate boundary).
//!
//! Modules are added by the move tasks (1a.2 `deploy`, 1a.3 `oneshots_offline`).

                                                                            
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
                                                                                         
                                                                                                    
                                                                                                    
                                                                                            
                                          
#![deny(clippy::disallowed_methods)]

/// The guided-ceremony spine: the install ceremony as code-resident data + classification +
                                                                                            
pub mod ceremony;
/// The clap surface (`Cli`/`OrchardCmd`/sub-enums + value parsers), lib-resident so the ceremony
/// classification and its totality self-tests reach the real enum (guided-ceremony Task 2b,
                                                 
pub mod cli;
/// The operator-host `deploy` subcommand logic (build pipeline + key ceremony + pin
/// refresh + the prod takeover). Lifted from the recipes crate's `deploy` feature.
pub mod deploy;
/// The offline rescue/runtime host-key precompute (TOFU known_hosts), lifted from
/// `box_oneshots::rescue_keys`'s `--image` mode.
pub mod oneshots_offline;
                                                                                                
pub mod utf8path;
