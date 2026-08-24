                                                                                                      
//!
//! The fb-manifest crate's own `gate_tests` + `fail_closed_battery` prove each validator/parse class
//! against a *representative* OS set and hand-written fixtures. This battery is the §9 acceptance gate
//! ("a malformed / privilege-escalating / uid-colliding manifest is REFUSED at BAKE"): it mutates a
//! COMPLETE valid tenant (the synthetic `sample-tenant.toml`) and validates through image-builder's
//! REAL [`config::os_identities`] source of truth — so it proves the WIRING (a real tenant + the
//! production OS-fixed identity set fail closed), not just the library in isolation. A mutation that
//! slipped past the bake gate would ship a privilege-escalating box; each class below must `Err`.
//!
                                                                                                          
//! from the pinned store at bake (`config::parse_validated_manifest`). This battery therefore mutates
//! orchard's OWN synthetic fixture (a non-recipes "blogd" tenant); the gate it exercises is
//! tenant-agnostic, so every validator class's fail-closed coverage is preserved.
//!
                                                                                     
                                                                                            
                                                                                                  
                                                                                                       

use fb_manifest::argv::{ArgvToken, KnownPlaceholder};
use fb_manifest::validate::ValidationError;
use fb_manifest::{parse_and_validate, BakeError};
use recipes_image_builder::config;

/// The synthetic sample tenant — a COMPLETE valid manifest (orchard's own test fixture, NOT recipes).
/// Mutating THIS (not a hand-written single-table fixture) is what makes the battery prove the bake gate
/// fails closed on a real, complete tenant.
const SAMPLE: &str = include_str!("fixtures/sample-tenant.toml");

/// Mutate the sample fixture with a SINGLE targeted replacement, asserting the anchor existed (an
/// un-matched anchor would silently leave SAMPLE valid → a vacuous "refused" test).
fn mutate(from: &str, to: &str) -> String {
    let m = SAMPLE.replacen(from, to, 1);
    assert_ne!(
        m, SAMPLE,
        "mutation anchor {from:?} not found in sample-tenant.toml"
    );
    m
}

/// Validate a mutated manifest through the REAL OS-fixed identity set; return the (required) error.
fn refused(mutated: &str) -> BakeError {
    parse_and_validate(mutated, &config::os_identities())
        .expect_err("a privilege-escalating / malformed manifest must be REFUSED at bake")
}

#[test]
fn the_sample_fixture_validates_through_the_real_bake_wiring() {
                                                                                                
    parse_and_validate(SAMPLE, &config::os_identities()).expect(
        "the synthetic sample-tenant.toml must pass the gate (a complete, valid tenant to mutate)",
    );
}

                                                                   

#[test]
fn unknown_field_at_depth_is_refused() {
                                                                                                 
                                                                                                     
    let err = refused(&mutate("argv = [], priv", "argv = [], evil = 1, priv"));
    assert!(matches!(err, BakeError::Parse(_)), "{err:?}");
}

#[test]
fn a_missing_required_field_is_refused() {
                                                                                             
    let err = refused(&mutate("port = 443\n", ""));
    assert!(matches!(err, BakeError::Parse(_)), "{err:?}");
}

                                                               

#[test]
fn a_tenant_uid_of_zero_is_refused() {
                                                                                                
                                                                                              
    let err = refused(&mutate(
        "name = \"blogd\"\nuid = 100",
        "name = \"blogd\"\nuid = 0",
    ));
    assert!(
        matches!(err, BakeError::Validation(ValidationError::UidRoot)),
        "{err:?}"
    );
}

#[test]
fn a_uid_colliding_with_an_os_identity_is_refused() {
                                                                                                 
                                                                                                     
    let err = refused(&mutate(
        "name = \"blogd\"\nuid = 100",
        "name = \"blogd\"\nuid = 104",
    ));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::UidCollision { uid: 104 })
        ),
        "{err:?}"
    );
}

#[test]
fn a_tenant_identity_reusing_an_os_name_is_refused() {
                                                                                                
                                                                                                      
                                                                                                       
    let err = refused(&mutate(
        "name = \"blogd\"\nuid = 100",
        "name = \"haproxy\"\nuid = 100",
    ));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::IdentityNameCollision { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn a_setuidgid_root_service_is_refused() {
                                                                                            
                                 
    let err = refused(&mutate("user = \"blogd\"", "user = \"root\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::SetuidUserRoot { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn an_unbaked_setuidgid_user_is_refused() {
                                                                                                        
                                                                                                     
    let err = refused(&mutate("user = \"blogd\"", "user = \"ghost\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::SetuidUserUnknown { .. })
        ),
        "{err:?}"
    );
}

                                                                              

#[test]
fn an_argv_metacharacter_literal_is_refused() {
                                                                           
    let err = refused(&mutate("value = \"worker\"", "value = \"x; reboot\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::ArgvCharset { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn an_edge_path_metacharacter_is_refused() {
                                                                                                         
    let err = refused(&mutate("\"/upload/\"", "\"/up;load/\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::ArgvCharset { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn a_backup_traversal_source_is_refused() {
                                                                                            
    let err = refused(&mutate("\"posts\", \"media\"", "\"../../etc\", \"x\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::PathTraversal { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn an_absolute_backup_source_is_refused() {
                                                                                                      
    let err = refused(&mutate("\"posts\", \"media\"", "\"/etc\", \"x\""));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::PathAbsolute { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn an_ld_preload_env_key_is_refused() {
                                                                                            
    let err = refused(&mutate("STATE_DIR =", "LD_PRELOAD ="));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::EnvKeyForbidden { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn a_traversal_env_key_is_refused() {
                                                                                                
    let err = refused(&mutate("STATE_DIR =", "\"../escape\" ="));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::EnvKeyCharset { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn a_setuidgid_envdir_disagreeing_with_env_envdir_is_refused() {
                                                                                                      
                                                                                                           
                                                                                                          
    let err = refused(&mutate(
        "user = \"blogd\", envdir = \"/etc/blogd/env\"",
        "user = \"blogd\", envdir = \"/etc/other/env\"",
    ));
    assert!(
        matches!(
            err,
            BakeError::Validation(ValidationError::EnvdirMismatch { .. })
        ),
        "{err:?}"
    );
}

                                                                                                 

#[test]
fn a_literal_of_a_placeholder_string_renders_verbatim_not_the_epoch() {
    let ctx = fb_manifest::PlaceholderCtx {
        domain: "box.test".into(),
        source_date_epoch: 1_700_000_000,
    };
                                                                                                     
                                                                         
    let aliasing_literal = ArgvToken::Literal {
        value: "{source_date_epoch}".into(),
    };
    assert_eq!(aliasing_literal.render(&ctx), "{source_date_epoch}");
                                                                           
    let real = ArgvToken::Placeholder {
        name: KnownPlaceholder::SourceDateEpoch,
    };
    assert_eq!(real.render(&ctx), "1700000000");
}
