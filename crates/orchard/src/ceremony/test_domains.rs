                                                                                              
//!
//! The distinction is load-bearing, not cosmetic. A real-domain image's baked `fb-acme` reaches a
//! live ACME endpoint the moment it boots, so a real-domain gate boot MUST be hermetic (the
                                                                                                 
//! resolver answers for.
//!
//! An ALLOWLIST, exact-set and committed: anything not in it is REAL. A blocklist or a suffix
//! heuristic would classify a newly-invented test domain as real (harmless) but also a
//! real domain that happens to end in `.test` as test (a false green on the arm that exists to
//! stop a real-domain boot under open NAT).

/// The committed test-domain set. Adding a row is a deliberate act: it declares that no public
/// resolver answers for that name, so a gate boot with it cannot reach a live ACME endpoint.
pub const TEST_DOMAINS: &[&str] = &[
                                           
    "box.test",
                                   
    "prod.test",
];

/// The domain class of one baked domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainClass {
    Test,
    Real,
}

/// Classify. Exact match against the committed set, case-folded (DNS names are
/// case-insensitive, so `BOX.TEST` is the same name and must not read as a different, real one);
/// everything else is REAL, including the empty string — an image with no declared domain is not
/// a licence to boot it under open NAT.
pub fn classify(domain: &str) -> DomainClass {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if TEST_DOMAINS.iter().any(|t| *t == d) {
        DomainClass::Test
    } else {
        DomainClass::Real
    }
}
