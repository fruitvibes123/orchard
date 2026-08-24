                                                                                     
//! are UNFORGEABLE + NON-CONVERTIBLE, proven by NEGATIVE-COMPILE probes. Each file
//! under `tests/compile_fail/` MUST fail to compile; trybuild asserts the rejection
//! and pins the exact compiler error in the sibling `.stderr` — so the SEAL holding
//! is literally this test passing. A probe that started COMPILING (a leaked
//! constructor, a `From`, an `.into()`/`.as_verified()` path, a shared trait) flips
//! this test RED. This is the secure-by-construction guard from §2c made mechanical:
//! the non-convertibility is forbidden by the compiler, not by reviewer vigilance.
//!
//! Maintenance: the `.stderr` files pin rustc's exact diagnostics, so a rust pin bump
//! can require regenerating them — `TRYBUILD=overwrite cargo test -p dragonfruit
//! --test compile_fail`, then REVIEW each regenerated file to confirm the error is
//! still the seal-related one (E0451 private field / E0277 unimplemented trait /
//! E0599 no method), not an unrelated drift.
#[test]
fn sealed_proofs_are_unforgeable_and_non_convertible() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
