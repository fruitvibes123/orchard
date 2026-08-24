#!/bin/sh
# (the app + the 6 runtime binaries are fetched fixed-sha pinned artifacts; rambutan compiles ONLY in the
# deferred UEFI arm). So Orchard "reproducibility" is not a binary double-build but: (1) every vendored
# SOURCE drop re-verifies its pinned sha256 (fail-closed), and (2) the verify-at-consumption gate holds —
# a staged binary is fixed-sha BY CONSTRUCTION (a changed byte ⇒ hash mismatch ⇒ REFUSE). A REAL gate:
# DEFINITIVE produced-bytes reproducibility proof is the Phase-5 `make boot-gate` on the from-pins .img;
# this is the cheap fail-fast pre-check. Fail-closed (set -eu).
#
# NOTE: the gate is anchored on NAMED `--test` targets (pin_verify = the tamper-REFUSE break-test;
# pin_manifest_attrs = the serde fail-open guard). A bare name filter would silently MISS pin_verify (its
# fn name contains neither "pin_manifest" nor "artifact_store") and a deleted file would exit 0 "0 passed"
# — a false green (audit M-α class). `cargo test --test <name>` errors loud if the target is gone.
set -eu
echo "repro-check: vendored-source re-verify + verify-at-consumption gate (the produced-bytes proof is \`make boot-gate\`)"
cargo run --quiet -p orchard -- vendor                                          # (1) re-verify every *-src drop's sha; fail-closed
cargo test -p recipes-image-builder --test pin_verify --test pin_manifest_attrs # (2) tamper-REFUSE break-test + serde fail-open guard
cargo test -p recipes-image-builder --lib -- pin_manifest artifact_store        #     the parser + store unit battery (10 tests; filters after -- → libtest OR-matches both)
echo "repro-check OK: source drops verified; staged artifacts fixed-sha by construction."
echo "repro-check: the produced-bytes reproducibility seal is the Phase-5 \`make boot-gate\` on the from-pins .img."
