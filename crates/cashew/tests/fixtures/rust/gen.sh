#!/usr/bin/env bash
# cashew — generate the pinned-bare-key (SHA-1-self-signed) fixture corpus (Component C, plan Task 1 /
# norm); THIS corpus is SHA-1-self-signed (the `Keyring::load_pinned_bare` EXCEPTION — the real Rust
# release key shape, §3.1: all self-certs SHA-1, primary signs the manifests with a strong data sig).
#
# DEV-HOST ONLY. Tests NEVER invoke gpg — they read the committed bytes under gen/. A re-run produces a
# FRESH corpus (throwaway keys are random); tests bind to the committed bytes + gen/MANIFEST.toml, never
# to gen.sh determinism. Requires gpg 2.4.x (pinned toolchain gpg 2.4.9 / libgcrypt 1.12.2). No network.
#
# Shapes produced (mirror the real Rust key: RSA-4096 [SC] primary, SHA-1 self-cert, primary signs):
#   rust_key.asc                  [SC] primary, SHA-1 self-cert, NO subkey  — the genuine pinned key
#                                 cashew cannot tell a genuine [S] from an attacker-appended one — the
#                                 bare path binds the PRIMARY ONLY, so a subkey sig must NOT verify)
#   foreign_key.asc               a 2nd, UNPINNED [SC] key (SHA-1 self-cert)
#   manifest.bin                  a small "manifest" payload (opaque bytes at this layer)
#   sig_primary_sha512.asc        manifest signed by rust_key's PRIMARY, SHA-512  — the genuine data sig
#   sig_subkey_sha512.asc         manifest signed by the APPENDED SUBKEY, SHA-512 — must fail (primary-only)
#   sig_foreign_sha512.asc        manifest signed by foreign_key's primary, SHA-512 — unpinned → BadSignature
# gen/MANIFEST.toml records the run's fingerprints + the stable clocks.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/gen"
rm -rf "$out"
mkdir -p "$out"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

# Stable faked clocks (shared with ../gen.sh): keys + sigs stamped at GEN_TIME; tests evaluate at
# FIXTURE_NOW (> GEN_TIME, so nothing is future-dated). GEN_TIME = 2026-06-09.
GEN_TIME=1781000000
FIXTURE_NOW=$((GEN_TIME + 100000))

# The bare-path primary self-certs with SHA-1 (`--cert-digest-algo SHA1 --allow-weak-digest-algos`) —
# the WHOLE POINT: this key is REFUSED by the strict `Keyring::load` (WeakHash(2)) and only loadable via
# `load_pinned_bare`. Throwaway keys are UNPROTECTED (empty passphrase, loopback) — test material.
gpg_sha1() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --cert-digest-algo SHA1 --allow-weak-digest-algos --faked-system-time "${GEN_TIME}!" "$@"
}
# Default (SHA-256) invocation — for the subkey BINDING (its digest is irrelevant: the bare path ignores
# subkeys entirely) and for detached DATA sigs (forced strong, SHA-512).
gpg_def() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --faked-system-time "${GEN_TIME}!" "$@"
}

fpr_of() {  # <uid-substring> -> primary fingerprint
  gpg --batch --with-colons --list-keys "$1" | awk -F: '/^fpr:/ {print $10; exit}'
}

echo "generating RSA-4096 keys (SHA-1 self-cert; this takes a minute)…" >&2
gpg_sha1 --quick-generate-key "cashew-rust (sha1 self-cert, primary signs) <rust@example.invalid>" \
         rsa4096 sign never >/dev/null 2>&1
FR=$(fpr_of "rust@example.invalid")
gpg_sha1 --quick-generate-key "cashew-rust-foreign (unpinned) <foreign@example.invalid>" \
         rsa4096 sign never >/dev/null 2>&1
FF=$(fpr_of "foreign@example.invalid")

# The manifest payload (opaque bytes at the bare-path layer; Task 4 uses a manifest-SHAPED fixture).
printf 'cashew bare-path fixture manifest — Component C\nversion = "6.99.1 (deadbeef 2026-06-09)"\n' \
  > "$out/manifest.bin"

# 1) Export the genuine primary-only key BEFORE adding any subkey (no-subkey shape).
gpg_sha1 --export-options no-export-attributes --armor --export "$FR" > "$out/rust_key.asc"
# The genuine data sig: manifest signed by the PRIMARY (force with `!`), SHA-512 (strong; the bare path
# never touches the SHA-1 self-certs).
gpg_def --default-key "${FR}!" --digest-algo SHA512 --detach-sign --armor \
        --output "$out/sig_primary_sha512.asc" "$out/manifest.bin"

# 2) APPEND a signing subkey to the SAME primary (SHA-256 binding — ignored by the bare path), export the
# NOT verify against the primary-only bare keyring).
gpg_def --quick-add-key "$FR" rsa4096 sign never
FR_SUB=$(gpg --batch --with-colons --list-keys "$FR" | awk -F: '/^sub:/ {print $5}' | tail -n1)
gpg_sha1 --export-options no-export-attributes --armor --export "$FR" > "$out/rust_key_appended_subkey.asc"
gpg_def --default-key "${FR_SUB}!" --digest-algo SHA512 --detach-sign --armor \
        --output "$out/sig_subkey_sha512.asc" "$out/manifest.bin"

# 3) The foreign (unpinned) key + its data sig over the manifest.
gpg_sha1 --export-options no-export-attributes --armor --export "$FF" > "$out/foreign_key.asc"
gpg_def --default-key "${FF}!" --digest-algo SHA512 --detach-sign --armor \
        --output "$out/sig_foreign_sha512.asc" "$out/manifest.bin"

{
  echo "
  echo "# Tests bind to these committed bytes + these fingerprints, not to gen.sh determinism."
  echo "gen_time    = $GEN_TIME"
  echo "fixture_now = $FIXTURE_NOW"
  echo ""
  echo "[keys]                       # fingerprints of THIS run's throwaway keys"
  echo "rust_key    = \"$FR\"        # [SC] primary, SHA-1 self-cert, signs the genuine manifest sig"
  echo "foreign_key = \"$FF\"        # unpinned [SC] key"
  echo "rust_appended_subkey_keyid = \"$FR_SUB\"   # the appended signing subkey (16-hex long keyid)"
} > "$out/MANIFEST.toml"

echo "rust/gen.sh: wrote $(ls "$out" | wc -l) files to gen/ (rust_key=$FR foreign=$FF)" >&2
