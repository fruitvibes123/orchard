#!/usr/bin/env bash
# rust_bump fixture corpus (Component C Task 4): a throwaway SHA-1-self-signed "Rust" key + a signed
# release-manifest-shaped TOML + adversarial variants (tampered / unpinned-signer / older-version /
# unavailable-target). DEV-HOST ONLY — tests read the committed bytes under gen/ + gen/MANIFEST.toml
# (throwaway keys are random; a re-run yields a FRESH corpus). Requires gpg 2.4.x. No network.
#
# The signer self-certs with SHA-1 (the real Rust-key shape) so the bump exercises cashew's
# `load_pinned_bare` exception; it signs the manifests with a strong RSA/SHA-512 data sig.

set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/gen"; rm -rf "$out"; mkdir -p "$out"
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; chmod 700 "$GNUPGHOME"
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

GEN_TIME=1781000000
FIXTURE_NOW=$((GEN_TIME + 100000))
VERSION="6.99.1"
OLDER="6.98.0"

gpg_sha1() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --cert-digest-algo SHA1 --allow-weak-digest-algos --faked-system-time "${GEN_TIME}!" "$@"
}
gpg_def() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --faked-system-time "${GEN_TIME}!" "$@"
}
fpr_of() { gpg --batch --with-colons --list-keys "$1" | awk -F: '/^fpr:/ {print $10; exit}'; }

echo "generating RSA-4096 keys (SHA-1 self-cert)…" >&2
gpg_sha1 --quick-generate-key "rust-bump-signer (sha1 self-cert) <signer@example.invalid>" \
         rsa4096 sign never >/dev/null 2>&1
FR=$(fpr_of "signer@example.invalid")
gpg_sha1 --quick-generate-key "rust-bump-foreign (unpinned) <foreign@example.invalid>" \
         rsa4096 sign never >/dev/null 2>&1
FF=$(fpr_of "foreign@example.invalid")
gpg_sha1 --export-options no-export-attributes --armor --export "$FR" > "$out/signer.asc"

# A valid manifest for <version>: the two fixed components, available=true, an https static.rust-lang
# .tar.xz url + a 64-hex xz_hash (arbitrary — the bump pins the sha, the CONTAINER build checks it).
mk_manifest() {  # <version> <outfile>
  cat > "$2" <<EOF
[pkg.rust]
version = "$1 (deadbeef1 2026-06-09)"

[pkg.rust.target.x86_64-unknown-linux-musl]
available = true
xz_url = "https://static.rust-lang.org/dist/2026-06-09/rust-$1-x86_64-unknown-linux-musl.tar.xz"
xz_hash = "1111111111111111111111111111111111111111111111111111111111111111"

[pkg.rust-std.target.x86_64-unknown-uefi]
available = true
xz_url = "https://static.rust-lang.org/dist/2026-06-09/rust-std-$1-x86_64-unknown-uefi.tar.xz"
xz_hash = "2222222222222222222222222222222222222222222222222222222222222222"
EOF
}
mk_manifest "$VERSION" "$out/manifest.toml"
mk_manifest "$OLDER"   "$out/manifest-older.toml"

# The uefi target marked unavailable (validly signed, but component extraction must fail closed).
cat > "$out/manifest-unavailable.toml" <<EOF
[pkg.rust]
version = "$VERSION (deadbeef1 2026-06-09)"

[pkg.rust.target.x86_64-unknown-linux-musl]
available = true
xz_url = "https://static.rust-lang.org/dist/2026-06-09/rust-$VERSION-x86_64-unknown-linux-musl.tar.xz"
xz_hash = "1111111111111111111111111111111111111111111111111111111111111111"

[pkg.rust-std.target.x86_64-unknown-uefi]
available = false
EOF

# Tampered: the valid manifest + an appended byte; the VALID .asc will not verify it.
cp "$out/manifest.toml" "$out/manifest-tampered.toml"
printf '\n# tampered\n' >> "$out/manifest-tampered.toml"

sign() { gpg_def --default-key "$1!" --digest-algo SHA512 --detach-sign --armor --output "$3" "$2"; }
sign "$FR" "$out/manifest.toml"             "$out/manifest.toml.asc"
sign "$FR" "$out/manifest-older.toml"       "$out/manifest-older.toml.asc"
sign "$FR" "$out/manifest-unavailable.toml" "$out/manifest-unavailable.toml.asc"
sign "$FF" "$out/manifest.toml"             "$out/unpinned.asc"   # a DIFFERENT signer over the genuine manifest

{
  echo "# rust_bump fixture corpus (throwaway; FRESH per run). Tests bind to these bytes + fprs."
  echo "version = \"$VERSION\""
  echo "older_version = \"$OLDER\""
  echo "gen_time = $GEN_TIME"
  echo "fixture_now = $FIXTURE_NOW"
  echo ""
  echo "[keys]"
  echo "signer = \"$FR\""
  echo "foreign = \"$FF\""
} > "$out/MANIFEST.toml"
echo "rust_bump/gen.sh: wrote $(ls "$out" | wc -l) files (signer=$FR foreign=$FF)" >&2
