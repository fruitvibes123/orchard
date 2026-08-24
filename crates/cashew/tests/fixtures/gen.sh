#!/usr/bin/env bash
#
# DEV-HOST ONLY. Tests NEVER invoke gpg — they read the committed bytes under gen/. This script
# regenerates that corpus; because the keys are throwaway and randomly generated, a re-run produces a
# FRESH corpus (different keys/sigs) — that is expected. The REAL fixtures under real/ are the
# deterministic, toolchain-pinned ones; only this generated corpus is fresh-per-run. gen/MANIFEST.toml
# records what each file is.
#
# Requires: gpg 2.4.x (the pinned toolchain is gpg 2.4.9 / libgcrypt 1.12.2). No network.
#
#   key_a  RSA-4096 primary-signs [SC], NO signing subkey  (the REAL kernel-dev shape)
#   key_b  RSA-4096 primary + a signing subkey             (the chain shape; Component C / future)
#   key_c  RSA-4096 [SC]                                   (a second signer — "foreign / unpinned")
#   key_d  key_a-like + a SHORT-EXPIRY signing subkey       (policy negative: expired-at-now)
#   key_e  key_b-like whose signing subkey is REVOKED       (policy negative: revoked subkey)
#   key_f  [SC] whose PRIMARY is REVOKED (0x20)             (policy negative: revoked primary)
#   key_g  [SC] whose only UID CERT is REVOKED (0x30 at the SAME faked second as the 0x13 —
# Detached sigs (armored) over payloads {empty,1B,1KiB,5MiB} x {SHA256,SHA512} with key_a and key_b.
# Plus: a leading-zero-MPI sig (key_a; s has a high zero byte) and one SHA-1 sig (key_a, weak).
# All keys exported through the SAME §5.0 pruned+armored command.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/gen"
rm -rf "$out"
mkdir -p "$out"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"
# Permit loopback pinentry so throwaway keys generate UNATTENDED — no pinentry GUI/window ever, and an
# isolated home that never touches the operator's ~/.gnupg. The agent is killed + the home removed on
# exit.
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

# All throwaway key + signature material is stamped at a FIXED faked time (GENTIME), NOT the wall
# clock, so: (1) the corpus timestamps are stable across regenerations; (2) a single `fixture_now`
# (in METADATA, > GENTIME) sits after every generated creation time — otherwise keys created "today"
# would be future-dated relative to a fixture_now chosen for the 2026-05 real keys, and cashew's
# creation-time sanity would reject them. GENTIME = 2026-06-09; fixture_now = GENTIME + 100000 s.
GENTIME=1781000000
# Base batch invocation. Throwaway keys are UNPROTECTED (empty passphrase via loopback) — ephemeral
# test material, never secrets. `--cert-digest-algo SHA256` makes self-certs/bindings deterministically
# whitelisted (never a default SHA-1). `--faked-system-time` stamps creation times at GENTIME.
gpg_q() {
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --cert-digest-algo SHA256 --faked-system-time "${GENTIME}!" "$@"
}

# The §5.0 vendoring export (pruned, minimized, attribute-free, armored) — the SAME command the real
# fixtures use, so generated keyrings obey the identical contract.
prune_export() {  # <fpr> <keep-uid-expr> <outfile>
  gpg_q --export-options export-minimal,no-export-attributes \
        --export-filter "keep-uid=$2" \
        --export-filter 'drop-subkey=usage=e' \
        --armor --export "$1" > "$3"
}

# Deterministic payloads (content is fixed; only the keys are random). Built with python to avoid the
# `yes | head` SIGPIPE that trips `pipefail`.
mk_payloads() {
  : > "$out/payload_empty.bin"
  printf 'A' > "$out/payload_1b.bin"
  python3 - "$out" <<'PY'
import sys, pathlib
out = pathlib.Path(sys.argv[1])
pat = b"cashew differential fixture deterministic pattern block 0123456789abcdef\n"
def fill(n): return (pat * (n // len(pat) + 1))[:n]
(out / "payload_1kib.bin").write_bytes(fill(1024))
(out / "payload_5mib.bin").write_bytes(fill(5 * 1024 * 1024))
PY
}

quick_key() {  # <uid> -> prints fingerprint ; RSA-4096 [SC] primary, no passphrase
  gpg_q --quick-generate-key "$1" rsa4096 sign never >/dev/null 2>&1
  gpg --batch --with-colons --list-keys "$1" | awk -F: '/^fpr:/ {print $10; exit}'
}

echo "generating keys (RSA-4096; this takes a minute)…" >&2
FA=$(quick_key "cashew-key-a (primary-signs, no subkey) <a@example.invalid>")
FB=$(quick_key "cashew-key-b (primary + signing subkey) <b@example.invalid>")
FC=$(quick_key "cashew-key-c (foreign/unpinned) <c@example.invalid>")
FD=$(quick_key "cashew-key-d (short-expiry subkey) <d@example.invalid>")
FE=$(quick_key "cashew-key-e (revoked subkey) <e@example.invalid>")
FF=$(quick_key "cashew-key-f (revoked primary) <f@example.invalid>")
FG=$(quick_key "cashew-key-g (revoked uid cert) <g@example.invalid>")

# key_b: add a signing subkey (never expires).
gpg_q --quick-add-key "$FB" rsa4096 sign never
# key_d: add a signing subkey that expires 1h after GENTIME → expired at fixture_now (GENTIME+100000).
gpg_q --quick-add-key "$FD" rsa4096 sign seconds=3600
# key_e: add a signing subkey, then REVOKE it (a valid revocation signature over a valid binding).
gpg_q --quick-add-key "$FE" rsa4096 sign never
FE_SUB=$(gpg --batch --with-colons --list-keys "$FE" \
  | awk -F: '/^sub:/ {print $5}' | tail -n1)   # the 16-hex-digit long keyid of the newest subkey
# Revoke that subkey via an unattended edit-key macro (loopback; the full interactive prompt sequence:
# select subkey 1 → revkey → confirm → reason 3 (no longer used) → empty description → confirm → save).
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
    --cert-digest-algo SHA256 --faked-system-time "${GENTIME}!" --command-fd 0 \
    --edit-key "$FE" >/dev/null 2>&1 <<'EDIT'
key 1
revkey
y
3

y
save
EDIT

# key_f: revoke the PRIMARY — generate the 0x20 revocation certificate and import it back, so the
# export carries `primary, 0x20, uid, 0x13` (the direct-position revocation cashew must refuse).
# NOTE: --gen-revoke refuses --batch outright and wants a tty unless --no-tty; --command-fd drives
# its prompts: create? y → reason 3 (no longer used) → empty description → okay? y.
gpg --no-tty --yes --pinentry-mode loopback --passphrase '' \
    --cert-digest-algo SHA256 --faked-system-time "${GENTIME}!" --command-fd 0 \
    --gen-revoke "$FF" > "$GNUPGHOME/_f_rev.asc" 2>/dev/null <<'REVOKE'
y
3

y
REVOKE
gpg_q --import "$GNUPGHOME/_f_rev.asc"

# key_g: revoke the (only) UID's self-certification with a 0x30 at the SAME faked second — the
# Prompt sequence (status-fd verified): ask_revoke_sig.one y → ask_revoke_sig.okay y → reason 4
# (user id no longer valid) → empty description → okay y.
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
    --cert-digest-algo SHA256 --faked-system-time "${GENTIME}!" --command-fd 0 \
    --edit-key "$FG" >/dev/null 2>&1 <<'EDIT'
uid 1
revsig
y
y
4

y
save
EDIT

# key_a/b/c represent real vendoring shapes → export through the §5.0 pruned+armored command.
for pair in "a:$FA" "b:$FB" "c:$FC"; do
  tag="${pair%%:*}"; fpr="${pair##*:}"
  prune_export "$fpr" "mbox=${tag}@example.invalid" "$out/key_${tag}.asc"
done
# key_d (expired subkey) + key_e (revoked subkey) are ADVERSARIAL POLICY fixtures: their whole purpose
# is that the expired/revoked signing-subkey material is PRESENT for cashew to parse and reject on
# policy grounds. `export-minimal` on gpg 2.4.9 STRIPS expired subkeys (dev.gnupg.org T7990, the
# FULL export (still attribute-free + armored) to preserve that material. They are NOT §5.0 vendoring
# examples; they exercise the parser + no-skip law + candidate policy.
for pair in "d:$FD" "e:$FE" "f:$FF" "g:$FG"; do
  tag="${pair%%:*}"; fpr="${pair##*:}"
  gpg_q --export-options no-export-attributes --armor --export "$fpr" > "$out/key_${tag}.asc"
done

mk_payloads

# Detached, armored sigs over each payload x {SHA256,SHA512} with key_a (primary) and key_b (subkey).
sign_one() {  # <fpr> <digest> <payload> <outfile>
  gpg_q --default-key "$1" --digest-algo "$2" --detach-sign --armor \
        --output "$4" "$3"
}
for who in "a:$FA" "b:$FB"; do
  tag="${who%%:*}"; fpr="${who##*:}"
  for p in empty 1b 1kib 5mib; do
    for d in SHA256 SHA512; do
      sign_one "$fpr" "$d" "$out/payload_${p}.bin" \
        "$out/sig_${tag}_${p}_${d,,}.asc"
    done
  done
done

# Leading-zero-MPI sig (§6.4): sign the 1B payload repeatedly until the signature MPI's top octet is
# 0x00 (≈1/256 chance per try) — the fixture that pins the left-pad-to-k requirement. Record the loop
# count in the manifest.
# gpg emits canonical MINIMAL MPIs, and prints the signature integer's bit length as `data: [N bits]`.
# The fixture the left-pad-to-k requirement needs is a signature whose s < 2^(8(k-1)) — for RSA-4096
# (k = 512 octets) that is bits ≤ 4088 (minimal MPI ≤ 511 octets, so padding to 512 adds a leading
# zero). ~1/256 of signatures qualify. Read the bit length straight from gpg (robust; no byte-scan).
sig_mpi_bits() {  # prints the sig MPI bit length, 0 if not found
  gpg --batch --list-packets "$1" 2>/dev/null \
    | sed -n 's/.*data: \[\([0-9]\+\) bits\].*/\1/p' | head -n1
}
# PKCS#1 v1.5 signing is DETERMINISTIC (no random padding), so re-signing the same payload at the same
# faked time yields an identical s — the hunt must VARY an input. We vary the faked creation time by
# +1s per try (each still in [GENTIME, GENTIME+6000) ⊂ [GENTIME, fixture_now), so the winning sig's
# creation time stays ≤ fixture_now and ≥ key_a's creation). Record the winning offset in the manifest.
lz_tries=0
while :; do
  gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
      --cert-digest-algo SHA256 --faked-system-time "$((GENTIME + lz_tries))!" \
      --default-key "$FA" --digest-algo SHA256 --detach-sign --output "$out/_lz.bin" \
      "$out/payload_1b.bin"
  bits=$(sig_mpi_bits "$out/_lz.bin"); bits=${bits:-0}
  if [ "$bits" -gt 0 ] && [ "$bits" -le 4088 ]; then
    cp "$out/_lz.bin" "$out/sig_a_1b_sha256_leadingzero.sig"
    lz_win_offset=$lz_tries
    break
  fi
  lz_tries=$((lz_tries + 1))
  [ "$lz_tries" -ge 6000 ] && { echo "leading-zero hunt exhausted" >&2; exit 1; }
done
rm -f "$out/_lz.bin"

# One SHA-1 (weak) detached sig with key_a — the negative that must classify WeakHash(2).
gpg_q --default-key "$FA" --digest-algo SHA1 --allow-weak-digest-algos \
      --detach-sign --armor --output "$out/sig_a_1b_sha1_weak.asc" "$out/payload_1b.bin"

# One EXPIRING detached sig (hashed critical subpacket 3): expires 1h after GENTIME → EXPIRED at
# fixture_now (GENTIME+100000) but still valid at GENTIME+1000 — the finalize sig-expiry pair.
gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' \
    --cert-digest-algo SHA256 --faked-system-time "${GENTIME}!" \
    --default-sig-expire seconds=3600 --ask-sig-expire \
    --default-key "$FA" --digest-algo SHA256 --detach-sign --armor \
    --output "$out/sig_a_1b_sha256_expiring.asc" "$out/payload_1b.bin"

# Record the manifest (what each file is + the run's key fingerprints + the leading-zero loop count).
{
  echo "
  echo "# Keys are random; tests bind to these committed bytes, not to gen.sh determinism."
  echo "# All key + sig creation times are stamped at gen_time (--faked-system-time); tests evaluate"
  echo "# the generated corpus at fixture_now (> gen_time, so nothing is future-dated; key_d's subkey"
  echo "# is expired by then). The REAL fixtures under real/ share the same fixture_now (METADATA.toml)."
  echo "gen_time    = $GENTIME"
  echo "fixture_now = $((GENTIME + 100000))"
  echo "leading_zero_mpi_tries      = $lz_tries"
  echo "leading_zero_time_offset_s  = $lz_win_offset   # winning sig created at gen_time + this"
  echo "expiring_sig_lifetime_s     = 3600   # sig_a_1b_sha256_expiring: expired at fixture_now"
  echo ""
  echo "[keys]              # fingerprints of THIS run's throwaway keys"
  echo "key_a = \"$FA\"      # primary-signs [SC], no signing subkey"
  echo "key_b = \"$FB\"      # primary + signing subkey"
  echo "key_c = \"$FC\"      # foreign / unpinned [SC]"
  echo "key_d = \"$FD\"      # short-expiry signing subkey (expired at any real now)"
  echo "key_e = \"$FE\"      # revoked signing subkey"
  echo "key_f = \"$FF\"      # revoked PRIMARY (0x20 in the direct position)"
  echo "key_g = \"$FG\"      # only UID cert revoked (0x30, same faked second as the 0x13)"
  echo "key_e_revoked_subkey = \"$FE_SUB\""
} > "$out/MANIFEST.toml"

echo "gen.sh: wrote $(ls "$out" | wc -l) files to gen/ (lz tries: $lz_tries)" >&2
