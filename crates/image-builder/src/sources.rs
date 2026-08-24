                                                                                        
//!
                                                                                                    
//! this module's consts) and the bake's verify-at-consumption both decode through
//! [`decode_verified_xz`] — single-read whole-buffer (the hash and the decode consume the SAME
//! in-memory bytes, no TOCTOU window by construction), a parameterized sha-gate ([`ShaGate`]:
//! the bake refuses a pin mismatch BEFORE any decode; the bump emits the digest it is about to
                                                                                               
//! `?`, where the full-consumption assert would be vacuous), the decompressed-size bomb ceiling,
                                                                                            
//! attacker-suffix `.xz` must be refused — the pin covers bytes the decode never saw).
//!
//! This module is also the SOLE code home of the upstream source URLs (the §3a-5 reshape's
//! typed-derivation half — `tests/pins_drift.rs` locks the exact set).

use crate::Fetcher;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Where kernel.org publishes stable 6.x source tarballs + detached signatures (re-homed from
/// orchard `kernel_bump`, which re-exports it). The `v6.x/` segment is deliberate scope
                                                                                   
pub const KERNEL_ORG_BASE: &str = "https://cdn.kernel.org/pub/linux/kernel/v6.x";
/// Upstream base for `syslinux-<ver>.tar.xz` (the retired fetch script's URL, typed).
pub const SYSLINUX_ORG_BASE: &str =
    "https://www.kernel.org/pub/linux/utils/boot/syslinux/Testing/6.04";
/// Fetch-body/transport cap for the kernel `.tar.xz` (F-2ES-R1-6): linux-6.18's `.tar.xz`
/// ≈ 150 MB — 256 MiB is generous headroom over a specified shape, far below host RAM.
pub const KERNEL_XZ_CAP: u64 = 256 * 1024 * 1024;
/// Decompressed-size ceiling for the kernel tar — the decompression-bomb guard (F-2ES-R1-2).
/// linux-6.18's uncompressed tar ≈ 1.55 GB; ~2 GiB is 2× the expected shape. The streaming
/// decode counts bytes and aborts past this, so a hostile `.xz` burns at most this much digest
/// work, never unbounded memory.
pub const KERNEL_TAR_CEILING: u64 = 2 * 1024 * 1024 * 1024;
/// Transport cap for the syslinux `.tar.xz` fetch (tarball ≈ 5.4 MB).
pub const SYSLINUX_XZ_CAP: u64 = 16 * 1024 * 1024;
/// Decompressed-size bomb ceiling for the syslinux tree (≈ 30 MB decompressed).
pub const SYSLINUX_TAR_CEILING: u64 = 256 * 1024 * 1024;

/// Fail-closed errors for the verified source path. Every variant refuses BEFORE any consumer
/// (cashew feed, extraction, staging) sees unverified bytes.
#[derive(Debug, thiserror::Error)]
pub enum SourcesError {
    /// The sha-gate: the buffer does not hash to the pins.toml pin.
    #[error(
        "sha256 mismatch: pins.toml expects {expected}, the bytes hash to {actual} — REFUSING \
         (tampered/stale/absent-repin source)"
    )]
    ShaMismatch { expected: String, actual: String },
                                                                            
    #[error("xz decode: {0}")]
    Decode(String),
    /// The decompressed-size ceiling tripped.
    #[error("decompressed size exceeds the {limit}-byte ceiling — decompression-bomb guard")]
    Ceiling { limit: u64 },
                                                                                
    #[error(
        "the single xz stream consumed {consumed} of {total} bytes — {} trailing byte(s) would be \
         covered by the sha but never decoded; refusing (verify-bypass guard)",
        .total - .consumed
    )]
    TrailingBytes { consumed: u64, total: u64 },
    /// Extraction contract violations (Task 2: non-empty dest, topdir shape, unpack failure).
    #[error("extract: {0}")]
    Extract(String),
    /// Staging failures in the prime step (Task 4: symlink at the staged path, temp/rename io).
    #[error("stage: {0}")]
    Stage(String),
    /// Transport failures in the prime step (Task 4).
    #[error("fetch: {0}")]
    Fetch(String),
}

                                                                                 
pub enum ShaGate<'a> {
    /// Bake/prime: refuse unless `sha256(buffer)` equals this 64-hex pin — checked BEFORE any
    /// decode work, so a tampered source never reaches the decoder.
    ExpectPin(&'a str),
    /// Bump: no pin exists yet — emit the digest for pin-writing (the caller is CREATING the pin).
    Emit,
}

/// What a verified decode proved: the digest over the exact compressed bytes consumed, and the
/// decoded size (all of it seen by the sink).
#[derive(Debug)]
pub struct XzVerified {
    /// `hex(sha256(xz))` — in `ExpectPin` mode provably equal to the pin.
    pub xz_sha256: String,
    /// Total decompressed bytes streamed to the sink (≤ the ceiling).
    pub decoded_bytes: u64,
}

/// Single-read verified decode (the shape proven in `kernel_bump`, extracted verbatim): sha256
/// over the WHOLE in-memory buffer (gated per `gate`), then stream the SAME buffer through
                                                                                                  
                                                                         
pub fn decode_verified_xz(
    xz: &[u8],
    gate: ShaGate<'_>,
    decoded_ceiling: u64,
    sink: &mut dyn FnMut(&[u8]),
) -> Result<XzVerified, SourcesError> {
    let xz_sha256 = hex::encode(Sha256::digest(xz));
    if let ShaGate::ExpectPin(pin) = gate {
        if xz_sha256 != pin {
            return Err(SourcesError::ShaMismatch {
                expected: pin.into(),
                actual: xz_sha256,
            });
        }
    }
    let mut decoder = liblzma::read::XzDecoder::new(xz);
    let mut chunk = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = std::io::Read::read(&mut decoder, &mut chunk)
            .map_err(|e| SourcesError::Decode(e.to_string()))?;               
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > decoded_ceiling {
            return Err(SourcesError::Ceiling {
                limit: decoded_ceiling,
            });
        }
        sink(&chunk[..n]);
    }
                                                                                                 
                                                                                         
    if decoder.total_in() != xz.len() as u64 {
        return Err(SourcesError::TrailingBytes {
            consumed: decoder.total_in(),
            total: xz.len() as u64,
        });
    }
    Ok(XzVerified {
        xz_sha256,
        decoded_bytes: total,
    })
}

                                                                                                
/// and decode under the full [`decode_verified_xz`] gate set into a temp `.tar` file — the verify
/// COMPLETES before any extraction byte lands — then `tar::Archive::unpack` into `dest`, which must
/// exist and be EMPTY (the fresh-isolated-dir invariant: extraction into a per-build tempdir alone
/// defeats the CVE-2025-45582 multi-archive-symlink precondition). Returns the report + the SINGLE
/// top-level directory inside `dest` (the `linux-<v>/` / `syslinux-<v>/` shape; zero, two, or a
/// non-dir top entry = `Extract` error).
///
                                                                                                     
/// only ever a verify-at-consumption operation (the bump never extracts, it only streams to a
/// digest), so `ShaGate::Emit` is deliberately NOT expressible here. The gate cannot be forgotten
/// at a bake call site — the same secure-by-construction property `KernelInputs.sha256` gives the
/// field. The extractor is the Rust `tar` crate (the `lib.rs::extract` `unpack` precedent — NEVER a
                                                                                             
                                                                                                  
/// decode gates fire before `unpack`, and a post-unpack shape refusal cleans up).
pub fn extract_verified_xz(
    xz: &[u8],
    expected_pin: &str,
    decoded_ceiling: u64,
    dest: &Path,
) -> Result<(XzVerified, PathBuf), SourcesError> {
    let extract_err = |msg: String| SourcesError::Extract(msg);
                                                           
    let mut existing = std::fs::read_dir(dest)
        .map_err(|e| extract_err(format!("read_dir {}: {e}", dest.display())))?;
    if existing.next().is_some() {
        return Err(extract_err(format!(
            "{} is not empty — extraction requires a fresh, empty, isolated dir",
            dest.display()
        )));
    }
                                                                                                   
                                                                                             
    let parent = dest
        .parent()
        .ok_or_else(|| extract_err(format!("{} has no parent dir", dest.display())))?;
    let mut tmp_tar = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| extract_err(format!("temp tar in {}: {e}", parent.display())))?;
    let mut sink_io: Option<std::io::Error> = None;
                                                                           
    let verified = decode_verified_xz(
        xz,
        ShaGate::ExpectPin(expected_pin),
        decoded_ceiling,
        &mut |chunk| {
            if sink_io.is_none() {
                if let Err(e) = std::io::Write::write_all(tmp_tar.as_file_mut(), chunk) {
                    sink_io = Some(e);
                }
            }
        },
    )?;
    if let Some(e) = sink_io {
        return Err(extract_err(format!("write temp tar: {e}")));
    }
                                                                                                      
                                                                                                    
                                                                                              
                                                                                                   
                                                                                                 
                           
    let unpack_then_shape = || -> Result<PathBuf, SourcesError> {
        let reader = tmp_tar
            .reopen()
            .map_err(|e| extract_err(format!("reopen temp tar: {e}")))?;
        tar::Archive::new(reader)
            .unpack(dest)
            .map_err(|e| extract_err(format!("unpack into {}: {e}", dest.display())))?;
        single_topdir(dest)
    };
    match unpack_then_shape() {
        Ok(inner) => Ok((verified, inner)),
        Err(e) => {
                                                                                                   
                                                                       
            let _ = std::fs::remove_dir_all(dest);
            let _ = std::fs::create_dir(dest);
            Err(e)
        }
    }
}

/// The single-top-level-directory contract: `dest` holds exactly ONE entry, a real directory
/// (a symlink top fails — `DirEntry::file_type` does not follow). Returns its path.
fn single_topdir(dest: &Path) -> Result<PathBuf, SourcesError> {
    let extract_err = |msg: String| SourcesError::Extract(msg);
    let mut entries = Vec::new();
    let iter = std::fs::read_dir(dest)
        .map_err(|e| extract_err(format!("read_dir {}: {e}", dest.display())))?;
    for entry in iter {
        entries.push(entry.map_err(|e| extract_err(format!("read_dir entry: {e}")))?);
    }
    match entries.as_slice() {
        [single] => {
            let ft = single
                .file_type()
                .map_err(|e| extract_err(format!("file_type: {e}")))?;
            if !ft.is_dir() {
                return Err(extract_err(format!(
                    "the archive's single top-level entry {:?} is not a directory — expected the \
                     linux-<ver>/ / syslinux-<ver>/ shape",
                    single.file_name()
                )));
            }
            Ok(single.path())
        }
        other => Err(extract_err(format!(
            "the archive must hold exactly ONE top-level directory, found {} top-level entries",
            other.len()
        ))),
    }
}

                                                                                                                                                                  

/// URL/path-splice whitelist for a pins version component: 1–32 bytes of `[a-z0-9._-]`, no
/// leading dot (`"6.18.34"`, `"6.04-pre1"`). Defense-in-depth — `pins.toml` is git-reviewed, but
/// nothing spliced into a fetch URL or a staged path goes unvalidated (a hostile version could
/// otherwise carry `../` or a URL-authority break).
pub fn validate_source_component(v: &str) -> Result<(), SourcesError> {
    let ok = (1..=32).contains(&v.len())
        && !v.starts_with('.')
        && v.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        });
    if ok {
        Ok(())
    } else {
        Err(SourcesError::Fetch(format!(
            "source version {v:?} is not a valid pins version component \
             (1–32 of [a-z0-9._-], no leading dot)"
        )))
    }
}

/// `{KERNEL_ORG_BASE}/linux-{version}.tar.xz` (version whitelisted first).
pub fn kernel_xz_url(version: &str) -> Result<String, SourcesError> {
    validate_source_component(version)?;
    Ok(format!("{KERNEL_ORG_BASE}/linux-{version}.tar.xz"))
}

/// `{SYSLINUX_ORG_BASE}/syslinux-{version}.tar.xz` (version whitelisted first).
pub fn syslinux_xz_url(version: &str) -> Result<String, SourcesError> {
    validate_source_component(version)?;
    Ok(format!("{SYSLINUX_ORG_BASE}/syslinux-{version}.tar.xz"))
}

                                                                                           
/// cumulative MiB to one decimal. PURE — separated from the fetch so it is unit-testable with no
/// network. A streaming fetcher ([`crate::HttpFetcher::get_with_progress`]) ticks this repeatedly;
/// a non-streaming one (the test maps) never reaches it (the fetch is atomic + no TTY under test).
pub fn report_fetch_progress(
    sink: &mut Vec<String>,
    name: &str,
    done_bytes: u64,
    total_bytes: u64,
) {
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    sink.push(format!(
        "  {name}  {:.1}/{:.1} MiB",
        mib(done_bytes),
        mib(total_bytes)
    ));
}

/// The tarball basename for the fetch banner (the URL's last path segment; the whole URL if none).
fn tarball_name(url: &str) -> &str {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(url)
}

                                                                                                   
/// TTY). Redraw at most once per 2-MiB bucket, but ALWAYS on the final tick (`done == total`, when a
/// `Content-Length` was known). Returns whether this `(done, total)` tick should redraw; advances
/// `last_bucket` in place. (When `total` is a running-length hint — no `Content-Length` — `done < total`
/// is always false, so every bucket-crossing still redraws; it never over-suppresses, only the rare
/// no-Content-Length case redraws slightly more often, which is harmless.)
fn progress_should_emit(done: u64, total: u64, last_bucket: &mut u64) -> bool {
    let bucket = done / (2 * 1024 * 1024);
    if bucket == *last_bucket && done < total {
        return false;
    }
    *last_bucket = bucket;
    true
}

                                                                                                  
/// sink (sha-gate against `expected_pin` + ceiling + full-consumption — nothing is retained, we
/// stage the compressed bytes, not the decoded tree) → stage atomically at `staged`. Staging is
/// the `DirStore::put` shape: refuse a pre-planted symlink at `staged` (`symlink_metadata`
/// no-follow), write a `NamedTempFile` IN the staging dir, `persist(rename)`. A failed
/// fetch/verify stages NOTHING — no partial `.tar.xz` for a later consume to trust. The sha is
/// checked TWICE (here + at consumption): verify-at-consumption does not trust the prime.
pub fn prime_source(
    fetch: &dyn Fetcher,
    url: &str,
    expected_pin: &str,
    decoded_ceiling: u64,
    staged: &Path,
) -> Result<(), SourcesError> {
                                                                                                
                                                                                                   
                                                                                                   
                                                                                                   
                           
    use std::io::IsTerminal;
    let name = tarball_name(url);
                                                                                                      
                                                                                                     
                                                                                 
    let tty = std::io::stderr().is_terminal();
    if tty {
        eprintln!("=== prime: fetching {name} ===");
    }
    let mut last_bucket = u64::MAX;
    let mut shown = false;
    let xz = fetch
        .get_with_progress(url, &mut |done, total| {
            if !tty || !progress_should_emit(done, total, &mut last_bucket) {
                return;
            }
            let mut sink = Vec::new();
            report_fetch_progress(&mut sink, name, done, total);
            if let Some(l) = sink.last() {
                eprint!("\r{l}   ");
                shown = true;
            }
        })
        .map_err(|e| SourcesError::Fetch(format!("{url}: {e}")))?;
    if tty && shown {
        eprintln!();
    }
                                                                                                   
    decode_verified_xz(
        &xz,
        ShaGate::ExpectPin(expected_pin),
        decoded_ceiling,
        &mut |_| {},
    )?;
                                                            
    match std::fs::symlink_metadata(staged) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(SourcesError::Stage(format!(
                "{} is a symlink — refusing to write through it (the prime stages a real file only)",
                staged.display()
            )));
        }
        Ok(_) => {}                            
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}              
        Err(e) => {
            return Err(SourcesError::Stage(format!(
                "symlink_metadata {}: {e}",
                staged.display()
            )));
        }
    }
    let parent = staged
        .parent()
        .ok_or_else(|| SourcesError::Stage(format!("{} has no parent dir", staged.display())))?;
    let tmp = tempfile::Builder::new()
        .prefix(".prime-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| SourcesError::Stage(format!("temp in {}: {e}", parent.display())))?;
    std::fs::write(tmp.path(), &xz).map_err(|e| SourcesError::Stage(format!("write temp: {e}")))?;
    tmp.persist(staged)
        .map_err(|e| SourcesError::Stage(format!("persist {}: {e}", staged.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A fake fetcher over a `url → bytes` map (Err = not-found, mirrors the apk 404 shape).
    struct MapFetcher(BTreeMap<String, Vec<u8>>);
    impl Fetcher for MapFetcher {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.0
                .get(url)
                .cloned()
                .ok_or_else(|| format!("no fixture for {url}"))
        }
    }

    /// Fixture: a valid single-stream `.xz` over `bytes` (liblzma's own writer — no committed
    /// binaries; the encoder is implementation-independent of the decode path under test).
    fn xz(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn sha_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn emit_mode_returns_the_buffer_sha_and_decoded_bytes() {
        let payload = vec![42u8; 100 * 1024];
        let fixture = xz(&payload);
        let mut seen = Vec::new();
        let v = decode_verified_xz(&fixture, ShaGate::Emit, 1024 * 1024, &mut |c| {
            seen.extend_from_slice(c)
        })
        .expect("a valid single-stream xz decodes in Emit mode");
        assert_eq!(
            v.xz_sha256,
            sha_hex(&fixture),
            "the digest is over the COMPRESSED bytes"
        );
        assert_eq!(v.decoded_bytes, payload.len() as u64);
        assert_eq!(seen, payload, "the sink saw exactly the decoded payload");
    }

    #[test]
    fn expect_pin_gates_before_any_decode() {
        let fixture = xz(b"payload");
        let wrong_pin = "0".repeat(64);
        let mut sink_called = false;
        let err = decode_verified_xz(
            &fixture,
            ShaGate::ExpectPin(&wrong_pin),
            1024 * 1024,
            &mut |_| sink_called = true,
        )
        .unwrap_err();
        assert!(
            matches!(err, SourcesError::ShaMismatch { .. }),
            "a wrong pin must be ShaMismatch, got: {err}"
        );
        assert!(
            !sink_called,
            "the gate precedes the decode — the sink must never run"
        );
    }

    #[test]
    fn expect_pin_accepts_the_matching_pin() {
        let payload = b"pinned payload".to_vec();
        let fixture = xz(&payload);
        let pin = sha_hex(&fixture);
        let mut seen = Vec::new();
        let v = decode_verified_xz(&fixture, ShaGate::ExpectPin(&pin), 1024 * 1024, &mut |c| {
            seen.extend_from_slice(c)
        })
        .expect("the matching pin passes the gate");
        assert_eq!(v.xz_sha256, pin);
        assert_eq!(seen, payload);
    }

    #[test]
    fn truncated_and_empty_xz_fail_via_the_decode_error() {
                                                                                                  
                                                                                                    
                                                                                                 
                                                                                
        let fixture = xz(&vec![9u8; 64 * 1024]);
        for bad in [&fixture[..fixture.len() / 2], &[][..]] {
            let err = decode_verified_xz(bad, ShaGate::Emit, 1024 * 1024, &mut |_| {}).unwrap_err();
            assert!(
                matches!(err, SourcesError::Decode(_)),
                "empty/truncated must be a Decode error, got: {err}"
            );
        }
    }

    #[test]
    fn decoded_ceiling_refuses_a_bomb() {
        let bomb = xz(&vec![0u8; 4 * 1024 * 1024]);                                  
        let ceiling = 1024 * 1024;         
        let err = decode_verified_xz(&bomb, ShaGate::Emit, ceiling, &mut |_| {}).unwrap_err();
        match &err {
            SourcesError::Ceiling { limit } => assert_eq!(*limit, ceiling),
            other => panic!("a 4 MiB bomb must trip the 1 MiB ceiling, got: {other}"),
        }
        assert!(
            err.to_string().contains("decompression-bomb guard"),
            "the ceiling text names the guard, got: {err}"
        );
    }

    #[test]
    fn a_multistream_suffix_is_refused() {
                                                                                                    
                                                                                                 
                                            
        let mut fixture = xz(b"genuine prefix");
        fixture.extend_from_slice(&xz(b"attacker suffix"));
        let err =
            decode_verified_xz(&fixture, ShaGate::Emit, 1024 * 1024, &mut |_| {}).unwrap_err();
        assert!(
            matches!(err, SourcesError::TrailingBytes { .. }),
            "a concatenated second stream must be TrailingBytes, got: {err}"
        );
        let text = err.to_string();
        assert!(
            text.contains("trailing byte") && text.contains("verify-bypass guard"),
            "the canonical diagnostic carries the probe tokens, got: {text}"
        );
    }

    #[test]
    fn plain_trailing_garbage_is_refused() {
        let mut fixture = xz(b"genuine prefix");
        fixture.extend_from_slice(b"garbage");
        let err =
            decode_verified_xz(&fixture, ShaGate::Emit, 1024 * 1024, &mut |_| {}).unwrap_err();
        assert!(
            matches!(err, SourcesError::TrailingBytes { .. }),
            "trailing garbage must be TrailingBytes, got: {err}"
        );
    }

                                                                                                                                                                                                                              

    /// Fixture: a tar over (path, contents) file entries (fixed mode/mtime — determinism is not
    /// under test here, containment is).
    fn tar_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// A fresh empty extraction dest inside `root` (the fn contract: exists + empty).
    fn fresh_dest(root: &Path) -> PathBuf {
        let dest = root.join("dest");
        std::fs::create_dir(&dest).unwrap();
        dest
    }

    /// A HOSTILE file entry written with raw header bytes — `tar::Builder::append_data` refuses
    /// `..`/absolute paths at build time, but an attacker's archive has no such courtesy, so the
    /// fixture bypasses `set_path` and writes the name field directly (path < 100 bytes).
    fn raw_hostile_entry(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        let name = path.as_bytes();
        assert!(
            name.len() < 100,
            "raw fixture name must fit the header field"
        );
        h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    #[test]
    fn extracts_a_single_topdir_archive_and_returns_the_inner_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = fresh_dest(tmp.path());
        let fixture = xz(&tar_with(&[("linux-9.9/README", b"the readme")]));
        let pin = sha_hex(&fixture);
        let (v, inner) = extract_verified_xz(&fixture, &pin, 1024 * 1024, &dest)
            .expect("a clean single-topdir archive extracts");
        assert_eq!(v.xz_sha256, pin);
        assert_eq!(inner, dest.join("linux-9.9"));
        assert_eq!(
            std::fs::read(inner.join("README")).unwrap(),
            b"the readme",
            "the extracted file carries the archive content"
        );
    }

    #[test]
    fn gate_failures_leave_dest_empty() {
                                                                                                       
                                                                                          
                                                                                                   
                                                                                                    
                                    
        let tar = tar_with(&[("linux-9.9/README", b"x")]);
        let good = xz(&tar);
        let wrong_pin = "0".repeat(64);
        let mut multi = good.clone();
        multi.extend_from_slice(&xz(b"suffix"));
        let multi_pin = sha_hex(&multi);
        let bomb = xz(&vec![0u8; 4 * 1024 * 1024]);
        let bomb_pin = sha_hex(&bomb);
        let cases: [(&[u8], &str, u64); 3] = [
            (&good, &wrong_pin, 1024 * 1024),                 
            (&multi, &multi_pin, 1024 * 1024),                                             
            (&bomb, &bomb_pin, 1024 * 1024),                                     
        ];
        for (bytes, pin, ceiling) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let dest = fresh_dest(tmp.path());
            extract_verified_xz(bytes, pin, ceiling, &dest)
                .expect_err("every gate failure refuses extraction");
            assert_eq!(
                std::fs::read_dir(&dest).unwrap().count(),
                0,
                "a refused extraction leaves dest EMPTY"
            );
        }
    }

    #[test]
    fn a_shape_refusal_also_leaves_dest_empty() {
                                                                                                     
                                                                                                  
                                             
        let tmp = tempfile::tempdir().unwrap();
        let dest = fresh_dest(tmp.path());
                                                                                            
        let fixture = xz(&tar_with(&[("loose-file", b"not in a topdir")]));
        let pin = sha_hex(&fixture);
        let err = extract_verified_xz(&fixture, &pin, 1024 * 1024, &dest).unwrap_err();
        assert!(matches!(err, SourcesError::Extract(_)), "got: {err}");
        assert_eq!(
            std::fs::read_dir(&dest).unwrap().count(),
            0,
            "a shape refusal must leave dest EMPTY (clean-on-refusal)"
        );
    }

    #[test]
    fn a_nonempty_dest_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = fresh_dest(tmp.path());
        std::fs::write(dest.join("stale"), b"leftover").unwrap();
        let fixture = xz(&tar_with(&[("linux-9.9/README", b"x")]));
        let err =
            extract_verified_xz(&fixture, &sha_hex(&fixture), 1024 * 1024, &dest).unwrap_err();
        assert!(
            matches!(err, SourcesError::Extract(_)),
            "a non-empty dest violates the fresh-dir invariant, got: {err}"
        );
    }

    #[test]
    fn hostile_members_cannot_escape() {
                                                                                                
                                                                                                  
                                                              
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();

                                                               
        let traversal = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, "linux-9.9/README", &b"x"[..])
                .unwrap();
            raw_hostile_entry(&mut b, "../evil", b"escaped");
            b.into_inner().unwrap()
        };
                                                           
        let abs_evil = outside.join("evil");
        let abs = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, "linux-9.9/README", &b"x"[..])
                .unwrap();
            raw_hostile_entry(&mut b, abs_evil.to_str().unwrap(), b"escaped");
            b.into_inner().unwrap()
        };
                                                                          
        let symlink = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_mtime(0);
            b.append_data(&mut h, "linux-9.9/README", &b"x"[..])
                .unwrap();
            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Symlink);
            l.set_size(0);
            l.set_mtime(0);
            b.append_link(&mut l, "linux-9.9/link", &outside).unwrap();
            let mut f = tar::Header::new_gnu();
            f.set_size(5);
            f.set_mode(0o644);
            f.set_mtime(0);
            b.append_data(&mut f, "linux-9.9/link/owned", &b"owned"[..])
                .unwrap();
            b.into_inner().unwrap()
        };

        for (name, tar_bytes) in [
            ("traversal", traversal),
            ("absolute", abs),
            ("symlink-through", symlink),
        ] {
            let case_root = tmp.path().join(format!("case-{name}"));
            std::fs::create_dir(&case_root).unwrap();
            let dest = fresh_dest(&case_root);
            let fixture = xz(&tar_bytes);
            let result = extract_verified_xz(&fixture, &sha_hex(&fixture), 1024 * 1024, &dest);
                                                                     
            assert!(
                !case_root.join("evil").exists(),
                "{name}: a traversal member must not land beside dest"
            );
            assert!(
                !abs_evil.exists(),
                "{name}: an absolute member must not land at its absolute path"
            );
            assert!(
                !outside.join("owned").exists(),
                "{name}: a write through a symlink member must not reach its target"
            );
            match &result {
                                                                                        
                Ok((_, inner)) => assert!(
                    inner.starts_with(&dest),
                    "{name}: inner dir stays inside dest"
                ),
                                                                                
                Err(_) => assert_eq!(
                    std::fs::read_dir(&dest).unwrap().count(),
                    0,
                    "{name}: a refused hostile archive leaves dest empty"
                ),
            }
        }
    }

    #[test]
    fn zero_or_two_topdirs_are_refused() {
        for (name, tar_bytes) in [
            ("empty", tar_with(&[])),
            (
                "two-topdirs",
                tar_with(&[("a/x", b"1".as_slice()), ("b/y", b"2".as_slice())]),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let dest = fresh_dest(tmp.path());
            let fixture = xz(&tar_bytes);
            let err =
                extract_verified_xz(&fixture, &sha_hex(&fixture), 1024 * 1024, &dest).unwrap_err();
            assert!(
                matches!(err, SourcesError::Extract(_)),
                "{name}: the single-topdir contract must refuse, got: {err}"
            );
        }
    }

    #[test]
    fn a_topdir_symlink_is_refused_and_dest_left_empty() {
                                                                                                    
                                                                                                    
                                                                                                   
        let tmp = tempfile::tempdir().unwrap();
        let dest = fresh_dest(tmp.path());
        let tar_bytes = {
            let mut b = tar::Builder::new(Vec::new());
            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Symlink);
            l.set_size(0);
            l.set_mtime(0);
            b.append_link(&mut l, "linux-9.9", "/etc").unwrap();
            b.into_inner().unwrap()
        };
        let fixture = xz(&tar_bytes);
        let err =
            extract_verified_xz(&fixture, &sha_hex(&fixture), 1024 * 1024, &dest).unwrap_err();
        assert!(matches!(err, SourcesError::Extract(_)), "got: {err}");
        assert_eq!(
            std::fs::read_dir(&dest).unwrap().count(),
            0,
            "a topdir-symlink refusal must leave dest empty"
        );
    }

                                                                                                                                                                                                                                                  

    fn fetcher_serving(url: &str, bytes: Vec<u8>) -> MapFetcher {
        let mut m = BTreeMap::new();
        m.insert(url.to_string(), bytes);
        MapFetcher(m)
    }

    #[test]
    fn prime_reports_a_banner_and_progress_through_the_sink() {
                                                                                        
        let mut events: Vec<String> = vec![];
        report_fetch_progress(
            &mut events,
            "linux-6.18.38.tar.xz",
            1024 * 1024,
            4 * 1024 * 1024,
        );
        assert!(
            events.iter().any(|e| e.contains("linux-6.18.38.tar.xz")),
            "{events:?}"
        );
        assert!(events.iter().any(|e| e.contains("MiB")), "{events:?}");
                                                                                          
        assert!(
            events
                .iter()
                .any(|e| e.contains("1.0") && e.contains("4.0")),
            "{events:?}"
        );
    }

    #[test]
    fn progress_throttle_emits_per_bucket_and_always_the_final_tick() {
                                                                                                   
                                                                                              
        let mib = |n: u64| n * 1024 * 1024;
        let total = mib(3);
        let mut last = u64::MAX;
        assert!(
            progress_should_emit(0, total, &mut last),
            "first tick emits"
        );
        assert!(
            progress_should_emit(mib(2), total, &mut last),
            "crossing into 2-MiB bucket 1 emits"
        );
        assert!(
            !progress_should_emit(mib(2) + 512 * 1024, total, &mut last),
            "same bucket, not final ⇒ skip"
        );
        assert!(
            progress_should_emit(total, total, &mut last),
            "the final tick (done == total) ALWAYS emits, even in the same bucket"
        );
    }

    #[test]
    fn get_with_progress_default_is_the_atomic_get_with_no_ticks() {
                                                                                                 
                                                                                             
        let url = "https://example/x.tar.xz";
        let f = fetcher_serving(url, b"abc".to_vec());
        let mut ticks = 0u32;
        let got = f.get_with_progress(url, &mut |_d, _t| ticks += 1).unwrap();
        assert_eq!(got, b"abc");
        assert_eq!(ticks, 0, "the default does not tick");
    }

    #[test]
    fn prime_stages_a_verified_tarball_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join("linux-9.9.tar.xz");
        let payload = xz(b"the kernel tarball");
        let pin = sha_hex(&payload);
        let url = "https://example/linux-9.9.tar.xz";
        let f = fetcher_serving(url, payload.clone());
        prime_source(&f, url, &pin, 1024 * 1024, &staged).expect("green prime");
        assert_eq!(std::fs::read(&staged).unwrap(), payload, "staged == served");
                                                                                 
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".prime-"))
            .collect();
        assert!(leftovers.is_empty(), "no .prime- temp left behind");
    }

    #[test]
    fn prime_refuses_a_sha_mismatch_and_stages_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join("linux-9.9.tar.xz");
        let url = "https://example/linux-9.9.tar.xz";
        let f = fetcher_serving(url, xz(b"attacker bytes"));
        let good_pin = sha_hex(&xz(b"the real tarball"));                              
        let err = prime_source(&f, url, &good_pin, 1024 * 1024, &staged).unwrap_err();
        assert!(
            matches!(err, SourcesError::ShaMismatch { .. }),
            "a mismatch must refuse, got: {err}"
        );
        assert!(!staged.exists(), "nothing staged on a mismatch");
    }

    #[test]
    fn prime_refuses_a_multistream_and_an_over_ceiling_body() {
        let tmp = tempfile::tempdir().unwrap();
        let url = "https://example/x.tar.xz";
                                                                                                  
                                                              
        let mut multi = xz(b"genuine");
        multi.extend_from_slice(&xz(b"suffix"));
        let staged_m = tmp.path().join("m.tar.xz");
        let f = fetcher_serving(url, multi.clone());
        let err = prime_source(&f, url, &sha_hex(&multi), 1024 * 1024, &staged_m).unwrap_err();
        assert!(
            matches!(err, SourcesError::TrailingBytes { .. }),
            "got: {err}"
        );
        assert!(!staged_m.exists());
                                                          
        let bomb = xz(&vec![0u8; 4 * 1024 * 1024]);
        let staged_b = tmp.path().join("b.tar.xz");
        let f2 = fetcher_serving(url, bomb.clone());
        let err2 = prime_source(&f2, url, &sha_hex(&bomb), 1024 * 1024, &staged_b).unwrap_err();
        assert!(matches!(err2, SourcesError::Ceiling { .. }), "got: {err2}");
        assert!(!staged_b.exists());
    }

    #[test]
    fn prime_refuses_a_preplanted_symlink_at_the_staged_path() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("victim");
        std::fs::write(&target, b"precious").unwrap();
        let staged = tmp.path().join("linux-9.9.tar.xz");
        std::os::unix::fs::symlink(&target, &staged).unwrap();
        let payload = xz(b"the kernel tarball");
        let pin = sha_hex(&payload);
        let url = "https://example/linux-9.9.tar.xz";
        let f = fetcher_serving(url, payload);
        let err = prime_source(&f, url, &pin, 1024 * 1024, &staged).unwrap_err();
        assert!(
            matches!(err, SourcesError::Stage(_)) && err.to_string().contains("symlink"),
            "a symlink at the staged path must be refused, got: {err}"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"precious",
            "the symlink target must be untouched"
        );
    }

    #[test]
    fn url_builders_reject_hostile_components() {
        for bad in ["../6.1", "6.1 x", "", ".6", "6/1", "A.B", &"9".repeat(33)] {
            assert!(
                kernel_xz_url(bad).is_err(),
                "kernel_xz_url must reject {bad:?}"
            );
            assert!(
                syslinux_xz_url(bad).is_err(),
                "syslinux_xz_url must reject {bad:?}"
            );
        }
        assert_eq!(
            kernel_xz_url("6.18.34").unwrap(),
            "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.34.tar.xz"
        );
        assert_eq!(
            syslinux_xz_url("6.04-pre1").unwrap(),
            "https://www.kernel.org/pub/linux/utils/boot/syslinux/Testing/6.04/syslinux-6.04-pre1.tar.xz"
        );
    }
}
