                                                                                               
//!
//! Accepted block types are exactly `PGP SIGNATURE` (detached `.sign`, exactly ONE block) and
//! `PGP PUBLIC KEY BLOCK` (keyring, ≥1 blocks). Only whitespace may appear outside/between blocks.
//! Armor headers (`Key: value` lines before the blank separator) are ignored wholesale; the CRC24
//! line is parsed and its value IGNORED (RFC 9580 deprecates it — the signature is the integrity
//! mechanism); any other `=`-leading line is malformed. LF and CRLF both accepted. Size caps are
//! checked FIRST, before any parsing.

use crate::limits::{KEYRING_MAX, SIGN_MAX};
use crate::Error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

const SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
const SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";
const KEY_BEGIN: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----";
const KEY_END: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----";

/// Decode a detached-signature input: exactly ONE `PGP SIGNATURE` armor block, nothing but
/// whitespace around it. Returns the binary packet bytes.
pub(crate) fn decode_sign(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() > SIGN_MAX {
        return Err(Error::Malformed("armor input exceeds size cap"));
    }
    let mut lines = split_lines(input).peekable();
    skip_blanks(&mut lines);
    let begin = lines
        .next()
        .ok_or(Error::Malformed("no armor block found"))?;
    if begin == KEY_BEGIN {
        return Err(Error::Malformed(
            "armor block type does not match entry point",
        ));
    }
    if begin != SIG_BEGIN {
        return Err(Error::Malformed("expected armor BEGIN line"));
    }
    let body = decode_block_after_begin(&mut lines, SIG_END)?;
    skip_blanks(&mut lines);
    match lines.next() {
        None => Ok(body),
        Some(l) if l == SIG_BEGIN || l == KEY_BEGIN => Err(Error::Malformed(
            "multiple armor blocks in detached signature input",
        )),
        Some(_) => Err(Error::Malformed(
            "non-whitespace bytes outside armor blocks",
        )),
    }
}

/// Decode a keyring input: a sequence (≥1) of `PGP PUBLIC KEY BLOCK` armor blocks, whitespace-only
/// between them (§5.0: one block per signer). Returns each block's binary packet bytes.
pub(crate) fn decode_keyring(input: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if input.len() > KEYRING_MAX {
        return Err(Error::Malformed("armor input exceeds size cap"));
    }
    let mut lines = split_lines(input).peekable();
    let mut blocks = Vec::new();
    loop {
        skip_blanks(&mut lines);
        let Some(line) = lines.next() else { break };
        if line == KEY_BEGIN {
            blocks.push(decode_block_after_begin(&mut lines, KEY_END)?);
        } else if line == SIG_BEGIN {
            return Err(Error::Malformed(
                "armor block type does not match entry point",
            ));
        } else if blocks.is_empty() {
            return Err(Error::Malformed("expected armor BEGIN line"));
        } else {
            return Err(Error::Malformed(
                "non-whitespace bytes outside armor blocks",
            ));
        }
    }
    if blocks.is_empty() {
        return Err(Error::Malformed("no armor block found"));
    }
    Ok(blocks)
}

/// Lines split on LF with one trailing CR stripped (LF + CRLF accepted, §5.1).
fn split_lines(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    input
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// RFC 4880 "blank": zero-length or whitespace-only (the LF separator is already consumed).
fn is_blank(line: &[u8]) -> bool {
    line.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r'))
}

fn skip_blanks<'a, I: Iterator<Item = &'a [u8]>>(lines: &mut core::iter::Peekable<I>) {
    while lines.peek().copied().is_some_and(is_blank) {
        lines.next();
    }
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Parse one armor block body after its BEGIN line was consumed: header section (ignored) → blank
/// separator → base64 body → optional CRC24 line → the matching END line. One-shot strict base64
/// decode of the whitespace-stripped body.
fn decode_block_after_begin<'a, I: Iterator<Item = &'a [u8]>>(
    lines: &mut I,
    end_line: &[u8],
) -> Result<Vec<u8>, Error> {
                                                                                              
                                                                              
    loop {
        let line = lines
            .next()
            .ok_or(Error::Malformed("unterminated armor block"))?;
        if is_blank(line) {
            break;
        }
        if !line.contains(&b':') {
            return Err(Error::Malformed("malformed armor header section"));
        }
    }
    let mut b64 = Vec::new();
    let mut saw_crc = false;
    loop {
        let line = lines
            .next()
            .ok_or(Error::Malformed("unterminated armor block"))?;
        if is_blank(line) {
                                                                                                    
                                                                                   
            continue;
        }
        if line == end_line {
            break;
        }
        if line.starts_with(b"-") {
                                                                               
            return Err(Error::Malformed("unexpected armor boundary line"));
        }
        if saw_crc {
            return Err(Error::Malformed("armor CRC line not followed by END"));
        }
        if let Some(rest) = line.strip_prefix(b"=") {
                                                                                                  
                                                                                              
                                                                                                   
                                                                                                    
                                     
            if rest.len() == 4 && rest.iter().copied().all(is_base64_char) {
                saw_crc = true;
                continue;
            }
            return Err(Error::Malformed("malformed armor '=' line"));
        }
        b64.extend(
            line.iter()
                .copied()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'\r')),
        );
    }
    STANDARD
        .decode(&b64)
        .map_err(|_| Error::Malformed("invalid base64 in armor body"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]
mod tests {
    use super::{decode_keyring, decode_sign};
    use crate::limits::{KEYRING_MAX, SIGN_MAX};
    use crate::Error;

    fn fixture(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
    }

    /// The real kernel.org `.sign` decodes; its `Comment:` armor headers are ignored wholesale.
    /// Decoded length + first byte ground-truthed independently (Python stdlib base64: 566 bytes,
    /// 0x89 = old-format tag-2 header).
    #[test]
    fn real_sign_decodes_with_headers_ignored() {
        let bin = decode_sign(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
        assert_eq!(bin.len(), 566);
        assert_eq!(bin.first(), Some(&0x89));
    }

    /// Both real pruned keyrings decode to exactly one block each (ground truth: Greg 2479 B /
    /// Sasha 1154 B binary, both starting 0x99 = old-format tag-6 header).
    #[test]
    fn real_keyrings_decode_to_one_block_each() {
        let greg = decode_keyring(&fixture("real/greg-pruned.asc")).unwrap();
        assert_eq!(greg.iter().map(Vec::len).collect::<Vec<_>>(), vec![2479]);
        assert_eq!(greg.first().and_then(|b| b.first()), Some(&0x99));
        let sasha = decode_keyring(&fixture("real/sasha-pruned.asc")).unwrap();
        assert_eq!(sasha.iter().map(Vec::len).collect::<Vec<_>>(), vec![1154]);
        assert_eq!(sasha.first().and_then(|b| b.first()), Some(&0x99));
    }

    /// The vendored-keyring input shape: concatenated per-signer blocks (§5.0).
    #[test]
    fn concatenated_keyring_decodes_to_two_blocks() {
        let mut cat = fixture("real/greg-pruned.asc");
        cat.extend_from_slice(&fixture("real/sasha-pruned.asc"));
        let blocks = decode_keyring(&cat).unwrap();
        assert_eq!(
            blocks.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![2479, 1154]
        );
    }

    /// CRLF line endings decode to the identical bytes as LF (§5.1).
    #[test]
    fn crlf_variant_decodes_identically() {
        let lf = fixture("gen/sig_a_1b_sha256.asc");
        let mut crlf = Vec::with_capacity(lf.len() * 2);
        for &b in &lf {
            if b == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(b);
        }
        assert_eq!(decode_sign(&crlf).unwrap(), decode_sign(&lf).unwrap());
    }

    /// The CRC24 line is parsed but its VALUE is ignored — a wrong CRC still decodes (§5.1: the
    /// signature is the integrity mechanism, not the checksum).
    #[test]
    fn crc_value_is_parsed_but_ignored() {
        let input: &[u8] =
            b"-----BEGIN PGP SIGNATURE-----\n\nSGVsbG8h\n=AAAA\n-----END PGP SIGNATURE-----\n";
        assert_eq!(decode_sign(input).unwrap(), b"Hello!".to_vec());
    }

                                                                       

    #[test]
    fn binary_input_is_malformed() {
        let bin = decode_sign(&fixture("real/linux-6.6.30.tar.sign")).unwrap();
        assert_eq!(
            decode_sign(&bin),
            Err(Error::Malformed("expected armor BEGIN line"))
        );
        assert_eq!(
            decode_keyring(&bin),
            Err(Error::Malformed("expected armor BEGIN line"))
        );
    }

    #[test]
    fn garbage_between_blocks_is_malformed() {
        let mut cat = fixture("real/greg-pruned.asc");
        cat.extend_from_slice(b"X\n");
        cat.extend_from_slice(&fixture("real/sasha-pruned.asc"));
        assert_eq!(
            decode_keyring(&cat),
            Err(Error::Malformed(
                "non-whitespace bytes outside armor blocks"
            ))
        );
    }

    #[test]
    fn bad_base64_is_malformed() {
        let input: &[u8] = b"-----BEGIN PGP SIGNATURE-----\n\n!!!!\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            decode_sign(input),
            Err(Error::Malformed("invalid base64 in armor body"))
        );
    }

    #[test]
    fn missing_end_line_is_malformed() {
        let sign = String::from_utf8(fixture("real/linux-6.6.30.tar.sign")).unwrap();
        let cut = sign.replace("-----END PGP SIGNATURE-----", "");
        assert_eq!(
            decode_sign(cut.as_bytes()),
            Err(Error::Malformed("unterminated armor block"))
        );
    }

    #[test]
    fn three_char_crc_line_is_malformed() {
        let input: &[u8] =
            b"-----BEGIN PGP SIGNATURE-----\n\nSGVsbG8h\n=ABC\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            decode_sign(input),
            Err(Error::Malformed("malformed armor '=' line"))
        );
    }

    /// BEGIN/END type must match the entry point: a keyring fed to `decode_sign` (and vice versa)
    /// is malformed, not silently accepted.
    #[test]
    fn wrong_block_type_for_entry_point_is_malformed() {
        assert_eq!(
            decode_sign(&fixture("real/greg-pruned.asc")),
            Err(Error::Malformed(
                "armor block type does not match entry point"
            ))
        );
        assert_eq!(
            decode_keyring(&fixture("real/linux-6.6.30.tar.sign")),
            Err(Error::Malformed(
                "armor block type does not match entry point"
            ))
        );
    }

    #[test]
    fn two_signature_blocks_are_malformed() {
        let mut two = fixture("real/linux-6.6.30.tar.sign");
        two.extend_from_slice(&fixture("real/linux-6.6.30.tar.sign"));
        assert_eq!(
            decode_sign(&two),
            Err(Error::Malformed(
                "multiple armor blocks in detached signature input"
            ))
        );
    }

    /// Caps are checked FIRST — before any line scanning.
    #[test]
    fn over_cap_input_is_malformed() {
        let sign_big = vec![b'\n'; SIGN_MAX + 1];
        assert_eq!(
            decode_sign(&sign_big),
            Err(Error::Malformed("armor input exceeds size cap"))
        );
        let key_big = vec![b'\n'; KEYRING_MAX + 1];
        assert_eq!(
            decode_keyring(&key_big),
            Err(Error::Malformed("armor input exceeds size cap"))
        );
    }

    /// The blank header/body separator is required (gpg always emits it); base64 directly after
    /// BEGIN is outside the whitelist.
    #[test]
    fn non_header_line_before_blank_is_malformed() {
        let input: &[u8] =
            b"-----BEGIN PGP SIGNATURE-----\nSGVsbG8h\n\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            decode_sign(input),
            Err(Error::Malformed("malformed armor header section"))
        );
    }

    #[test]
    fn base64_after_crc_is_malformed() {
        let input: &[u8] = b"-----BEGIN PGP SIGNATURE-----\n\nSGVsbG8h\n=AAAA\nSGVsbG8h\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            decode_sign(input),
            Err(Error::Malformed("armor CRC line not followed by END"))
        );
    }

    /// A boundary line that is not THIS block's END (nested BEGIN, mismatched END type) is named,
    /// not fed to base64.
    #[test]
    fn mismatched_boundary_inside_block_is_malformed() {
        let input: &[u8] =
            b"-----BEGIN PGP SIGNATURE-----\n\nSGVsbG8h\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(
            decode_sign(input),
            Err(Error::Malformed("unexpected armor boundary line"))
        );
    }

    #[test]
    fn empty_and_whitespace_input_has_no_block() {
        assert_eq!(
            decode_sign(b""),
            Err(Error::Malformed("no armor block found"))
        );
        assert_eq!(
            decode_keyring(b"\n  \n"),
            Err(Error::Malformed("no armor block found"))
        );
    }
}
