                                                                                               
//! decides whether an entry is armed for growfs, so the every-entry `x-systemd.growfs` strip edits
//! the RAW /etc/fstab exactly where the tool arms. glibc `getmntent` splits fields on `{b' ', b'\t'}`
//! and `decode_name`s each field (five escapes); systemd's `fstab_filter_options` then runs its
//! non-escaped-comma option scan over the DECODED text. This module models both stages and carries
//! each decoded option word's RAW byte range so the edit maps back over the raw file byte-for-byte.
//! Pure: `Result<_, String>` and std only, no reclaim types, no I/O. The write/refuse orchestration
//! that drives `edit_fstab`/`verify_fstab_edit` across the target read/write is in `neutralize.rs`.

/// The heredoc terminator for the fstab write. `edit_fstab` refuses any /etc/fstab that contains a
                                                                                  
pub(super) const FSTAB_HEREDOC_MARKER: &str = "ORCHARD_RECLAIM_FSTAB";

                                                                                                    
  
                                                                                                 
                                                                                             
                                                                                                    
                                                                                             
                                                                                                      
                                                                                              

const GROWFS_TOKEN: &str = "x-systemd.growfs";

/// glibc `getmntent` reads each line through a fixed 4096-byte `fgets` buffer (`misc/mntent.c`:
/// `char buffer[4096]`; `misc/mntent_r.c:126` `fgets(buffer, 4096, stream)` keeps at most 4095 chars
/// INCLUDING the `\n`). A body of exactly 4095 bytes is delivered COMPLETE — only its `\n` lands in the
/// discard loop (`mntent_r.c:138-145`, which consumes and forgets the over-long tail; it does NOT
/// re-parse it as a line). Semantic truncation of the body begins at 4096: the option scan then runs
/// over a prefix while this module models the whole line — the one non-grammar property of the read,
                                                                                                     
                                                                                                      
const GETMNTENT_LINE_CAP: usize = 4096;

/// systemd's `fstab_filter_options` arming match on ONE decoded option word: `startswith(word, name)`
/// then the next byte is `\0` (end) or `=` (systemd v252 `src/shared/fstab-util.c`). The bare token
/// AND `x-systemd.growfs=<value>` both arm; a longer token like `x-systemd.growfsX` does not; a
                                                                                         
fn word_arms(word: &[u8]) -> bool {
    match word.strip_prefix(GROWFS_TOKEN.as_bytes()) {
        Some(rest) => rest.is_empty() || rest[0] == b'=',
        None => false,
    }
}

                                                                                                   
                                                                                            
/// deleted), so it is test-only rather than crate-visible `pub`.
#[cfg(test)]
fn option_arms_growfs(opt: &str) -> bool {
    word_arms(opt.as_bytes())
}

/// glibc `getmntent`'s `decode_name` (`misc/mntent_r.c:72-114`, glibc 2.36): rewrite five escape
/// sequences, each to one output byte, in glibc's check order (`\\` is tested BEFORE `\134`). Returns
/// the decoded bytes and, per decoded byte, the RAW byte range `[start, end)` it came from — so an
/// edit computed on the decoded text (the bytes systemd's option scan actually sees) maps back to the
                                                                                                     
/// a backslash, so only `\\`/`\134` change the following comma's escape state.
fn decode_field(raw: &[u8]) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut out = Vec::new();
    let mut prov = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let rest = &raw[i..];
        let (byte, len) = if rest.starts_with(b"\\040") {
            (b' ', 4)
        } else if rest.starts_with(b"\\011") {
            (b'\t', 4)
        } else if rest.starts_with(b"\\012") {
            (b'\n', 4)
        } else if rest.starts_with(b"\\\\") {
            (b'\\', 2)
        } else if rest.starts_with(b"\\134") {
            (b'\\', 4)
        } else {
            (raw[i], 1)
        };
        out.push(byte);
        prov.push((i, i + len));
        i += len;
    }
    (out, prov)
}

/// The option words of a RAW options field, matching the tool's pipeline: glibc `decode_field` then
/// systemd's non-escaped-comma split (`strcspn(end, ",\\")` + the two-byte backslash skip, run over
/// the DECODED bytes). Each word is `(arms, raw_range)`: whether the decoded word arms growfs, and the
/// RAW byte range it occupies (so the strip removes exactly the raw bytes). A pre-existing empty word
/// is preserved with an empty raw range (I-3). Split positions are decoded commas that map to raw
/// commas (ASCII, char boundaries), so the raw slices are UTF-8-safe.
fn option_words(raw: &str) -> Vec<(bool, std::ops::Range<usize>)> {
    let (decoded, prov) = decode_field(raw.as_bytes());
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < decoded.len() {
        match decoded[i] {
            b'\\' => i += 2,                                                       
            b',' => {
                ranges.push((start, i));
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    ranges.push((start, decoded.len()));
    ranges
        .into_iter()
        .map(|(a, b)| {
            let b = b.min(decoded.len());
            let a = a.min(b);
            let arms = word_arms(&decoded[a..b]);
            let raw_range = if a < b {
                prov[a].0..prov[b - 1].1
            } else {
                let p = if a < prov.len() { prov[a].0 } else { raw.len() };
                p..p
            };
            (arms, raw_range)
        })
        .collect()
}

                                                                                               
                                                                                                 
/// pre-existing empty word is preserved and only a removal-introduced empty is dropped (I-3).
fn strip_growfs_options(raw: &str) -> String {
    option_words(raw)
        .into_iter()
        .filter(|(arms, _)| !arms)
        .map(|(_, r)| &raw[r])
        .collect::<Vec<_>>()
        .join(",")
}

                                                                                                    
pub(super) fn options_carry_no_token(raw: &str) -> bool {
    option_words(raw).iter().all(|(arms, _)| !arms)
}

/// The byte spans of the fields in one fstab line body, glibc `getmntent`'s field model: fields are
/// separated by ASCII space and TAB ONLY (`{b' ', b'\t'}`), never CR/FF/VT/newline or a Unicode
/// whitespace char (glibc `misc/mntent_r.c` scans over `" \t"`). Using the host's wider whitespace
/// predicate here shifts the options field on a CR/FF-bearing entry and admits an armed line as
                           
fn fields_with_spans(line: &str) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let sep = |c: u8| c == b' ' || c == b'\t';
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && sep(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        while i < b.len() && !sep(b[i]) {
            i += 1;
        }
        spans.push((start, i));
    }
    spans
}

/// glibc `__hasmntopt` (misc/mntent_r.c:267-286) over the DECODED mnt_opts: the option name matches at
/// a word boundary — preceded by the start or `,`, followed by the end, `=` or `,`. Only the
                                            
fn hasmntopt_ignore(decoded_opts: &[u8]) -> bool {
    const IGNORE: &[u8] = b"ignore";
    decoded_opts
        .windows(IGNORE.len())
        .enumerate()
        .any(|(p, w)| {
            w == IGNORE && (p == 0 || decoded_opts[p - 1] == b',') && {
                let after = p + IGNORE.len();
                after == decoded_opts.len()
                    || decoded_opts[after] == b'='
                    || decoded_opts[after] == b','
            }
        })
}

/// Parse one fstab line BODY (no trailing newline) as a glibc mount entry: skip leading `{b' ',b'\t'}`,
/// a `#` comment or a blank line is not an entry (None), and a line with no field-1 (a lone token) has
/// no mountpoint (None). Returns the glibc-DECODED mountpoint (field 1, for the root-entry check,
                                                                                                    
/// parses a <4-field line as an entry with an EMPTY `mnt_opts` that cannot arm, so its mountpoint must
/// still be counted for the exactly-one-root detector even though there is no options field to strip
                                                                                                    
                  
fn entry_fields(body: &str) -> Option<(String, Option<std::ops::Range<usize>>)> {
    let b = body.as_bytes();
    let mut j = 0usize;
    while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
        j += 1;
    }
    if j >= b.len() || b[j] == b'#' {
        return None;
    }
    let spans = fields_with_spans(body);
                                                                                                  
    let (ms, me) = *spans.get(1)?;
                                                                                                
                                                                                                     
                                                                                                         
                                                              
    if let (Some(&(ts, te)), Some(&(os, oe))) = (spans.get(2), spans.get(3))
        && decode_field(&b[ts..te]).0.as_slice() == b"autofs"
        && hasmntopt_ignore(&decode_field(&b[os..oe]).0)
    {
        return None;
    }
    let (decoded_mnt, _) = decode_field(&b[ms..me]);
    let opt_span = spans.get(3).map(|&(s, e)| s..e);
    Some((String::from_utf8_lossy(&decoded_mnt).into_owned(), opt_span))
}

/// Split `content` into lines that KEEP their terminator, as `(body, line_with_terminator)` pairs, so
                                                                                                     
                                                                                  
fn lines_with_terminators(content: &str) -> impl Iterator<Item = (&str, &str)> {
    content.split_inclusive('\n').map(|line| {
                                                                                                
                                                                                                    
                                                                                          
        let term = usize::from(line.ends_with('\n'));
        (&line[..line.len() - term], line)
    })
}

                                                                                                    
                                                                                                   
/// entry (glibc-decoded mountpoint `/`); zero or more than one refuses fail-closed — the misparse /
/// empty-or-truncated-fstab detector the root-only predecessor carried, which an already-absent return
                                                                                                     
                                                                                       
pub(super) fn edit_fstab(content: &str) -> Result<Option<String>, String> {
                                                                                                      
                                                                                                       
                                                                                                              
                                                                                                    
                                                 
    if !content.is_empty() && !content.ends_with('\n') {
        return Err(
            "fstab content is not newline-terminated — the heredoc terminator would glue to the last \
             line and never fire; refusing fail-closed"
                .to_string(),
        );
    }
    let mut root_count = 0usize;
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut pos = 0usize;
    for (body, line) in lines_with_terminators(content) {
                                                                                                
                                                                                                       
                                                                                                          
                                                                                                      
                                                                                                       
                                                                         
        if body.len() >= GETMNTENT_LINE_CAP {
            return Err(format!(
                "an /etc/fstab line is {} bytes; glibc getmntent reads only the first {} of a line and \
                 parses a truncated prefix (a token split across the cut under-strips) — refusing \
                 fail-closed",
                body.len(),
                GETMNTENT_LINE_CAP
            ));
        }
        if let Some((mnt, opt_span)) = entry_fields(body) {
            if mnt == "/" {
                root_count += 1;
            }
                                                                                                       
                     
            if let Some(opt_span) = opt_span {
                let raw_opts = &body[opt_span.clone()];
                if !options_carry_no_token(raw_opts) {
                    let stripped = strip_growfs_options(raw_opts);
                    if stripped.is_empty() {
                        return Err(format!(
                            "stripping {GROWFS_TOKEN} would leave an empty options field on entry \
                             {body:?} — refusing fail-closed"
                        ));
                    }
                    edits.push((pos + opt_span.start, pos + opt_span.end, stripped));
                }
            }
        }
        pos += line.len();
    }
    if root_count != 1 {
        return Err(format!(
            "the fstab has {root_count} root (/) entries, expected exactly one — refusing fail-closed; \
             a misparse or an empty/truncated fstab must not read as already-absent"
        ));
    }
    if edits.is_empty() {
        return Ok(None);
    }
    let mut out = String::with_capacity(content.len() + 1);
    let mut cur = 0usize;
    for (s, e, rep) in edits {
        out.push_str(&content[cur..s]);
        out.push_str(&rep);
        cur = e;
    }
    out.push_str(&content[cur..]);
                                                                                                   
                                                                                                      
                                                                                                       
                                                                                                      
                                                                                                   
                                                                                                      
                                                                           
    if lines_with_terminators(&out).any(|(body, _)| body == FSTAB_HEREDOC_MARKER) {
        return Err(format!(
            "an /etc/fstab line equals the heredoc terminator {FSTAB_HEREDOC_MARKER:?} — refusing; \
             the write would truncate the file"
        ));
    }
    Ok(Some(out))
}

                                                                                               
                                                                                                   
                                                                                                  
                                                                                                   
/// words; and every other byte — non-entry lines, untokened entries, terminators — is identical.
pub(super) fn verify_fstab_edit(original: &str, reread: &str) -> Result<(), String> {
    let o_lines: Vec<(&str, &str)> = lines_with_terminators(original).collect();
    let r_lines: Vec<(&str, &str)> = lines_with_terminators(reread).collect();
    if o_lines.len() != r_lines.len() {
        return Err("fstab line count changed — not the original minus the token".into());
    }
    let mut root_count = 0usize;
    for (i, (&(o_body, o), &(r_body, r))) in o_lines.iter().zip(r_lines.iter()).enumerate() {
        let Some((o_mnt, o_opts_span)) = entry_fields(o_body) else {
                                                                                             
                          
            if o != r {
                return Err(format!("non-entry fstab line {i} changed: {o:?} -> {r:?}"));
            }
            continue;
        };
                                                                                                      
                                                                                                
                                                                                                        
                                     
        if o_mnt == "/" {
            root_count += 1;
        }
        let carried = match &o_opts_span {
            Some(span) => !options_carry_no_token(&o_body[span.clone()]),
            None => false,
        };
        if !carried {
                                                                                              
                          
            if o != r {
                return Err(format!("unrelated fstab line {i} changed: {o:?} -> {r:?}"));
            }
            continue;
        }
                                                                                                     
                                                                                   
        let o_span = o_opts_span.expect("carried implies an options span");
        let o_opts = &o_body[o_span.clone()];
        let (_r_mnt, r_opts_span) = entry_fields(r_body).ok_or_else(|| {
            format!("edited fstab line {i} is no longer a parseable entry: {r:?}")
        })?;
        let r_span = r_opts_span
            .ok_or_else(|| format!("edited fstab line {i} lost its options field: {r:?}"))?;
        if !options_carry_no_token(&r_body[r_span]) {
            return Err(format!(
                "fstab line {i} still carries {GROWFS_TOKEN} after the edit — verification \
                 is the ABSENCE of the arming, not a diff"
            ));
        }
                                                                                             
                                               
        let expected_body = format!(
            "{}{}{}",
            &o_body[..o_span.start],
            strip_growfs_options(o_opts),
            &o_body[o_span.end..]
        );
        let expected = format!("{}{}", expected_body, &o[o_body.len()..]);
        if r != expected {
            return Err(format!(
                "fstab line {i} is not the original minus only {GROWFS_TOKEN} occurrences: \
                 {r:?} vs expected {expected:?}"
            ));
        }
    }
    if root_count != 1 {
                                                                                                 
                                                              
        return Err(format!(
            "the original fstab has {root_count} root () entries, expected exactly one"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

                                          
    const ORIG_TWICE: &str = "rw,x-systemd.growfs,discard,errors=remount-ro,x-systemd.growfs";
    const E2_MINUS_ONE: &str = "rw,discard,errors=remount-ro,x-systemd.growfs";
    const E3_ALL_REMOVED: &str = "rw,discard,errors=remount-ro";
    const E4_SINGLE: &str = "rw,discard,errors=remount-ro,x-systemd.growfs";

    #[test]
    fn strip_removes_every_occurrence_and_verify_is_absence() {
                                                         
        assert_eq!(strip_growfs_options(ORIG_TWICE), E3_ALL_REMOVED);
        assert_eq!(strip_growfs_options(E4_SINGLE), E3_ALL_REMOVED);
                                                                                 
        assert!(!options_carry_no_token(E2_MINUS_ONE));
        assert!(options_carry_no_token(E3_ALL_REMOVED));
    }

    fn fstab(root_opts: &str) -> String {
        format!(
            "# /etc/fstab: static file system information\n\
             PARTUUID=b69af6fb-08dd-4525-acb0-1f870e0f0221 / ext4 {root_opts} 0 1\n\
             PARTUUID=cafe-01 /boot/efi vfat umask=0077 0 1\n"
        )
    }

    #[test]
    fn edit_fstab_strips_the_tokened_entry_and_preserves_untokened_lines() {
        for orig_opts in [ORIG_TWICE, E4_SINGLE] {
            let orig = fstab(orig_opts);
            let edited = edit_fstab(&orig).unwrap().unwrap();
            assert_eq!(edited, fstab(E3_ALL_REMOVED));
            verify_fstab_edit(&orig, &edited).unwrap();
        }
    }

    #[test]
    fn verify_refuses_the_minus_one_edit_and_mangled_writes() {
        let orig = fstab(ORIG_TWICE);
                                                                                               
                                                                             
        let minus_one = fstab(E2_MINUS_ONE);
        let e = verify_fstab_edit(&orig, &minus_one).unwrap_err();
        assert!(e.contains("ABSENCE"), "{e}");
                                                          
        let mangled = fstab(E3_ALL_REMOVED).replace("/boot/efi", "/boot/efi2");
        assert!(verify_fstab_edit(&orig, &mangled).is_err());
                                                                                         
        let overstripped = fstab("rw,errors=remount-ro");
        assert!(verify_fstab_edit(&orig, &overstripped).is_err());
    }

    #[test]
    fn edit_fstab_requires_exactly_one_root_and_empty_options_refuse() {
                                                                                                       
                                                                                                
                                                                              
        assert!(edit_fstab(&fstab(E3_ALL_REMOVED)).unwrap().is_none());
        assert!(edit_fstab("PARTUUID=a / ext4 rw 0 1\n").unwrap().is_none());
        assert!(edit_fstab("").is_err(), "empty fstab: zero root entries");
        assert!(
            edit_fstab("PARTUUID=x /data ext4 rw 0 2\n").is_err(),
            "no root entry"
        );
        let two_root = "PARTUUID=a / ext4 rw 0 1\nPARTUUID=b / ext4 rw 0 1\n";
        assert!(edit_fstab(two_root).is_err(), "two root entries");
                                                                                             
        assert!(edit_fstab(&fstab("x-systemd.growfs")).is_err());
    }

    #[test]
    fn cr_in_a_pre_options_field_does_not_shift_the_options_field() {
                                                                                                  
                                                                                                      
                                                                                                   
                                                                    
        assert!(!options_carry_no_token("rw,discard,x-systemd.growfs"));
        let orig = "# /etc/fstab\nLABEL=a\rb / ext4 rw,discard,x-systemd.growfs 0 1\n";
        let edited = edit_fstab(orig)
            .unwrap()
            .expect("the CR-bearing root entry carries the token");
        assert_eq!(edited, "# /etc/fstab\nLABEL=a\rb / ext4 rw,discard 0 1\n");
        verify_fstab_edit(orig, &edited).unwrap();
    }

    #[test]
    fn glibc_decode_fuses_an_escaped_backslash_before_the_token_no_over_strip() {
                                                                                                 
                                                                                                     
                                                                                                   
                          
        for opts in [
            "rw,foo\\134,x-systemd.growfs",
            "rw,foo\\\\,x-systemd.growfs",
        ] {
            assert!(
                options_carry_no_token(opts),
                "{opts} must not arm (decode fuses the comma)"
            );
            assert_eq!(
                strip_growfs_options(opts),
                opts,
                "{opts} must be left byte-identical"
            );
        }
                                                                                                    
                                        
        assert_eq!(
            strip_growfs_options("rw,foo\\134x,x-systemd.growfs"),
            "rw,foo\\134x"
        );
    }

    #[test]
    fn value_form_no_arms_and_strips() {
                                                                                                       
                       
        assert!(option_arms_growfs("x-systemd.growfs=no"));
        assert_eq!(
            strip_growfs_options("rw,x-systemd.growfs=no,discard"),
            "rw,discard"
        );
    }

    #[test]
    fn edit_fstab_refuses_a_heredoc_terminator_collision() {
                                                                                                 
        let orig = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\nORCHARD_RECLAIM_FSTAB\n";
        let e = edit_fstab(orig).unwrap_err();
        assert!(e.contains("heredoc terminator"), "{e}");
    }

    #[test]
    fn crlf_four_field_entry_is_not_over_stripped() {
                                                                                                     
                                                                                                      
                                                                                                      
        assert!(options_carry_no_token("rw,x-systemd.growfs\r"));
                                                                                                    
                                                                                                   
        let orig = "PARTUUID=aa / ext4 rw 0 1\nPARTUUID=bb /data ext4 rw,x-systemd.growfs\r\n";
        assert!(edit_fstab(orig).unwrap().is_none());
    }

    #[test]
    fn eqvalue_form_strips_and_verifies_like_the_bare_token() {
                                                                                                  
                                                                                                 
                                                                                                    
                                                                                                  
        assert!(!options_carry_no_token("rw,x-systemd.growfs=1,discard"));
        assert_eq!(
            strip_growfs_options("rw,x-systemd.growfs=1,discard"),
            "rw,discard"
        );
        let orig = fstab("rw,x-systemd.growfs=1,discard");
        let edited = edit_fstab(&orig)
            .unwrap()
            .expect("a =value root line is edited, not reported already-absent");
        assert_eq!(edited, fstab("rw,discard"));
        verify_fstab_edit(&orig, &edited).unwrap();
                                                                             
        assert!(verify_fstab_edit(&orig, &orig).is_err());
    }

                                                                                                
                                                                                                   
                                                                                             

    #[test]
    fn strips_every_entry_not_only_the_root() {
                                                                                             
                                                                                        
        let orig = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                    PARTUUID=bb /data ext4 defaults,x-systemd.growfs 0 2\n";
        let edited = edit_fstab(orig)
            .unwrap()
            .expect("both entries carry the token");
        assert_eq!(
            edited,
            "PARTUUID=aa / ext4 rw 0 1\n\
             PARTUUID=bb /data ext4 defaults 0 2\n"
        );
        verify_fstab_edit(orig, &edited).unwrap();
    }

    #[test]
    fn non_escaped_comma_split_both_directions() {
                                                                                              
                                                                                                     
        assert_eq!(
            strip_growfs_options("bind,foo\\,x-systemd.growfs"),
            "bind,foo\\,x-systemd.growfs"
        );
                                                                                                 
                                                                                               
                                                                                                      
        assert_eq!(
            strip_growfs_options("rw,x-systemd.growfs=a\\,b,discard"),
            "rw,discard"
        );
    }

    #[test]
    fn glibc_model_does_not_octal_decode_the_token() {
                                                                                                
                                                                                                     
                                                                          
        assert!(!option_arms_growfs("x-systemd.growf\\163"));
        assert_eq!(
            strip_growfs_options("rw,x-systemd.growf\\163"),
            "rw,x-systemd.growf\\163"
        );
    }

    #[test]
    fn empty_option_word_is_preserved_i3() {
                                                                                                 
                                                                                                
        assert_eq!(strip_growfs_options("bind,,x-systemd.growfs"), "bind,");
    }

    #[test]
    fn bare_equals_value_form_arms_and_strips() {
                                                                              
        assert!(option_arms_growfs("x-systemd.growfs="));
        assert_eq!(
            strip_growfs_options("rw,x-systemd.growfs=,discard"),
            "rw,discard"
        );
    }

    #[test]
    fn entry_shapes_leading_ws_tab_and_short_lines_all_strip() {
                                                                                                   
                                                                                                    
                                                                                                
        let orig = "  PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                    PARTUUID=bb\t/srv\text4\tdefaults,x-systemd.growfs\n\
                    PARTUUID=cc /opt ext4 rw,x-systemd.growfs 0\n\
                    # x-systemd.growfs here is a comment, not an entry\n";
        let edited = edit_fstab(orig)
            .unwrap()
            .expect("three entries carry the token");
        assert_eq!(
            edited,
            "  PARTUUID=aa / ext4 rw 0 1\n\
             PARTUUID=bb\t/srv\text4\tdefaults\n\
             PARTUUID=cc /opt ext4 rw 0\n\
             # x-systemd.growfs here is a comment, not an entry\n"
        );
        verify_fstab_edit(orig, &edited).unwrap();
    }

    #[test]
    fn verify_refuses_a_surviving_non_root_token() {
                                                                                               
                                                                                       
        let orig = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                    PARTUUID=bb /data ext4 defaults,x-systemd.growfs 0 2\n";
        let non_root_survives = "PARTUUID=aa / ext4 rw 0 1\n\
                                 PARTUUID=bb /data ext4 defaults,x-systemd.growfs 0 2\n";
        assert!(verify_fstab_edit(orig, non_root_survives).is_err());
    }

                                                                                                    

    #[test]
    fn edit_fstab_refuses_only_lines_glibc_would_truncate() {
                                                                                                     
                                                                                                       
                                      
        let fixed =
            "PARTUUID=aa / ext4 ".len() + "rw,".len() + ",x-systemd.growfs".len() + " 0 1".len();
        let line = |body_len: usize| {
            format!(
                "PARTUUID=aa / ext4 rw,{},x-systemd.growfs 0 1\n",
                "a".repeat(body_len - fixed)
            )
        };
                                                                                          
        let ok = line(GETMNTENT_LINE_CAP - 1);
        assert_eq!(ok.trim_end().len(), GETMNTENT_LINE_CAP - 1);
        let edited = edit_fstab(&ok).unwrap().expect("a 4095-byte line strips");
        assert!(
            !edited.contains(",x-systemd.growfs"),
            "the 4095-byte line strips its token"
        );
                                                        
        let over = line(GETMNTENT_LINE_CAP);
        assert_eq!(over.trim_end().len(), GETMNTENT_LINE_CAP);
        let e = edit_fstab(&over).unwrap_err();
        assert!(e.contains("under-strips") && e.contains("truncat"), "{e}");
    }

    #[test]
    fn edit_fstab_refuses_content_without_a_trailing_newline() {
                                                                                                         
                                                                                                       
        let e = edit_fstab("PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1").unwrap_err();
        assert!(e.contains("newline"), "{e}");
                                                                                             
        assert!(edit_fstab("").unwrap_err().contains("root"));
    }

    #[test]
    fn heredoc_collision_uses_the_cr_preserving_splitter() {
                                                                                                       
                                                                                                         
                                                                                                      
                               
        let cr = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\nORCHARD_RECLAIM_FSTAB\r\n";
        let edited = edit_fstab(cr)
            .unwrap()
            .expect("the root entry carries the token");
        assert!(
            edited.contains("ORCHARD_RECLAIM_FSTAB\r"),
            "the CR marker line is preserved: {edited:?}"
        );
                                                                    
        let exact = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\nORCHARD_RECLAIM_FSTAB\n";
        assert!(
            edit_fstab(exact)
                .unwrap_err()
                .contains("heredoc terminator"),
            "the exact marker line still refuses"
        );
    }

    #[test]
    fn a_three_field_root_entry_is_counted_not_false_refused() {
                                                                                                        
                                                                                                    
                                                     
        let orig = "PARTUUID=aa / ext4\nPARTUUID=bb /data ext4 rw,x-systemd.growfs 0 2\n";
        let edited = edit_fstab(orig)
            .unwrap()
            .expect("the /data entry carries the token");
        assert_eq!(
            edited,
            "PARTUUID=aa / ext4\nPARTUUID=bb /data ext4 rw 0 2\n"
        );
        verify_fstab_edit(orig, &edited).unwrap();
                                                                                               
        assert!(edit_fstab("PARTUUID=aa / ext4\n").unwrap().is_none());
                                                                                                     
        assert!(edit_fstab("PARTUUID=aa / ext4\nPARTUUID=bb / ext4\n").is_err());
    }

    #[test]
    fn autofs_ignore_entry_is_not_stripped_or_counted() {
                                                                                                 
                                                                                                        
                                                                           
        let orig = "PARTUUID=aa / ext4 rw,x-systemd.growfs 0 1\n\
                    /dev/auto / autofs ignore,x-systemd.growfs 0 0\n";
        let edited = edit_fstab(orig)
            .unwrap()
            .expect("the real ext4 root carries the token");
        assert_eq!(
            edited,
            "PARTUUID=aa / ext4 rw 0 1\n\
             /dev/auto / autofs ignore,x-systemd.growfs 0 0\n",
            "the real root strips; the autofs+ignore line is untouched and not a second root"
        );
        verify_fstab_edit(orig, &edited).unwrap();
                                                                                             
        assert!(!hasmntopt_ignore(b"ignoreme,rw"));
        assert!(hasmntopt_ignore(b"rw,ignore"));
        assert!(hasmntopt_ignore(b"ignore=1,rw"));
    }
}
