                                                                                                 
//! mini-fuzzer over the real fixtures, through both public entry points.
//!
                                                                                                
//! fixed iteration budget — it is a regression tripwire, NOT a coverage claim. A real coverage-
//! guided fuzz (libFuzzer/cargo-fuzz) is a named DEV-HOST check, deliberately not CI-claimed.
//!
//! The asserted property: across every truncation and every mutation, the entry points return a
//! structured `Err` (or a legitimate `Ok` for an unlucky-benign mutation) and the count of
//! `Error::ParserPanic` is ZERO — no panic ever reaches the boundary, no abort kills the process.

use cashew::{DetachedVerifier, Error, Fingerprint, Keyring};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_NOW: u64 = 1_781_100_000;
const GREG_PIN: &str = "647F28654894E3BD457199BE38DBBDC86092693E";
const SASHA_PIN: &str = "E27E5D8A3403A2EF66873BBCDEA66FF797772CDC";

fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn real_pins() -> [Fingerprint; 2] {
    [
        Fingerprint::from_hex(GREG_PIN).unwrap(),
        Fingerprint::from_hex(SASHA_PIN).unwrap(),
    ]
}

/// Occurrences of `needle` in `hay` (the armor END-marker counter for the truncation oracle).
fn count_marker(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// Every strict prefix of the real `.sign` through `DetachedVerifier::new`, and of the real
/// two-signer keyring through `Keyring::load`: all structured errors, zero ParserPanic. A prefix
/// may legitimately SUCCEED only when it still contains the complete armor block set (i.e. the
/// cut removed nothing but trailing whitespace — insignificant by §5.1); any success on an
/// incomplete block set is a fabrication and fails the test.
#[test]
fn truncation_sweep_both_entry_points() {
    let mut panics = 0usize;

    let sign = fixture("real/linux-6.6.30.tar.sign");
    let sig_end: &[u8] = b"-----END PGP SIGNATURE-----";
    for i in 0..sign.len() {
        match DetachedVerifier::new(&sign[..i]) {
            Err(Error::ParserPanic) => panics += 1,
            Err(_) => {}
            Ok(_) => assert!(
                count_marker(&sign[..i], sig_end) == 1,
                "prefix {i} constructed from an INCOMPLETE armor block"
            ),
        }
    }

    let mut keyring = fixture("real/greg-pruned.asc");
    keyring.extend_from_slice(&fixture("real/sasha-pruned.asc"));
    let key_end: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----";
    let full_blocks = count_marker(&keyring, key_end);
    let pins = real_pins();
    for i in 0..keyring.len() {
        match Keyring::load(&keyring[..i], &pins, at(FIXTURE_NOW)) {
            Err(Error::ParserPanic) => panics += 1,
            Err(_) => {}
            Ok(_) => assert!(
                count_marker(&keyring[..i], key_end) == full_blocks,
                "prefix {i} loaded from an INCOMPLETE block set"
            ),
        }
    }

    assert_eq!(panics, 0, "ParserPanic must never fire");
}

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

                                                                                           
/// 1–8 xor-mutations each, through the entry point that matches the input kind. Deterministic —
/// a failure reproduces exactly.
#[test]
fn bounded_deterministic_fuzz_zero_parser_panics() {
    let corpus: [(&str, bool); 4] = [
        ("real/linux-6.6.30.tar.sign", true),
        ("real/greg-pruned.asc", false),
        ("real/sasha-pruned.asc", false),
        ("gen/sig_a_1kib_sha256.asc", true),                                     
    ];
    let pins = real_pins();
    let mut rng = XorShift64(0xC5A1_1E77);
    let mut panics = 0usize;

    for (rel, is_sign) in corpus {
        let base = fixture(rel);
        for _ in 0..4096 {
            let mut mutated = base.clone();
            let flips = 1 + (rng.next() as usize) % 8;
            for _ in 0..flips {
                let pos = (rng.next() as usize) % mutated.len();
                let val = (rng.next() % 255) as u8 + 1;                      
                mutated[pos] ^= val;
            }
            let result_is_panic = if is_sign {
                matches!(DetachedVerifier::new(&mutated), Err(Error::ParserPanic))
            } else {
                matches!(
                    Keyring::load(&mutated, &pins, at(FIXTURE_NOW)),
                    Err(Error::ParserPanic)
                )
            };
            if result_is_panic {
                panics += 1;
            }
        }
    }
    assert_eq!(panics, 0, "ParserPanic must never fire");
}
