                                                                  
//!
//! Deliberately NOT `#[non_exhaustive]`: a new variant is a consumer-visible review event, not a
//! silent addition. No variant carries an attacker-controlled string or slice — reasons are
//! `&'static str` chosen at the throw site, and `WeakHash` carries only the bounded algorithm-id
//! octet (log-injection hygiene).

use core::fmt;

/// Every way a cashew verification can refuse. Refusal is the ONLY non-success outcome — there are
/// no partial results and no "best effort" accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Structure violates the §5 whitelist grammar (framing, lengths, canonicality, ordering).
    Malformed(&'static str),
    /// A recognized form deliberately outside the whitelist (v3/v6 sig, pubkey algo ≠ RSA,
    /// multi-signature `.sign`, …).
    Unsupported(&'static str),
    /// A non-whitelisted hash algorithm on a signature that must carry a strong hash: a data
    /// signature, or a trust-granting keyring signature (§5.3). Carries the offending algorithm id.
    WeakHash(u8),
    /// LOAD-TIME ONLY (§14 E-1): a pinned fingerprint is absent from the vendored keyring. A failed
    /// signature verification at `finalize` is NEVER this — it is `BadSignature`.
    UnknownSigner,
    /// A validity-policy predicate failed (expiry, key-flags, revocation, creation-time sanity,
    /// zero-survivors).
    PolicyViolation(&'static str),
    /// A cryptographic signature check failed (including the left-16 quick-reject and the `s ≥ n`
    /// pre-check), or no candidate signing key verified the data signature (§14 E-1).
    BadSignature,
    /// A panic was caught at a public entry boundary (§4). Always a bug in cashew; always
    /// fail-closed — the process survives, nothing is accepted.
    ParserPanic,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(why) => write!(f, "malformed OpenPGP structure: {why}"),
            Error::Unsupported(what) => write!(f, "unsupported OpenPGP form: {what}"),
            Error::WeakHash(algo) => {
                write!(f, "weak/non-whitelisted hash algorithm {algo} on a signature requiring SHA-256/512")
            }
            Error::UnknownSigner => {
                write!(
                    f,
                    "a pinned fingerprint is absent from the vendored keyring"
                )
            }
            Error::PolicyViolation(why) => write!(f, "validity policy violation: {why}"),
            Error::BadSignature => write!(f, "signature verification failed"),
            Error::ParserPanic => write!(f, "parser panic caught at the verification boundary"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Every variant renders a non-empty message, and payload-carrying variants name their payload.
    #[test]
    fn display_is_populated_and_names_payloads() {
        let cases = [
            Error::Malformed("truncated"),
            Error::Unsupported("v3 signature"),
            Error::WeakHash(2),
            Error::UnknownSigner,
            Error::PolicyViolation("expired"),
            Error::BadSignature,
            Error::ParserPanic,
        ];
        for e in cases {
            let s = e.to_string();
            assert!(!s.is_empty(), "empty Display for {e:?}");
        }
                                                                             
        assert!(Error::WeakHash(2).to_string().contains('2'));
        assert!(Error::Malformed("truncated")
            .to_string()
            .contains("truncated"));
        assert!(Error::Unsupported("v3 signature")
            .to_string()
            .contains("v3 signature"));
        assert!(Error::PolicyViolation("expired")
            .to_string()
            .contains("expired"));
    }

    /// `WeakHash` distinguishes algorithm ids (the octet is load-bearing for diagnostics).
    #[test]
    fn weak_hash_distinguishes_algos() {
        assert_ne!(Error::WeakHash(2), Error::WeakHash(1));
        assert_eq!(Error::WeakHash(2), Error::WeakHash(2));
    }
}
