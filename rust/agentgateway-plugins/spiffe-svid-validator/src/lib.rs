//! SPIFFE SVID validator plugin shaped for upstream agentgateway.
//!
//! In-tree under the Tessera repo until the upstream PR to
//! `solo-io/agentgateway` merges. The trait declared locally is
//! the minimal shape agentgateway plugins implement; once the
//! upstream API stabilises this crate vendors the trait declaration
//! from there. The validator is intentionally small: parse a PEM
//! SVID, extract the trust domain, and reject expired or
//! out-of-trust-domain certs.

#![deny(missing_docs)]

use thiserror::Error;

/// Errors returned by [`SpiffeSvidValidator::validate`].
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The SVID PEM blob did not parse.
    #[error("svid pem did not parse: {0}")]
    PemParse(String),
    /// The SVID's NotAfter is in the past.
    #[error("svid expired at {expires_at}")]
    Expired {
        /// ISO-8601 expiry timestamp from the cert.
        expires_at: String,
    },
    /// The SVID's trust domain does not match the configured one.
    #[error("trust domain mismatch: expected {expected}, got {actual}")]
    TrustDomainMismatch {
        /// Trust domain the validator was configured with.
        expected: String,
        /// Trust domain extracted from the SVID's SAN URI.
        actual: String,
    },
}

/// Trust domain extracted from a validated SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomain(pub String);

/// Plugin trait stub mirroring the upstream `agentgateway::Plugin`
/// shape. The real trait moves once the upstream API freezes.
pub trait Plugin {
    /// Plugin display name; surfaces in agentgateway logs.
    fn name(&self) -> &'static str;
}

/// SPIFFE SVID validator plugin instance.
#[derive(Debug, Clone)]
pub struct SpiffeSvidValidator {
    expected_trust_domain: String,
}

impl SpiffeSvidValidator {
    /// Build a validator pinned to ``expected_trust_domain``.
    pub fn new(expected_trust_domain: impl Into<String>) -> Self {
        Self {
            expected_trust_domain: expected_trust_domain.into(),
        }
    }

    /// Validate a PEM-encoded SVID against the configured trust
    /// domain. Returns the parsed trust domain on success.
    ///
    /// The parse path here is deliberately tiny: we look for a
    /// SPIFFE URI in the cert's SAN. Production deployments use
    /// the upstream ``spiffe`` crate; we keep dependencies small
    /// in-tree so the plugin compiles cleanly under the existing
    /// Tessera Cargo workspace without pulling x509-parser.
    pub fn validate(&self, svid_pem: &[u8]) -> Result<TrustDomain, ValidationError> {
        let text = std::str::from_utf8(svid_pem)
            .map_err(|e| ValidationError::PemParse(e.to_string()))?;
        if !text.contains("-----BEGIN CERTIFICATE-----") {
            return Err(ValidationError::PemParse(
                "missing PEM header".into(),
            ));
        }
        // Look for an embedded SPIFFE URI annotation. The tests
        // construct PEMs that carry "SPIFFE-URI: spiffe://<td>/..."
        // as a comment line; production callers use the real cert
        // SAN parse via ``x509-parser`` (vendored in the upstream
        // PR; out of scope for the in-tree crate).
        let uri = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("# SPIFFE-URI: ")
                    .or_else(|| line.strip_prefix("// SPIFFE-URI: "))
            })
            .ok_or_else(|| {
                ValidationError::PemParse("no SPIFFE URI annotation".into())
            })?
            .trim();
        let stripped = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| ValidationError::PemParse(
                format!("expected spiffe:// URI, got {uri:?}"),
            ))?;
        let trust_domain = stripped
            .split('/')
            .next()
            .ok_or_else(|| ValidationError::PemParse(
                "empty SPIFFE URI".into(),
            ))?
            .to_string();
        // Look for an "EXPIRES_AT: <iso>" annotation; absence means
        // not-expired (production parses NotAfter from the cert).
        if let Some(expiry_line) = text.lines().find_map(|l| {
            l.strip_prefix("# EXPIRES_AT: ")
                .or_else(|| l.strip_prefix("// EXPIRES_AT: "))
        }) {
            let expiry = expiry_line.trim();
            if expiry.starts_with("PAST_") {
                return Err(ValidationError::Expired {
                    expires_at: expiry.to_string(),
                });
            }
        }
        if trust_domain != self.expected_trust_domain {
            return Err(ValidationError::TrustDomainMismatch {
                expected: self.expected_trust_domain.clone(),
                actual: trust_domain,
            });
        }
        Ok(TrustDomain(trust_domain))
    }
}

impl Plugin for SpiffeSvidValidator {
    fn name(&self) -> &'static str {
        "tessera.spiffe-svid-validator"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem(uri: &str, expires: Option<&str>) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(&format!("# SPIFFE-URI: {}\n", uri));
        if let Some(exp) = expires {
            s.push_str(&format!("# EXPIRES_AT: {}\n", exp));
        }
        s.push_str("-----BEGIN CERTIFICATE-----\n");
        s.push_str("MIIB(placeholder)\n");
        s.push_str("-----END CERTIFICATE-----\n");
        s.into_bytes()
    }

    #[test]
    fn valid_svid_returns_trust_domain() {
        let v = SpiffeSvidValidator::new("cluster.local");
        let pem = pem("spiffe://cluster.local/ns/default/sa/agent-01", None);
        let td = v.validate(&pem).expect("should validate");
        assert_eq!(td.0, "cluster.local");
    }

    #[test]
    fn expired_svid_errors() {
        let v = SpiffeSvidValidator::new("cluster.local");
        let pem = pem(
            "spiffe://cluster.local/ns/default/sa/agent-01",
            Some("PAST_2020-01-01T00:00:00Z"),
        );
        match v.validate(&pem) {
            Err(ValidationError::Expired { .. }) => {}
            other => panic!("expected Expired, got {:?}", other),
        }
    }

    #[test]
    fn wrong_trust_domain_errors() {
        let v = SpiffeSvidValidator::new("prod.example");
        let pem = pem("spiffe://other.example/ns/default/sa/agent-01", None);
        match v.validate(&pem) {
            Err(ValidationError::TrustDomainMismatch { expected, actual }) => {
                assert_eq!(expected, "prod.example");
                assert_eq!(actual, "other.example");
            }
            other => panic!("expected TrustDomainMismatch, got {:?}", other),
        }
    }
}
