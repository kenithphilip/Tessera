//! SSRF guard. Deny outbound URLs that resolve to internal targets.
//!
//! Mirrors `tessera.ssrf_guard` from the Python reference. A URL is
//! unsafe when it resolves, after parsing, decoding, and DNS, to any
//! of: loopback, RFC1918 private space, link-local, cloud metadata
//! endpoints, or other special-use ranges. Naive checks miss the
//! interesting attacks: decimal-encoded IPs (`http://2130706433/` is
//! 127.0.0.1), octal/hex octets, IPv4-mapped IPv6, and hostnames that
//! resolve to private space.
//!
//! This module is a checker, not an HTTP client. It returns a verdict
//! on a URL string. Callers that follow redirects MUST re-check after
//! each hop, otherwise an attacker controlling a public endpoint can
//! 302 to `http://169.254.169.254/` and bypass the front-door check.
//!
//! Resolver injection: the default resolver uses
//! `std::net::ToSocketAddrs` (libc `getaddrinfo`). Tests supply a fake.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use url::Url;

/// One reason a URL was rejected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SsrfFinding {
    pub rule_id: String,
    pub category: String,
    pub message: String,
    pub url: String,
    pub resolved_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsrfDecision {
    pub allowed: bool,
    pub findings: Vec<SsrfFinding>,
}

impl SsrfDecision {
    pub fn primary_reason(&self) -> String {
        if self.allowed {
            return String::new();
        }
        self.findings
            .first()
            .map(|f| format!("{}: {}", f.rule_id, f.message))
            .unwrap_or_default()
    }
}

/// Resolver hook: hostname -> list of IP strings. Inject a fake in
/// tests; the default uses the system DNS via `getaddrinfo`.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let target = format!("{host}:0");
        let addrs = target
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for a in addrs {
            let ip = a.ip();
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        Ok(out)
    }
}

/// SSRF guard. Configurable via [`SsrfGuardBuilder`].
pub struct SsrfGuard {
    allowed_schemes: Vec<String>,
    blocked_v4: Vec<IpV4Cidr>,
    blocked_v6: Vec<IpV6Cidr>,
    cidr_categories: std::collections::HashMap<String, String>,
    blocked_hostnames: std::collections::HashSet<String>,
    allowlist_hostnames: Option<std::collections::HashSet<String>>,
    resolver: Arc<dyn Resolver>,
    cloud_metadata: Vec<(IpAddr, &'static str)>,
}

impl SsrfGuard {
    pub fn builder() -> SsrfGuardBuilder {
        SsrfGuardBuilder::new()
    }

    /// Construct a guard with all defaults.
    pub fn with_defaults() -> Self {
        Self::builder().build()
    }

    /// Check a single URL string. See module docs for the rules.
    pub fn check_url(&self, url_str: &str) -> SsrfDecision {
        if url_str.is_empty() {
            return deny(&[finding(
                "ssrf.malformed_url",
                "malformed",
                "URL is empty",
                url_str,
                None,
            )]);
        }
        let url = match Url::parse(url_str) {
            Ok(u) => u,
            Err(e) => {
                return deny(&[finding(
                    "ssrf.malformed_url",
                    "malformed",
                    &format!("unparseable URL: {e}"),
                    url_str,
                    None,
                )]);
            }
        };
        let scheme = url.scheme().to_ascii_lowercase();
        if !self.allowed_schemes.iter().any(|s| s == &scheme) {
            return deny(&[finding(
                &format!(
                    "ssrf.scheme.{}",
                    if scheme.is_empty() { "empty" } else { &scheme }
                ),
                "scheme",
                &format!(
                    "scheme not allowed: {scheme:?} (allowed: {:?})",
                    self.allowed_schemes
                ),
                url_str,
                None,
            )]);
        }
        let host = match url.host_str() {
            Some(h) => h.to_string(),
            None => {
                return deny(&[finding(
                    "ssrf.no_host",
                    "malformed",
                    "URL has no host component",
                    url_str,
                    None,
                )]);
            }
        };
        let host_lc = host.to_ascii_lowercase();

        if self.blocked_hostnames.contains(&host_lc) {
            return deny(&[finding(
                "ssrf.blocked_hostname",
                "hostname_denylist",
                &format!("hostname is in deny list: {host_lc}"),
                url_str,
                None,
            )]);
        }

        // Direct IP literal (any encoding): check IP, skip DNS.
        if let Some(ip) = parse_ip_any(&host) {
            if let Some(f) = self.check_ip(&ip, url_str) {
                return deny(&[f]);
            }
            // Allowlist still applies even for literal IPs.
            if let Some(allow) = &self.allowlist_hostnames {
                if !allow.contains(&host_lc) {
                    return deny(&[finding(
                        "ssrf.not_in_allowlist",
                        "hostname_allowlist",
                        &format!("host not in allowlist: {host_lc}"),
                        url_str,
                        Some(&ip.to_string()),
                    )]);
                }
            }
            return SsrfDecision { allowed: true, findings: vec![] };
        }

        // Hostname (not IP literal). Allowlist applies before resolution.
        if let Some(allow) = &self.allowlist_hostnames {
            if !allow.contains(&host_lc) {
                return deny(&[finding(
                    "ssrf.not_in_allowlist",
                    "hostname_allowlist",
                    &format!("hostname not in allowlist: {host_lc}"),
                    url_str,
                    None,
                )]);
            }
        }

        // Resolve and check every returned IP. Fail closed on resolver
        // errors and empty resolutions.
        let ips = match self.resolver.resolve(&host) {
            Ok(v) => v,
            Err(e) => {
                return deny(&[finding(
                    "ssrf.resolution_failed",
                    "resolution",
                    &format!("hostname resolution failed: {e}"),
                    url_str,
                    None,
                )]);
            }
        };
        if ips.is_empty() {
            return deny(&[finding(
                "ssrf.resolution_empty",
                "resolution",
                &format!("hostname did not resolve: {host}"),
                url_str,
                None,
            )]);
        }

        let mut bad: Vec<SsrfFinding> = Vec::new();
        for ip in &ips {
            if let Some(f) = self.check_ip(ip, url_str) {
                bad.push(f);
            }
        }
        if !bad.is_empty() {
            return deny(&bad);
        }
        SsrfDecision { allowed: true, findings: vec![] }
    }

    /// Return a finding if this IP is blocked. Unwraps IPv4-mapped
    /// IPv6 first so the v4 blocklist applies.
    fn check_ip(&self, ip: &IpAddr, url: &str) -> Option<SsrfFinding> {
        let normalized = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => *ip,
            },
            other => *other,
        };
        // Cloud metadata first (specific over generic).
        for (meta_ip, label) in &self.cloud_metadata {
            if meta_ip == &normalized {
                return Some(finding(
                    &format!("ssrf.cloud_metadata.{label}"),
                    "cloud_metadata",
                    &format!("cloud metadata endpoint: {normalized} ({label})"),
                    url,
                    Some(&normalized.to_string()),
                ));
            }
        }
        match normalized {
            IpAddr::V4(v4) => {
                for cidr in &self.blocked_v4 {
                    if cidr.contains(&v4) {
                        let key = cidr.canonical();
                        let category = self
                            .cidr_categories
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "blocked_cidr".to_string());
                        return Some(finding(
                            &format!("ssrf.{category}"),
                            &category,
                            &format!("IP in blocked range {key}: {v4}"),
                            url,
                            Some(&v4.to_string()),
                        ));
                    }
                }
            }
            IpAddr::V6(v6) => {
                for cidr in &self.blocked_v6 {
                    if cidr.contains(&v6) {
                        let key = cidr.canonical();
                        let category = self
                            .cidr_categories
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "blocked_cidr".to_string());
                        return Some(finding(
                            &format!("ssrf.{category}"),
                            &category,
                            &format!("IP in blocked range {key}: {v6}"),
                            url,
                            Some(&v6.to_string()),
                        ));
                    }
                }
            }
        }
        None
    }
}

fn deny(findings: &[SsrfFinding]) -> SsrfDecision {
    SsrfDecision {
        allowed: false,
        findings: findings.to_vec(),
    }
}

fn finding(rule_id: &str, category: &str, message: &str, url: &str, resolved: Option<&str>) -> SsrfFinding {
    SsrfFinding {
        rule_id: rule_id.to_string(),
        category: category.to_string(),
        message: message.to_string(),
        url: url.to_string(),
        resolved_ip: resolved.map(String::from),
    }
}

// ---------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------

pub struct SsrfGuardBuilder {
    allowed_schemes: Vec<String>,
    extra_blocked_cidrs: Vec<String>,
    replace_default_cidrs: bool,
    blocked_hostnames: Vec<String>,
    allowlist_hostnames: Option<Vec<String>>,
    resolver: Option<Arc<dyn Resolver>>,
}

impl SsrfGuardBuilder {
    fn new() -> Self {
        Self {
            allowed_schemes: vec!["http".into(), "https".into()],
            extra_blocked_cidrs: Vec::new(),
            replace_default_cidrs: false,
            blocked_hostnames: Vec::new(),
            allowlist_hostnames: None,
            resolver: None,
        }
    }

    pub fn allowed_schemes<I: IntoIterator<Item = String>>(mut self, schemes: I) -> Self {
        self.allowed_schemes = schemes.into_iter().map(|s| s.to_lowercase()).collect();
        self
    }

    pub fn add_blocked_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.extra_blocked_cidrs.push(cidr.into());
        self
    }

    pub fn replace_default_cidrs(mut self, value: bool) -> Self {
        self.replace_default_cidrs = value;
        self
    }

    pub fn block_hostname(mut self, host: impl Into<String>) -> Self {
        self.blocked_hostnames.push(host.into());
        self
    }

    pub fn allowlist_hostname(mut self, host: impl Into<String>) -> Self {
        self.allowlist_hostnames
            .get_or_insert_with(Vec::new)
            .push(host.into());
        self
    }

    pub fn resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn build(self) -> SsrfGuard {
        let mut cidr_strs: Vec<&str> = Vec::new();
        if !self.replace_default_cidrs {
            cidr_strs.extend(DEFAULT_BLOCKED_CIDRS_V4);
            cidr_strs.extend(DEFAULT_BLOCKED_CIDRS_V6);
        }
        let extra: Vec<&str> = self.extra_blocked_cidrs.iter().map(String::as_str).collect();
        cidr_strs.extend(extra);

        let mut blocked_v4 = Vec::new();
        let mut blocked_v6 = Vec::new();
        let mut cidr_categories = std::collections::HashMap::new();
        for s in &cidr_strs {
            if let Some(v4) = IpV4Cidr::parse(s) {
                let key = v4.canonical();
                if let Some(cat) = cidr_category(&key) {
                    cidr_categories.insert(key.clone(), cat.to_string());
                }
                blocked_v4.push(v4);
            } else if let Some(v6) = IpV6Cidr::parse(s) {
                let key = v6.canonical();
                if let Some(cat) = cidr_category(&key) {
                    cidr_categories.insert(key.clone(), cat.to_string());
                }
                blocked_v6.push(v6);
            }
        }

        let blocked_hostnames = self
            .blocked_hostnames
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let allowlist_hostnames = self
            .allowlist_hostnames
            .map(|v| v.into_iter().map(|h| h.to_ascii_lowercase()).collect());

        let resolver: Arc<dyn Resolver> = self
            .resolver
            .unwrap_or_else(|| Arc::new(SystemResolver));

        SsrfGuard {
            allowed_schemes: self.allowed_schemes,
            blocked_v4,
            blocked_v6,
            cidr_categories,
            blocked_hostnames,
            allowlist_hostnames,
            resolver,
            cloud_metadata: vec![
                ("169.254.169.254".parse().unwrap(), "aws_gcp_azure_oci"),
                ("100.100.100.200".parse().unwrap(), "alibaba"),
                ("fd00:ec2::254".parse().unwrap(), "aws_ipv6"),
            ],
        }
    }
}

// ---------------------------------------------------------------------
// CIDR types (minimal, no extra deps)
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
struct IpV4Cidr {
    network: u32,
    prefix: u8,
}

impl IpV4Cidr {
    fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let ip: Ipv4Addr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix) };
        let network = u32::from(ip) & mask;
        Some(Self { network, prefix })
    }

    fn contains(&self, ip: &Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0u32 } else { u32::MAX << (32 - self.prefix) };
        (u32::from(*ip) & mask) == self.network
    }

    fn canonical(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

#[derive(Clone, Copy)]
struct IpV6Cidr {
    network: u128,
    prefix: u8,
}

impl IpV6Cidr {
    fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let ip: Ipv6Addr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        let mask = if prefix == 0 {
            0u128
        } else if prefix == 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix)
        };
        let network = u128::from(ip) & mask;
        Some(Self { network, prefix })
    }

    fn contains(&self, ip: &Ipv6Addr) -> bool {
        let mask = if self.prefix == 0 {
            0u128
        } else if self.prefix == 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - self.prefix)
        };
        (u128::from(*ip) & mask) == self.network
    }

    fn canonical(&self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.network), self.prefix)
    }
}

// ---------------------------------------------------------------------
// IP literal decoding (decimal, hex, octal, dotted-hex, IPv4-mapped v6)
// ---------------------------------------------------------------------

/// Try to parse `host` as an IPv4 or IPv6 literal in any common
/// encoding. Returns `None` if it doesn't look like an IP literal.
pub fn parse_ip_any(host: &str) -> Option<IpAddr> {
    if host.is_empty() {
        return None;
    }
    // Strip brackets from IPv6 literals if present (url crate already
    // strips them, but be defensive).
    let h = host.trim_start_matches('[').trim_end_matches(']');

    // Standard form (handles IPv4 dotted-quad, IPv6 colon notation).
    if let Ok(addr) = h.parse::<IpAddr>() {
        return Some(addr);
    }

    // Pure decimal integer (e.g. "2130706433" == 127.0.0.1).
    if h.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = h.parse::<u64>() {
            if n <= u32::MAX as u64 {
                return Some(IpAddr::V4(Ipv4Addr::from(n as u32)));
            }
        }
    }

    // Hex integer ("0x7f000001").
    let lower = h.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_prefix("0x") {
        if !stripped.contains('.') {
            if let Ok(n) = u64::from_str_radix(stripped, 16) {
                if n <= u32::MAX as u64 {
                    return Some(IpAddr::V4(Ipv4Addr::from(n as u32)));
                }
            }
        }
    }

    // Dotted-quad with non-decimal octets (0177.0.0.1, 0x7f.0.0.1).
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 4 {
        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return None;
            }
            let lower_part = part.to_ascii_lowercase();
            let value: u32 = if let Some(hex) = lower_part.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()?
            } else if part.starts_with('0') && part.len() > 1 {
                u32::from_str_radix(part, 8).ok()?
            } else {
                part.parse().ok()?
            };
            if value > 255 {
                return None;
            }
            octets[i] = value as u8;
        }
        return Some(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])));
    }

    None
}

// ---------------------------------------------------------------------
// Default CIDR sets and category labels (mirrors Python reference)
// ---------------------------------------------------------------------

const DEFAULT_BLOCKED_CIDRS_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

const DEFAULT_BLOCKED_CIDRS_V6: &[&str] = &[
    "::/128",
    "::1/128",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

fn cidr_category(cidr: &str) -> Option<&'static str> {
    Some(match cidr {
        "0.0.0.0/8" => "this_network",
        "10.0.0.0/8" => "private_ip",
        "100.64.0.0/10" => "cgnat",
        "127.0.0.0/8" => "loopback",
        "169.254.0.0/16" => "link_local",
        "172.16.0.0/12" => "private_ip",
        "192.0.0.0/24" => "ietf_protocol",
        "192.0.2.0/24" => "documentation",
        "192.168.0.0/16" => "private_ip",
        "198.18.0.0/15" => "benchmark",
        "198.51.100.0/24" => "documentation",
        "203.0.113.0/24" => "documentation",
        "224.0.0.0/4" => "multicast",
        "240.0.0.0/4" => "reserved",
        "::/128" => "unspecified",
        "::1/128" => "loopback",
        "100::/64" => "discard",
        "2001::/23" => "ietf_protocol",
        "2001:db8::/32" => "documentation",
        "fc00::/7" => "unique_local",
        "fe80::/10" => "link_local",
        "ff00::/8" => "multicast",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MapResolver(std::collections::HashMap<String, Vec<IpAddr>>);

    impl MapResolver {
        fn new() -> Self {
            Self(std::collections::HashMap::new())
        }
        fn with(mut self, host: &str, ips: &[&str]) -> Self {
            self.0.insert(
                host.to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
            self
        }
    }

    impl Resolver for MapResolver {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| format!("unknown host: {host}"))
        }
    }

    fn guard_with_resolver(r: MapResolver) -> SsrfGuard {
        SsrfGuard::builder().resolver(Arc::new(r)).build()
    }

    fn empty_resolver_guard() -> SsrfGuard {
        SsrfGuard::builder().resolver(Arc::new(MapResolver::new())).build()
    }

    // -- schemes -----------------------------------------------------

    #[test]
    fn https_allowed_for_public_resolution() {
        let g = guard_with_resolver(MapResolver::new().with("example.com", &["93.184.216.34"]));
        assert!(g.check_url("https://example.com/").allowed);
    }

    #[test]
    fn http_allowed_for_public_resolution() {
        let g = guard_with_resolver(MapResolver::new().with("example.com", &["93.184.216.34"]));
        assert!(g.check_url("http://example.com/").allowed);
    }

    #[test]
    fn file_scheme_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("file:///etc/passwd");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "scheme");
    }

    #[test]
    fn gopher_scheme_blocked() {
        let g = empty_resolver_guard();
        assert!(!g.check_url("gopher://example.com/").allowed);
    }

    #[test]
    fn custom_allowed_schemes_respected() {
        let g = SsrfGuard::builder()
            .allowed_schemes(vec!["https".to_string()])
            .resolver(Arc::new(MapResolver::new().with("example.com", &["93.184.216.34"])))
            .build();
        assert!(!g.check_url("http://example.com/").allowed);
        assert!(g.check_url("https://example.com/").allowed);
    }

    // -- private ranges ----------------------------------------------

    #[test]
    fn loopback_v4_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://127.0.0.1/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn loopback_v6_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://[::1]/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn rfc1918_ranges_all_blocked() {
        let g = empty_resolver_guard();
        for ip in &["http://10.0.0.5/", "http://172.16.0.1/", "http://192.168.1.1/"] {
            assert!(!g.check_url(ip).allowed, "expected deny for {ip}");
        }
    }

    #[test]
    fn link_local_v4_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://169.254.0.5/");
        assert!(!r.allowed);
        // 169.254.169.254 (a specific IP) gets cloud_metadata category.
        assert!(r.findings[0].category == "link_local" || r.findings[0].category == "cloud_metadata");
    }

    #[test]
    fn unique_local_v6_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://[fc00::1]/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "unique_local");
    }

    #[test]
    fn dns_rebinding_resolved_to_private_blocked() {
        let g = guard_with_resolver(
            MapResolver::new().with("internal.example.com", &["10.20.30.40"]),
        );
        let r = g.check_url("http://internal.example.com/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].resolved_ip.as_deref(), Some("10.20.30.40"));
    }

    // -- encoded IPs --------------------------------------------------

    #[test]
    fn decimal_encoded_loopback_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://2130706433/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn hex_encoded_loopback_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://0x7f000001/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn octal_dotted_loopback_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://0177.0.0.1/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn hex_dotted_loopback_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://0x7f.0.0.1/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    #[test]
    fn ipv4_mapped_v6_loopback_blocked() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://[::ffff:127.0.0.1]/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "loopback");
    }

    // -- cloud metadata ----------------------------------------------

    #[test]
    fn aws_metadata_specific_rule_id() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://169.254.169.254/latest/meta-data/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "cloud_metadata");
        assert_eq!(r.findings[0].rule_id, "ssrf.cloud_metadata.aws_gcp_azure_oci");
    }

    #[test]
    fn alibaba_metadata_specific_rule_id() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://100.100.100.200/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].rule_id, "ssrf.cloud_metadata.alibaba");
    }

    #[test]
    fn metadata_resolved_via_dns_blocked() {
        let g = guard_with_resolver(
            MapResolver::new().with("metadata.google.internal", &["169.254.169.254"]),
        );
        let r = g.check_url("http://metadata.google.internal/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].rule_id, "ssrf.cloud_metadata.aws_gcp_azure_oci");
    }

    // -- hostname allow / deny lists ---------------------------------

    #[test]
    fn blocked_hostname_skips_resolution() {
        struct CountingResolver(std::sync::atomic::AtomicUsize);
        impl Resolver for CountingResolver {
            fn resolve(&self, _h: &str) -> Result<Vec<IpAddr>, String> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec!["1.2.3.4".parse().unwrap()])
            }
        }
        let counter = Arc::new(CountingResolver(std::sync::atomic::AtomicUsize::new(0)));
        let g = SsrfGuard::builder()
            .resolver(Arc::clone(&counter) as Arc<dyn Resolver>)
            .block_hostname("forbidden.example.com")
            .build();
        let r = g.check_url("http://forbidden.example.com/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "hostname_denylist");
        assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn allowlist_denies_other_hostnames() {
        let g = SsrfGuard::builder()
            .resolver(Arc::new(
                MapResolver::new()
                    .with("allowed.example.com", &["1.2.3.4"])
                    .with("other.example.com", &["1.2.3.5"]),
            ))
            .allowlist_hostname("allowed.example.com")
            .build();
        assert!(g.check_url("http://allowed.example.com/").allowed);
        let r = g.check_url("http://other.example.com/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "hostname_allowlist");
    }

    #[test]
    fn allowlist_blocks_raw_public_ip() {
        let g = SsrfGuard::builder()
            .resolver(Arc::new(MapResolver::new().with("only.example.com", &["8.8.8.8"])))
            .allowlist_hostname("only.example.com")
            .build();
        let r = g.check_url("http://8.8.8.8/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "hostname_allowlist");
    }

    // -- resolution failures -----------------------------------------

    #[test]
    fn resolver_error_fails_closed() {
        let g = empty_resolver_guard();
        let r = g.check_url("http://does-not-exist.example/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "resolution");
    }

    #[test]
    fn empty_resolution_fails_closed() {
        struct EmptyResolver;
        impl Resolver for EmptyResolver {
            fn resolve(&self, _h: &str) -> Result<Vec<IpAddr>, String> { Ok(vec![]) }
        }
        let g = SsrfGuard::builder().resolver(Arc::new(EmptyResolver)).build();
        let r = g.check_url("http://something.example/");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].rule_id, "ssrf.resolution_empty");
    }

    #[test]
    fn partial_bad_resolution_blocked() {
        struct MixedResolver;
        impl Resolver for MixedResolver {
            fn resolve(&self, _h: &str) -> Result<Vec<IpAddr>, String> {
                Ok(vec!["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()])
            }
        }
        let g = SsrfGuard::builder().resolver(Arc::new(MixedResolver)).build();
        let r = g.check_url("http://multi.example/");
        assert!(!r.allowed);
        assert!(r.findings.iter().any(|f| f.resolved_ip.as_deref() == Some("10.0.0.1")));
    }

    // -- malformed / public ------------------------------------------

    #[test]
    fn empty_url_rejected() {
        let g = empty_resolver_guard();
        let r = g.check_url("");
        assert!(!r.allowed);
        assert_eq!(r.findings[0].category, "malformed");
    }

    #[test]
    fn missing_or_unresolvable_host_rejected() {
        // The url crate parses "http:///x" as host="x" (RFC compliant
        // behavior, the slash count is interpreted differently). We
        // get a denied verdict via the resolver path because the empty
        // resolver does not know "x"; the important property is that
        // the request is denied, not which category fires.
        let g = empty_resolver_guard();
        let r = g.check_url("http:///path");
        assert!(!r.allowed);
    }

    #[test]
    fn public_v6_allowed() {
        let g = empty_resolver_guard();
        // 2606:4700:4700::1111 (Cloudflare DNS) is public.
        assert!(g.check_url("https://[2606:4700:4700::1111]/").allowed);
    }

    // -- IP literal parsing edges ------------------------------------

    #[test]
    fn parse_ip_any_handles_standard_v4() {
        assert_eq!(
            parse_ip_any("127.0.0.1"),
            Some("127.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn parse_ip_any_rejects_obvious_garbage() {
        assert!(parse_ip_any("hello").is_none());
        assert!(parse_ip_any("0xZZZ").is_none());
        assert!(parse_ip_any("999.0.0.1").is_none());
    }

    #[test]
    fn parse_ip_any_handles_v6_with_brackets() {
        assert_eq!(parse_ip_any("[::1]"), Some("::1".parse().unwrap()));
    }
}
