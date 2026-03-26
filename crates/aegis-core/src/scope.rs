use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Defines the authorized target scope for a penetration test engagement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetScope {
    /// Allowed targets: domain globs ("*.acme.com") or CIDRs ("10.0.1.0/24")
    #[serde(default)]
    pub targets: Vec<String>,
    /// Allowed ports
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Explicitly excluded targets (even if within scope)
    #[serde(default)]
    pub exclusions: Vec<String>,
}

/// Normalize a host string by resolving obfuscated IP representations.
///
/// Handles:
/// - Standard dotted-quad: "127.0.0.1" (passthrough)
/// - Decimal integer: "2130706433" → "127.0.0.1"
/// - Hex integer: "0x7f000001" → "127.0.0.1"
/// - Octal-prefixed octets: "0177.0.0.01" → "127.0.0.1"
/// - Domain names: returned as-is
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();

    // Already a valid IP? Return as-is.
    if IpAddr::from_str(host).is_ok() {
        return host.to_string();
    }

    // Try decimal integer (e.g. "2130706433" → 127.0.0.1)
    if let Ok(n) = host.parse::<u32>() {
        return IpAddr::V4(Ipv4Addr::from(n)).to_string();
    }

    // Try hex integer (e.g. "0x7f000001" → 127.0.0.1)
    if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return IpAddr::V4(Ipv4Addr::from(n)).to_string();
        }
    }

    // Try octal-prefixed octets (e.g. "0177.0.0.01")
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            let mut octets = [0u8; 4];
            let mut all_ok = true;
            for (i, part) in parts.iter().enumerate() {
                let val = if let Some(oct) = part.strip_prefix('0') {
                    if oct.is_empty() {
                        Some(0u8)
                    } else {
                        u8::from_str_radix(oct, 8).ok()
                    }
                } else {
                    part.parse::<u8>().ok()
                };
                match val {
                    Some(v) => octets[i] = v,
                    None => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if all_ok {
                return IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
                    .to_string();
            }
        }
    }

    // Not an obfuscated IP — return as-is (domain name)
    host.to_string()
}

impl TargetScope {
    /// Check if a host:port combination is within the authorized scope.
    /// Returns true if scope is empty (no restrictions).
    pub fn is_in_scope(&self, host: &str, port: u16) -> bool {
        // Empty scope = no restrictions (allow all)
        if self.targets.is_empty() {
            return true;
        }

        // Normalize host to resolve IP obfuscation (decimal, hex, octal)
        let normalized = normalize_host(host);
        let host = normalized.as_str();

        // Check exclusions first
        if self.matches_any(host, &self.exclusions) {
            return false;
        }

        // Check port
        if !self.ports.is_empty() && !self.ports.contains(&port) {
            return false;
        }

        // Check target
        self.matches_any(host, &self.targets)
    }

    /// Check if a host matches any pattern in the list.
    fn matches_any(&self, host: &str, patterns: &[String]) -> bool {
        for pattern in patterns {
            if self.matches_pattern(host, pattern) {
                return true;
            }
        }
        false
    }

    /// Match a host against a single pattern.
    /// Supports:
    /// - CIDR notation: "10.0.1.0/24"
    /// - Exact IP: "192.168.1.50"
    /// - Domain glob: "*.acme.com"
    /// - Exact domain: "app.acme.com"
    fn matches_pattern(&self, host: &str, pattern: &str) -> bool {
        // Try CIDR match
        if let Ok(network) = IpNet::from_str(pattern) {
            if let Ok(ip) = IpAddr::from_str(host) {
                return network.contains(&ip);
            }
            return false;
        }

        // Try exact IP match
        if let Ok(pattern_ip) = IpAddr::from_str(pattern) {
            if let Ok(host_ip) = IpAddr::from_str(host) {
                return pattern_ip == host_ip;
            }
            return false;
        }

        // Domain glob match
        self.matches_domain_glob(host, pattern)
    }

    /// Match a hostname against a domain glob pattern.
    /// "*.acme.com" matches "app.acme.com", "sub.app.acme.com"
    /// "acme.com" matches only "acme.com"
    fn matches_domain_glob(&self, host: &str, pattern: &str) -> bool {
        let host = host.to_lowercase();
        let pattern = pattern.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard: host must end with .suffix or be exactly suffix
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(targets: &[&str], ports: &[u16], exclusions: &[&str]) -> TargetScope {
        TargetScope {
            targets: targets.iter().map(|s| s.to_string()).collect(),
            ports: ports.to_vec(),
            exclusions: exclusions.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn empty_scope_allows_all() {
        let s = TargetScope::default();
        assert!(s.is_in_scope("anything.com", 80));
        assert!(s.is_in_scope("10.0.0.1", 443));
    }

    #[test]
    fn domain_glob_matching() {
        let s = scope(&["*.acme.com"], &[80, 443], &[]);
        assert!(s.is_in_scope("app.acme.com", 80));
        assert!(s.is_in_scope("sub.app.acme.com", 443));
        assert!(s.is_in_scope("acme.com", 80));
        assert!(!s.is_in_scope("evil.com", 80));
    }

    #[test]
    fn exact_domain() {
        let s = scope(&["app.acme.com"], &[80], &[]);
        assert!(s.is_in_scope("app.acme.com", 80));
        assert!(!s.is_in_scope("other.acme.com", 80));
    }

    #[test]
    fn cidr_matching() {
        let s = scope(&["10.0.1.0/24"], &[80, 443], &[]);
        assert!(s.is_in_scope("10.0.1.50", 80));
        assert!(s.is_in_scope("10.0.1.255", 443));
        assert!(!s.is_in_scope("10.0.2.1", 80));
    }

    #[test]
    fn port_enforcement() {
        let s = scope(&["*.acme.com"], &[80, 443], &[]);
        assert!(s.is_in_scope("app.acme.com", 80));
        assert!(!s.is_in_scope("app.acme.com", 8080));
    }

    #[test]
    fn exclusions() {
        let s = scope(&["*.acme.com"], &[80, 443], &["admin.acme.com"]);
        assert!(s.is_in_scope("app.acme.com", 80));
        assert!(!s.is_in_scope("admin.acme.com", 80));
    }

    #[test]
    fn ip_exclusion() {
        let s = scope(&["10.0.1.0/24"], &[80], &["10.0.1.1"]);
        assert!(s.is_in_scope("10.0.1.50", 80));
        assert!(!s.is_in_scope("10.0.1.1", 80));
    }

    // =========================================================================
    // IP obfuscation normalization
    // =========================================================================

    #[test]
    fn normalize_decimal_ip() {
        assert_eq!(normalize_host("2130706433"), "127.0.0.1");
        assert_eq!(normalize_host("167772161"), "10.0.0.1");
    }

    #[test]
    fn normalize_hex_ip() {
        assert_eq!(normalize_host("0x7f000001"), "127.0.0.1");
        assert_eq!(normalize_host("0X7F000001"), "127.0.0.1");
    }

    #[test]
    fn normalize_octal_ip() {
        assert_eq!(normalize_host("0177.0.0.01"), "127.0.0.1");
    }

    #[test]
    fn normalize_passthrough() {
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_host("app.acme.com"), "app.acme.com");
    }

    #[test]
    fn scope_blocks_decimal_ip_obfuscation() {
        let s = scope(&["127.0.0.1"], &[8888], &[]);
        // Standard IP — in scope
        assert!(s.is_in_scope("127.0.0.1", 8888));
        // Decimal obfuscation — should be normalized and matched
        assert!(s.is_in_scope("2130706433", 8888));
    }

    #[test]
    fn scope_blocks_hex_ip_obfuscation() {
        let s = scope(&["127.0.0.1"], &[8888], &[]);
        assert!(s.is_in_scope("0x7f000001", 8888));
    }

    #[test]
    fn scope_blocks_obfuscated_cidr() {
        let s = scope(&["10.0.1.0/24"], &[80], &[]);
        // 10.0.1.50 = 167772466
        assert!(s.is_in_scope("167772466", 80));
    }

    #[test]
    fn scope_exclusion_catches_obfuscated_ip() {
        let s = scope(&["10.0.1.0/24"], &[80], &["10.0.1.1"]);
        // 10.0.1.1 = 167772161 — should be excluded even when obfuscated
        assert!(!s.is_in_scope("167772161", 80));
    }
}
