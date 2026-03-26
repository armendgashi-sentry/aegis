use std::net::IpAddr;
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

impl TargetScope {
    /// Check if a host:port combination is within the authorized scope.
    /// Returns true if scope is empty (no restrictions).
    pub fn is_in_scope(&self, host: &str, port: u16) -> bool {
        // Empty scope = no restrictions (allow all)
        if self.targets.is_empty() {
            return true;
        }

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
}
