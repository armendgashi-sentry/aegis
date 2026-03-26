use crate::analyzer::{HttpAnalyzer, RequestContext};
use crate::decode;
use crate::decision::Verdict;
use crate::policy::yaml_policy::HttpPolicy;

/// Built-in HTTP analyzer: checks HTTP method and request body for destructive patterns.
/// Performs URL decoding on payloads to catch encoded evasion attempts.
pub struct BuiltinHttpAnalyzer {
    policy: HttpPolicy,
}

impl BuiltinHttpAnalyzer {
    pub fn new(policy: HttpPolicy) -> Self {
        Self { policy }
    }
}

impl HttpAnalyzer for BuiltinHttpAnalyzer {
    fn name(&self) -> &'static str {
        "builtin:http"
    }

    fn analyze(&self, ctx: &RequestContext) -> Option<Verdict> {
        let method = ctx.method.to_uppercase();

        // Check blocked methods
        if self
            .policy
            .methods
            .block
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method))
        {
            return Some(Verdict::deny(
                format!("HTTP method {method} is blocked by policy"),
                self.name(),
            ));
        }

        // Safe methods pass without payload inspection
        if self
            .policy
            .methods
            .safe
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method))
        {
            return None;
        }

        // Inspect methods: check payload for destructive content
        if self
            .policy
            .methods
            .inspect
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method))
        {
            if let Some(ref body) = ctx.body {
                if let Ok(body_str) = std::str::from_utf8(body) {
                    // Check all decoded variants for destructive command patterns
                    for variant in decode::decode_variants(body_str) {
                        for pattern in &self.policy.payload.block_commands {
                            if variant.to_lowercase().contains(&pattern.to_lowercase()) {
                                return Some(Verdict::deny(
                                    format!(
                                        "Request body contains destructive command pattern: {pattern}"
                                    ),
                                    self.name(),
                                ));
                            }
                        }
                    }
                }

                // Check body size limit
                if body.len() as u64 > self.policy.max_request_body {
                    return Some(Verdict::deny(
                        format!(
                            "Request body size ({} bytes) exceeds limit ({} bytes)",
                            body.len(),
                            self.policy.max_request_body
                        ),
                        self.name(),
                    ));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::yaml_policy::{MethodPolicy, PayloadPolicy};
    use bytes::Bytes;
    use std::collections::HashMap;
    use url::Url;

    fn default_policy() -> HttpPolicy {
        HttpPolicy {
            methods: MethodPolicy {
                safe: vec!["GET".into(), "HEAD".into(), "OPTIONS".into()],
                inspect: vec!["POST".into(), "PUT".into(), "PATCH".into()],
                block: vec!["DELETE".into()],
            },
            payload: PayloadPolicy {
                block_sql: vec!["DROP".into(), "DELETE".into(), "TRUNCATE".into()],
                allow_sql: vec!["SELECT".into(), "UNION".into()],
                block_commands: vec!["rm -rf".into(), "dd if=".into(), "mkfs".into()],
            },
            max_request_body: 10_485_760,
        }
    }

    fn ctx(method: &str, body: Option<&str>) -> RequestContext {
        RequestContext {
            method: method.into(),
            url: Url::parse("http://target.com/api/test").unwrap(),
            host: "target.com".into(),
            port: 80,
            path: "/api/test".into(),
            headers: HashMap::new(),
            body: body.map(|b| Bytes::from(b.to_string())),
            content_type: None,
        }
    }

    #[test]
    fn blocks_delete_method() {
        let analyzer = BuiltinHttpAnalyzer::new(default_policy());
        let verdict = analyzer.analyze(&ctx("DELETE", None));
        assert!(verdict.is_some());
        assert!(verdict.unwrap().is_deny());
    }

    #[test]
    fn allows_get() {
        let analyzer = BuiltinHttpAnalyzer::new(default_policy());
        let verdict = analyzer.analyze(&ctx("GET", None));
        assert!(verdict.is_none());
    }

    #[test]
    fn blocks_destructive_command_in_body() {
        let analyzer = BuiltinHttpAnalyzer::new(default_policy());
        let verdict = analyzer.analyze(&ctx("POST", Some("cmd=rm -rf /tmp/target")));
        assert!(verdict.is_some());
        assert!(verdict.unwrap().is_deny());
    }

    #[test]
    fn allows_safe_post_body() {
        let analyzer = BuiltinHttpAnalyzer::new(default_policy());
        let verdict = analyzer.analyze(&ctx("POST", Some("{\"name\": \"test\"}")));
        assert!(verdict.is_none());
    }

    #[test]
    fn blocks_url_encoded_command_in_body() {
        let analyzer = BuiltinHttpAnalyzer::new(default_policy());
        // URL-encoded "rm -rf /tmp/target"
        let verdict = analyzer.analyze(&ctx("POST", Some("cmd=rm%20-rf%20/tmp/target")));
        assert!(verdict.is_some());
        assert!(verdict.unwrap().is_deny());
    }
}
