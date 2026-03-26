use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use crate::analyzer::{HttpAnalyzer, RequestContext};
use crate::decode;
use crate::decision::Verdict;
use crate::policy::yaml_policy::PayloadPolicy;

/// SQL analyzer: detects destructive SQL statements in HTTP request bodies and URL parameters.
/// Performs multi-layer URL decoding to catch encoded evasion attempts.
pub struct SqlAnalyzer {
    policy: PayloadPolicy,
}

impl SqlAnalyzer {
    pub fn new(policy: PayloadPolicy) -> Self {
        Self { policy }
    }

    /// Check a string for destructive SQL, including URL-decoded variants.
    fn check_for_destructive_sql(&self, text: &str) -> Option<String> {
        // Check the raw text first, then decoded variants
        for variant in decode::decode_variants(text) {
            if let Some(reason) = self.check_sql_in_text(&variant) {
                return Some(reason);
            }
        }
        None
    }

    /// Core SQL detection logic on a single text string.
    fn check_sql_in_text(&self, text: &str) -> Option<String> {
        let upper = text.to_uppercase();

        // Quick check: does the text contain any blocked SQL keywords?
        let has_blocked = self
            .policy
            .block_sql
            .iter()
            .any(|kw| upper.contains(&kw.to_uppercase()));

        if !has_blocked {
            return None;
        }

        // Try to parse as SQL to confirm it's actual SQL, not just the word "drop" in prose
        let dialect = GenericDialect {};

        if let Ok(statements) = Parser::parse_sql(&dialect, text) {
            for stmt in &statements {
                let stmt_str = stmt.to_string().to_uppercase();
                for blocked in &self.policy.block_sql {
                    if stmt_str.starts_with(&blocked.to_uppercase()) {
                        return Some(format!("Destructive SQL detected: {blocked} statement"));
                    }
                }
            }
        }

        // Check for SQL injection patterns that may not parse cleanly
        // e.g., "'; DROP TABLE users;--"
        let sqli_patterns = [
            (r";\s*DROP\s+", "DROP"),
            (r";\s*DELETE\s+", "DELETE"),
            (r";\s*TRUNCATE\s+", "TRUNCATE"),
            (r";\s*ALTER\s+TABLE\s+", "ALTER TABLE"),
            (r";\s*UPDATE\s+", "UPDATE"),
        ];

        for (pattern, label) in &sqli_patterns {
            if let Ok(re) = regex::Regex::new(&format!("(?i){pattern}")) {
                if re.is_match(text) {
                    return Some(format!(
                        "SQL injection with destructive payload: {label}"
                    ));
                }
            }
        }

        None
    }
}

impl HttpAnalyzer for SqlAnalyzer {
    fn name(&self) -> &'static str {
        "builtin:sql"
    }

    fn analyze(&self, ctx: &RequestContext) -> Option<Verdict> {
        // Check URL query parameters for SQL injection
        for (_, value) in ctx.url.query_pairs() {
            if let Some(reason) = self.check_for_destructive_sql(&value) {
                return Some(Verdict::deny(reason, self.name()));
            }
        }

        // Also check the raw query string (catches encoded params the URL parser might normalize)
        if let Some(query) = ctx.url.query() {
            let decoded_query = decode::url_decode_deep(query);
            if decoded_query != query {
                if let Some(reason) = self.check_sql_in_text(&decoded_query) {
                    return Some(Verdict::deny(reason, self.name()));
                }
            }
        }

        // Check request body
        if let Some(ref body) = ctx.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                // Check all decoded variants of the raw body
                for variant in decode::decode_variants(body_str) {
                    if let Some(reason) = self.check_sql_in_text(&variant) {
                        return Some(Verdict::deny(reason, self.name()));
                    }
                }

                // If JSON, check all string values (already decoded by JSON parser)
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                    if let Some(reason) = self.check_json_values(&json) {
                        return Some(Verdict::deny(reason, self.name()));
                    }
                }

                // If form-encoded, check all decoded values
                for (_, value) in url::form_urlencoded::parse(body_str.as_bytes()) {
                    if let Some(reason) = self.check_for_destructive_sql(&value) {
                        return Some(Verdict::deny(reason, self.name()));
                    }
                }
            }
        }

        None
    }
}

impl SqlAnalyzer {
    fn check_json_values(&self, value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(s) => self.check_for_destructive_sql(s),
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(reason) = self.check_json_values(v) {
                        return Some(reason);
                    }
                }
                None
            }
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    if let Some(reason) = self.check_json_values(v) {
                        return Some(reason);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use url::Url;

    fn default_payload_policy() -> PayloadPolicy {
        PayloadPolicy {
            block_sql: vec![
                "DROP".into(),
                "DELETE".into(),
                "TRUNCATE".into(),
                "ALTER TABLE".into(),
                "UPDATE".into(),
            ],
            allow_sql: vec!["SELECT".into(), "UNION".into()],
            block_commands: vec![],
        }
    }

    fn ctx(url: &str, body: Option<&str>) -> RequestContext {
        RequestContext {
            method: "POST".into(),
            url: Url::parse(url).unwrap(),
            host: "target.com".into(),
            port: 80,
            path: "/api/test".into(),
            headers: HashMap::new(),
            body: body.map(|b| Bytes::from(b.to_string())),
            content_type: None,
        }
    }

    #[test]
    fn detects_drop_table_in_query_param() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        let result = analyzer.analyze(&ctx(
            "http://target.com/search?q=%27%3B+DROP+TABLE+users%3B--",
            None,
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }

    #[test]
    fn detects_destructive_sql_in_body() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        let result = analyzer.analyze(&ctx(
            "http://target.com/api",
            Some("'; DELETE FROM users WHERE 1=1;--"),
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }

    #[test]
    fn allows_select_statement() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        let result = analyzer.analyze(&ctx(
            "http://target.com/search?q='+UNION+SELECT+1,2,3--",
            None,
        ));
        assert!(result.is_none());
    }

    #[test]
    fn detects_destructive_sql_in_json_body() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        let result = analyzer.analyze(&ctx(
            "http://target.com/api",
            Some(r#"{"query": "'; DROP TABLE users;--"}"#),
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }

    #[test]
    fn detects_url_encoded_sql_in_body() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        // Body contains URL-encoded DROP TABLE
        let result = analyzer.analyze(&ctx(
            "http://target.com/api",
            Some("q=%27%3B+DROP+TABLE+users%3B--"),
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }

    #[test]
    fn detects_double_encoded_sql_in_body() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        // Double-encoded: %2527 -> %27 -> '  /  %253B -> %3B -> ;
        let result = analyzer.analyze(&ctx(
            "http://target.com/api",
            Some("q=%2527%253B%2520DROP%2520TABLE%2520users"),
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }

    #[test]
    fn detects_double_encoded_sql_in_query_param() {
        let analyzer = SqlAnalyzer::new(default_payload_policy());
        let result = analyzer.analyze(&ctx(
            "http://target.com/search?q=%2527%253B%2520DROP%2520TABLE%2520users",
            None,
        ));
        assert!(result.is_some());
        assert!(result.unwrap().is_deny());
    }
}
