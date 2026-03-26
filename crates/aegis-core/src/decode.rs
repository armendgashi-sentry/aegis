//! URL decoding utilities for anti-evasion payload inspection.
//!
//! Attackers may encode payloads to bypass pattern-matching:
//! - Single encoding: `%27%3B%20DROP%20TABLE` -> `'; DROP TABLE`
//! - Double encoding: `%2527%253B%2520DROP` -> `%27%3B%20DROP` -> `'; DROP TABLE`
//! - Plus-as-space: `'+OR+1=1--` -> `' OR 1=1--`
//!
//! This module performs multi-layer decoding so analyzers always inspect
//! the fully decoded payload.

use percent_encoding::percent_decode_str;

/// Decode a string through multiple layers of URL encoding.
/// Decodes repeatedly until the output stabilizes (no more encoded sequences).
/// Also converts `+` to space (form-encoded convention).
/// Returns the fully decoded string.
pub fn url_decode_deep(input: &str) -> String {
    let mut current = input.to_string();

    // Up to 3 rounds to handle double/triple encoding
    for _ in 0..3 {
        // Replace + with space (form-encoded)
        let with_spaces = current.replace('+', " ");

        // Percent-decode
        let decoded = percent_decode_str(&with_spaces)
            .decode_utf8_lossy()
            .to_string();

        if decoded == current {
            return decoded;
        }
        current = decoded;
    }

    current
}

/// Check if a string contains any URL-encoded sequences.
pub fn has_encoding(input: &str) -> bool {
    input.contains('%') || input.contains('+')
}

/// Decode and return both the original and decoded forms.
/// Returns a vec of unique forms to check (avoids duplicate checks).
pub fn decode_variants(input: &str) -> Vec<String> {
    let mut variants = vec![input.to_string()];

    if has_encoding(input) {
        let decoded = url_decode_deep(input);
        if decoded != input {
            variants.push(decoded);
        }
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_url_encoding() {
        assert_eq!(
            url_decode_deep("%27%3B%20DROP%20TABLE%20users%3B--"),
            "'; DROP TABLE users;--"
        );
    }

    #[test]
    fn double_url_encoding() {
        // %2527 -> %27 -> '
        // %253B -> %3B -> ;
        assert_eq!(
            url_decode_deep("%2527%253B%2520DROP%2520TABLE"),
            "'; DROP TABLE"
        );
    }

    #[test]
    fn plus_as_space() {
        assert_eq!(url_decode_deep("'+OR+1=1--"), "' OR 1=1--");
    }

    #[test]
    fn mixed_encoding() {
        assert_eq!(
            url_decode_deep("1%27+UNION+SELECT+%2A+FROM+users--"),
            "1' UNION SELECT * FROM users--"
        );
    }

    #[test]
    fn no_encoding_passthrough() {
        assert_eq!(url_decode_deep("plain text"), "plain text");
    }

    #[test]
    fn decode_variants_returns_both() {
        let v = decode_variants("%27%3B+DROP+TABLE");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "%27%3B+DROP+TABLE");
        assert_eq!(v[1], "'; DROP TABLE");
    }

    #[test]
    fn decode_variants_no_encoding() {
        let v = decode_variants("plain text");
        assert_eq!(v.len(), 1);
    }
}
