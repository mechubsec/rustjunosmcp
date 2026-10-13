//! Line-oriented redaction for unstructured Junos CLI/config text.
//!
//! Composes the cross-vendor [`mecmcp_redact::redact_text`] denylist with the
//! Junos-specific [`mecmcp_redact::junos::redact_log_text`] vocabulary. The
//! generic denylist matches `session` as a substring and blanks the rest of
//! the line, which masks ordinary Junos configuration keywords that are not
//! credentials. A small closed set of those keywords is shielded around the
//! generic pass; every other `session*` key (`session-id`, `session-token`,
//! ...) is untouched and still masked.

/// Bare `session`/`sessions` is shielded only as a CLI word, i.e. when the
/// next token is one of these keywords (`show security flow session
/// summary`); `session <value>` stays masked.
const KEYWORD_FOLLOWERS: &[&str] = &[
    "summary",
    "table",
    "extensive",
    "brief",
    "terse",
    "count",
    "close",
    "init",
];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Redact unstructured Junos text: generic denylist, then Junos vocabulary,
/// with the closed non-secret `session` keywords preserved.
#[must_use]
pub fn redact_junos_text(input: &str) -> String {
    // Pick a marker prefix that cannot already occur in the input.
    let mut prefix = String::from("JMCPKEEP");
    while input.contains(&prefix) {
        prefix.push('X');
    }
    let mut kept: Vec<String> = Vec::new();
    let shielded = shield(input, &prefix, &mut kept);
    let mut out = mecmcp_redact::junos::redact_log_text(&mecmcp_redact::redact_text(&shielded));
    for (i, tok) in kept.iter().enumerate().rev() {
        out = out.replace(&format!("{prefix}{i}Z"), tok);
    }
    out
}

fn shield(input: &str, prefix: &str, kept: &mut Vec<String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let start = rest.find(is_token_char).unwrap_or(rest.len());
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        if rest.is_empty() {
            break;
        }
        let end = rest.find(|c: char| !is_token_char(c)).unwrap_or(rest.len());
        let token = &rest[..end];
        let after = &rest[end..];
        let lower = token.to_ascii_lowercase();
        let shield_it = match lower.as_str() {
            "session-init" | "session-close" | "limit-session" => true,
            // Bare words are CLI vocabulary only when a keyword follows
            // (`show security flow session summary`).
            "session" | "sessions" => {
                let next = after.trim_start_matches([' ', '\t']);
                let word_end = next.find(|c: char| !is_token_char(c)).unwrap_or(next.len());
                KEYWORD_FOLLOWERS.contains(&next[..word_end].to_ascii_lowercase().as_str())
            }
            _ => false,
        };
        if shield_it {
            out.push_str(&format!("{prefix}{}Z", kept.len()));
            kept.push(token.to_string());
        } else {
            out.push_str(token);
        }
        rest = after;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_secret_session_keywords_survive() {
        let cases = [
            "set security policies from-zone a to-zone b policy p then log session-init",
            "set security policies from-zone a to-zone b policy p then log session-close",
            "set security screen ids-option s1 limit-session source-ip-based 100",
            "show security flow session summary",
            "Then Log SESSION-INIT;",
        ];
        for c in cases {
            assert_eq!(redact_junos_text(c), c, "over-masked: {c}");
        }
    }

    #[test]
    fn session_secrets_and_real_secrets_still_masked() {
        let cases = [
            "session-id abcdef0123456789",
            "session-token: s3cr3tvalue",
            "set system login session-key supersecretvalue",
            "session abcdef0123456789",
            "set security ike policy p pre-shared-key ascii-text \"hunter2hunter2\"",
            "set snmp community s3cr3tcomm authorization read-only",
            "set system root-authentication encrypted-password \"$6$abc$defghijklmnop\"",
            "Authorization: Bearer abcdef0123456789",
            "ftp://svc:hunter2hunter2@archive.example.net/cfg",
        ];
        for c in cases {
            let out = redact_junos_text(c);
            for secret in [
                "abcdef0123456789",
                "s3cr3tvalue",
                "supersecretvalue",
                "hunter2hunter2",
                "s3cr3tcomm",
                "$6$abc",
            ] {
                assert!(!out.contains(secret), "secret survived redaction: {c}");
            }
        }
    }

    #[test]
    fn shielded_keyword_does_not_unmask_a_secret_on_the_same_line() {
        let out = redact_junos_text(
            "then log session-init; pre-shared-key ascii-text \"hunter2hunter2\"",
        );
        assert!(out.contains("session-init"), "{out}");
        assert!(!out.contains("hunter2hunter2"), "{out}");
    }

    #[test]
    fn marker_collision_in_input_is_safe() {
        let out = redact_junos_text("JMCPKEEP0Z session-init");
        assert_eq!(out, "JMCPKEEP0Z session-init");
    }
}
