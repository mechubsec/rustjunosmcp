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
const KEYWORD_FOLLOWERS: &[&str] = &["summary", "table", "extensive", "brief", "terse", "count"];

/// Words other than digits that may follow a shielded keyword within the same
/// statement. Anything else means the keyword may be introducing a value, so
/// it is not shielded and the generic pass masks the statement (fail closed).
const STATEMENT_WORDS: &[&str] = &[
    "session-init",
    "session-close",
    "limit-session",
    "session",
    "sessions",
    "source-ip-based",
    "destination-ip-based",
];

/// Longest digit run accepted as a numeric argument (a limit or count).
const MAX_DIGITS: usize = 10;

/// Longest statement tail (in chars) inspected after a shielded keyword.
/// Longer tails are not shielded (fail closed), which keeps the scan linear.
const MAX_STATEMENT_CHARS: usize = 256;

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Redact unstructured Junos text: generic denylist, then Junos vocabulary,
/// with the closed non-secret `session` keywords preserved.
#[must_use]
pub fn redact_junos_text(input: &str) -> String {
    // Pick a marker prefix that cannot already occur in the input: one more
    // `X` than the longest `X` run following any existing occurrence. A
    // single pass, so device-supplied text cannot make this quadratic.
    let longest_x_run = input
        .match_indices("JMCPKEEP")
        .map(|(i, m)| {
            input[i + m.len()..]
                .bytes()
                .take_while(|&b| b == b'X')
                .count()
        })
        .max();
    let mut prefix = String::from("JMCPKEEP");
    if let Some(run) = longest_x_run {
        prefix.push_str(&"X".repeat(run + 1));
    }
    let mut kept: Vec<String> = Vec::new();
    let shielded = shield(input, &prefix, &mut kept);
    let out = mecmcp_redact::junos::redact_log_text(&mecmcp_redact::redact_text(&shielded));
    restore(&out, &prefix, &kept)
}

/// Replace every surviving `{prefix}{i}Z` marker with `kept[i]` in a single
/// pass, so the cost stays linear in the output size.
fn restore(out: &str, prefix: &str, kept: &[String]) -> String {
    let mut res = String::with_capacity(out.len());
    let mut rest = out;
    while let Some(pos) = rest.find(prefix) {
        res.push_str(&rest[..pos]);
        let after = &rest[pos + prefix.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        let tok = after[..digits]
            .parse::<usize>()
            .ok()
            .and_then(|i| kept.get(i));
        match tok {
            Some(tok) if after[digits..].starts_with('Z') => {
                res.push_str(tok);
                rest = &after[digits + 1..];
            }
            _ => {
                res.push_str(prefix);
                rest = after;
            }
        }
    }
    res.push_str(rest);
    res
}

/// True when the rest of the statement (up to `;` or end of line) holds only
/// numbers, whitespace, `{}|` and known non-secret keywords.
fn statement_is_keywords_only(after: &str) -> bool {
    let window = after
        .char_indices()
        .nth(MAX_STATEMENT_CHARS)
        .map_or(after, |(i, _)| &after[..i]);
    let Some(stmt) = window.split([';', '\n', '\r']).next() else {
        return false;
    };
    if stmt.len() == window.len() && window.len() < after.len() {
        return false;
    }
    if !stmt
        .chars()
        .all(|c| is_token_char(c) || matches!(c, ' ' | '\t' | '{' | '}' | '|'))
    {
        return false;
    }
    stmt.split(|c: char| !is_token_char(c))
        .filter(|w| !w.is_empty())
        .all(|w| {
            let w = w.to_ascii_lowercase();
            (w.len() <= MAX_DIGITS && w.bytes().all(|b| b.is_ascii_digit()))
                || STATEMENT_WORDS.contains(&w.as_str())
                || KEYWORD_FOLLOWERS.contains(&w.as_str())
        })
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
            "session-init" | "session-close" | "limit-session" => statement_is_keywords_only(after),
            // Bare words are CLI vocabulary only when a keyword follows
            // (`show security flow session summary`).
            "session" | "sessions" => {
                let next = after.trim_start_matches([' ', '\t']);
                let word_end = next.find(|c: char| !is_token_char(c)).unwrap_or(next.len());
                KEYWORD_FOLLOWERS.contains(&next[..word_end].to_ascii_lowercase().as_str())
                    && statement_is_keywords_only(after)
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
    fn values_after_session_keywords_are_masked() {
        let cases = [
            "session init 0123456789abcdef0123456789abcdef01234567",
            "session close id=0123456789abcdef0123456789abcdef01234567",
            "limit-session notanumber9f8e7d6c5b4a",
            "session summary token 0123456789abcdef",
        ];
        for c in cases {
            let out = redact_junos_text(c);
            assert!(
                !out.contains("0123456789abcdef") && !out.contains("notanumber"),
                "value survived redaction: {out}"
            );
        }
    }

    /// Large configs carry one shielded keyword per policy; restoring them
    /// must not rescan the whole output per marker.
    #[test]
    fn many_shielded_keywords_restore_in_order() {
        let line = "set security policies from-zone a to-zone b policy p then log session-init\n\
                    set security policies from-zone a to-zone b policy p then log session-close\n";
        let big = line.repeat(20_000);
        assert_eq!(redact_junos_text(&big), big);
    }

    /// A statement tail too long to inspect is not shielded (fail closed).
    #[test]
    fn overlong_statement_is_not_shielded() {
        let long = format!("session-init {}", "session-init ".repeat(100));
        assert!(!redact_junos_text(&long).starts_with("session-init session-init"));
        let short = "limit-session { source-ip-based 100; destination-ip-based 50; }";
        assert_eq!(redact_junos_text(short), short);
    }

    /// Picking a marker prefix absent from the input must stay linear even
    /// when the input carries long runs that look like grown prefixes.
    #[test]
    fn marker_prefix_selection_is_linear_and_collision_free() {
        let crafted = format!("JMCPKEEP{} session-init", "X".repeat(200_000));
        assert_eq!(redact_junos_text(&crafted), crafted);
        let mixed = "JMCPKEEPX0Z JMCPKEEPXX JMCPKEEP1Z then log session-init";
        assert_eq!(redact_junos_text(mixed), mixed);
    }

    #[test]
    fn marker_collision_in_input_is_safe() {
        let out = redact_junos_text("JMCPKEEP0Z session-init");
        assert_eq!(out, "JMCPKEEP0Z session-init");
    }
}
