//! Redaction for unstructured Junos CLI/config text.
//!
//! Thin wrapper over [`mecmcp_redact::junos::redact_text`], which runs the
//! generic scan, then the Junos log vocabulary, while preserving vetted
//! non-secret `session` counters, keywords and flow-session command echoes.

/// Redact unstructured Junos text (fails closed; linear time).
#[must_use]
pub fn redact_junos_text(input: &str) -> String {
    mecmcp_redact::junos::redact_text(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetted non-secret `session` text from #579 (and the config keywords).
    pub(crate) const PRESERVED: &[&str] = &[
        "SESSION_OPEN       1234        0",
        "SESSION_CLOSE      1233        0",
        "Valid sessions: 12",
        "Active sessions: 3",
        "Total sessions: 5",
        "Total processed sessions:      42",
        "show security flow session destination-prefix 10.9.0.2",
        "Unicast-sessions: 12\nMulticast-sessions: 0\nSessions-in-use: 3\nMaximum-sessions: 524288\nValid sessions: 12\nFailed sessions: 0",
        "log {\n    session-init;\n    session-close;\n}",
        "then log session-init",
    ];

    /// Session-shaped and real secrets that must stay masked.
    pub(crate) const MASKED: &[(&str, &str)] = &[
        ("session-id abcdef0123456789", "abcdef0123456789"),
        ("Session-Key: abcdef0123456789", "abcdef0123456789"), // gitleaks:allow -- fake fixture
        ("Valid sessions: abcdef0123456789", "abcdef0123456789"),
        (
            "set security ike policy p pre-shared-key ascii-text \"hunter2hunter2\"",
            "hunter2hunter2",
        ),
        ("then log session-init; hunter2hunter2", "hunter2hunter2"),
    ];

    #[test]
    fn non_secret_session_text_survives_issue_579() {
        for case in PRESERVED {
            assert_eq!(redact_junos_text(case), *case, "over-masked: {case}");
        }
    }

    #[test]
    fn session_secrets_stay_masked() {
        for (case, secret) in MASKED {
            let out = redact_junos_text(case);
            assert!(!out.contains(secret), "secret survived: {out}");
        }
    }

    /// DHCP `Session Id` column header stays masked (upstream ruling), and
    /// the `scan status` line is whatever upstream decides.
    #[test]
    fn dhcp_header_stays_masked() {
        assert!(!redact_junos_text("Session Id").contains("Session Id"));
    }

    /// Crafted input must not turn the redactor quadratic (fixed upstream).
    #[test]
    fn crafted_input_is_linear() {
        let big = "session-init ".repeat(50_000);
        let _ = redact_junos_text(&big);
        let _ = redact_junos_text(&format!("JMCPKEEP{} session-init", "X".repeat(200_000)));
    }
}
