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
    const PRESERVED: &[&str] = &[
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
    const MASKED: &[(&str, &str)] = &[
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

    /// Documented leftovers (upstream rulings): the DHCP `Session Id` header
    /// and `Dynamic-address session scan status : Disable` stay masked.
    #[test]
    fn documented_leftovers_stay_masked() {
        assert!(!redact_junos_text("Session Id").contains("Session Id"));
        let scan = redact_junos_text("Dynamic-address session scan status            : Disable");
        assert!(!scan.contains("Disable"), "{scan}");
    }

    /// Secrets the old local shield pinned; each must stay masked.
    #[test]
    fn legacy_still_masked_pins() {
        let cases = [
            ("session-token: s3cr3tvalue", "s3cr3tvalue"),
            (
                "set system login session-key supersecretvalue",
                "supersecretvalue",
            ),
            ("session abcdef0123456789", "abcdef0123456789"),
            (
                "set snmp community s3cr3tcomm authorization read-only",
                "s3cr3tcomm",
            ),
            (
                "set system root-authentication encrypted-password \"$6$abc$defghijklmnop\"",
                "$6$abc",
            ),
            ("Authorization: Bearer abcdef0123456789", "abcdef0123456789"), // gitleaks:allow -- fake fixture
            (
                "ftp://svc:hunter2hunter2@archive.example.net/cfg",
                "hunter2hunter2",
            ), // gitleaks:allow -- fake fixture
            (
                "session init 0123456789abcdef0123456789abcdef01234567",
                "0123456789abcdef",
            ),
            (
                "session close id=0123456789abcdef0123456789abcdef01234567",
                "0123456789abcdef",
            ),
            ("limit-session notanumber9f8e7d6c5b4a", "notanumber"),
            ("session summary token 0123456789abcdef", "0123456789abcdef"), // gitleaks:allow -- fake fixture
        ];
        for (case, secret) in cases {
            let out = redact_junos_text(case);
            assert!(!out.contains(secret), "secret survived: {case} -> {out}");
        }
    }

    /// Crafted input must not turn the redactor quadratic (fixed upstream).
    /// The bound is generous: a quadratic pass over 600 KB takes minutes.
    #[test]
    fn crafted_input_is_linear() {
        let inputs = [
            "session-init ".repeat(50_000),
            format!("JMCPKEEP{} session-init", "X".repeat(300_000)),
        ];
        for input in inputs {
            assert!(input.len() >= 200_000);
            let start = std::time::Instant::now();
            let out = redact_junos_text(&input);
            assert!(!out.is_empty());
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "redaction too slow: {:?}",
                start.elapsed()
            );
        }
    }
}
