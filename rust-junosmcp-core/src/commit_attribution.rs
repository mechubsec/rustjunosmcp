//! Commit-0 attribution classifier for the plane-owned rollback guard (MEC-1880, P5b).
//!
//! `rollback_source: 1` on a plane-owned device replaces the candidate with
//! whatever is one commit behind the running configuration. That is safe only
//! when commit 0 (the current running config) was not committed by the owning
//! management plane itself — otherwise the rollback discards a plane commit
//! this server cannot tell apart from its own. This module classifies who made
//! commit 0 from the device's own commit log, and binds that classification
//! into the approved plan so apply time can detect the log moving underneath
//! it (§5.5 TOCTOU binding).
//!
//! Input is `show system commit`'s text rendering, not `<get-commit-information/>`'s
//! XML shape: the XML form is documented by the vendor but no fixture of it has
//! been captured against a live device yet (MEC-1876 design doc, G14; tracked as
//! follow-up F1). The text form is already parsed elsewhere in this crate
//! (`changeset_recovery.rs`), so this reuses the same entry-grouping approach.
//!
//! Classification is fail-closed by construction: every condition in
//! [`classify_commit_zero`] that cannot positively prove a non-plane commit
//! returns `Ambiguous` or a stricter class, never `NonPlane`.
//!
//! Chassis-cluster timing is tracked separately (MEC-153); see the MEC-1880
//! Paperclip task for the detailed acceptance notes.

use crate::helpers::excerpt;
use crate::tools::transfer_file::hex32;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// One parsed entry from a Junos `show system commit` log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitLogEntry {
    /// Sequence number from the header (0 is the newest / currently running commit).
    pub sequence: u32,
    /// Timestamp text exactly as printed on the header line.
    pub timestamp: String,
    /// The `by <user>` field. Junos prints `root` when no login session carried
    /// the commit (H9).
    pub user: String,
    /// The `via <client>` field (`cli`, `netconf`, `other`, `synchronize`,
    /// `autoinstall`, `button`, `snmp`, ...).
    pub client: String,
    /// Whether the header carries Junos's `commit confirmed, rollback in Nmins`
    /// marker: the commit is live only provisionally.
    pub pending_confirm: bool,
    /// Continuation lines (the commit comment), joined and trimmed. `None` when
    /// the entry has no comment at all.
    pub comment: Option<String>,
}

/// Whether `line` opens a new commit-log entry: Junos indents a header's
/// continuation lines, so an unindented line beginning with a run of ASCII
/// digits is the one unambiguous signal (shared with `changeset_recovery`'s
/// `commit_entry_for_request_id`).
fn is_header_line(line: &str) -> bool {
    !line.starts_with(' ')
        && line
            .split_once(char::is_whitespace)
            .is_some_and(|(first, _)| {
                !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit())
            })
}

/// Parse one header line into its fields.
///
/// Expected shape: `<seq>   <date> <time> UTC by <user> via <client>[ commit
/// confirmed, rollback in Nmins]`. Returns `None` if the line does not match
/// this shape — callers treat that as `unreadable`, never as a best-effort guess.
fn parse_header(line: &str) -> Option<(u32, String, String, String, bool)> {
    let (seq_str, rest) = line.trim_start().split_once(char::is_whitespace)?;
    let sequence: u32 = seq_str.parse().ok()?;
    let rest = rest.trim_start();

    let by_idx = rest.find(" by ")?;
    let timestamp = rest[..by_idx].trim().to_string();
    let after_by = &rest[by_idx + 4..];

    let via_idx = after_by.find(" via ")?;
    let user = after_by[..via_idx].trim().to_string();
    if user.is_empty() {
        return None;
    }
    let after_via = after_by[via_idx + 5..].trim();

    let (client, pending_confirm) = match after_via.find("commit confirmed") {
        Some(marker_idx) => (after_via[..marker_idx].trim().to_string(), true),
        None => (after_via.to_string(), false),
    };
    if client.is_empty() || timestamp.is_empty() {
        return None;
    }

    Some((sequence, timestamp, user, client, pending_confirm))
}

/// Parse the newest (entry 0) record out of a `show system commit` log.
///
/// Returns `None` when the log is empty, carries no recognisable header, or
/// the header line itself fails to parse — all three fold into `unreadable`
/// at the classifier, by design (§5.3: "Commit log unavailable, empty, or the
/// newest entry does not parse").
pub fn parse_newest_entry(log: &str) -> Option<CommitLogEntry> {
    let mut lines = log.lines();
    let header_line = lines.find(|l| is_header_line(l))?;
    let (sequence, timestamp, user, client, pending_confirm) = parse_header(header_line)?;

    let mut comment_lines = Vec::new();
    for line in lines {
        if is_header_line(line) {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            comment_lines.push(trimmed);
        }
    }
    let comment = if comment_lines.is_empty() {
        None
    } else {
        Some(comment_lines.join(" "))
    };

    Some(CommitLogEntry {
        sequence,
        timestamp,
        user,
        client,
        pending_confirm,
        comment,
    })
}

/// Who made commit 0, as far as the device log and the operator-declared
/// allowlist can positively establish it.
///
/// Ordered exactly as MEC-1876 design §5.3: a log that cannot be read is
/// `Unreadable` before anything else is asked of it; a pending confirm is
/// reported before attribution is attempted at all (the right action is to
/// confirm it or let it lapse, not to stack a rollback on it); every path
/// that cannot positively prove the commit was not the plane's own falls to
/// `Ambiguous`; only an exact allowlist hit is `Plane`; everything else that
/// survives is `NonPlane`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitZeroClass {
    /// The commit log could not be read, was empty, or its newest entry did
    /// not parse.
    Unreadable,
    /// Entry 0 is a provisional confirmed-commit, not yet settled.
    PendingConfirm,
    /// Attribution could not be positively established; refused by default.
    Ambiguous,
    /// Entry 0's user is on the declared plane-commit-logins allowlist.
    Plane,
    /// Entry 0's user is positively not the plane: not on the allowlist, and
    /// not one of the login-less/ambiguous client forms.
    NonPlane,
}

impl CommitZeroClass {
    /// Stable lowercase-with-underscore name, matching the design doc's table
    /// and used verbatim in refusal messages and `commit0_attribution` output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::PendingConfirm => "pending_confirm",
            Self::Ambiguous => "ambiguous",
            Self::Plane => "plane",
            Self::NonPlane => "non_plane",
        }
    }

    /// Whether this class permits a guarded `rollback_source: 1` to proceed.
    /// Only `NonPlane` does; every other class — including `Unreadable` — fails
    /// closed.
    pub fn allows_rollback_one(&self) -> bool {
        matches!(self, Self::NonPlane)
    }
}

/// Classify who made commit 0.
///
/// `plane_commit_logins` is the operator-declared inventory field. An absent
/// or empty list always yields `Ambiguous` — attribution is never inferred
/// from device behavior, only from this explicit allowlist (MEC-1880 scope
/// item 2). `device_login` is this server's own NETCONF/CLI login for the
/// device (the inventory `username`): if the operator mistakenly lists it as
/// a plane login, attribution is impossible to trust either way, so that also
/// folds into `Ambiguous` rather than silently misclassifying rustjunosmcp's
/// own commits as the plane's.
pub fn classify_commit_zero(
    entry: Option<&CommitLogEntry>,
    plane_commit_logins: &[String],
    device_login: &str,
) -> CommitZeroClass {
    let Some(entry) = entry else {
        return CommitZeroClass::Unreadable;
    };

    if entry.pending_confirm {
        return CommitZeroClass::PendingConfirm;
    }

    if entry.sequence != 0 {
        return CommitZeroClass::Ambiguous;
    }

    let logins_unusable = plane_commit_logins.is_empty()
        || plane_commit_logins
            .iter()
            .any(|login| login == device_login);
    let no_login_session = entry.user == "root" && entry.client == "other";
    // Allowlist, not denylist (MEC-1880 review F4): only client forms this
    // module can positively attribute to an interactive or NETCONF session
    // clear the gate. Anything else — an automated client form, a future
    // Junos client string, or a header with a trailing annotation this
    // parser doesn't recognise — falls to `Ambiguous` rather than being
    // assumed non-plane by default.
    let attributable_client = matches!(entry.client.as_str(), "cli" | "netconf" | "junoscript");

    if logins_unusable || no_login_session || !attributable_client {
        return CommitZeroClass::Ambiguous;
    }

    if plane_commit_logins.iter().any(|login| login == &entry.user) {
        return CommitZeroClass::Plane;
    }

    CommitZeroClass::NonPlane
}

/// The commit-0 identity bound into an approved change-set plan (§5.5).
///
/// Persisted as part of the plan's `commit0`-attributed rollback action, so the
/// approval digest covers it. Re-derived at apply time from a fresh read of
/// entry 0 and compared with [`CommitZeroBinding::matches`]; a mismatch means
/// the commit log moved between create and apply and the apply is refused with
/// `commit_log_moved` rather than trusting a plan that no longer describes the
/// device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitZeroBinding {
    /// Entry-0 sequence number at the time of classification (always 0; kept
    /// explicit because a reply shaped differently would be a bug worth seeing
    /// in the comparison, not assumed away).
    pub sequence: u32,
    /// Entry-0 timestamp text at classification time.
    pub timestamp: String,
    /// Entry-0 user at classification time.
    pub user: String,
    /// Entry-0 client at classification time.
    pub client: String,
    /// SHA-256 of the entry's raw comment (empty string if there was none).
    /// Hashed rather than stored verbatim because the comment is untrusted free
    /// text (MEC-1870 R10) and the binding only needs to detect change, not
    /// redisplay it.
    pub comment_sha256: String,
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    hex32(&hash)
}

impl CommitZeroBinding {
    /// Capture the binding from a freshly classified entry 0.
    pub fn from_entry(entry: &CommitLogEntry) -> Self {
        Self {
            sequence: entry.sequence,
            timestamp: entry.timestamp.clone(),
            user: entry.user.clone(),
            client: entry.client.clone(),
            comment_sha256: sha256_hex(entry.comment.as_deref().unwrap_or("")),
        }
    }

    /// Whether a freshly re-read entry 0 is exactly the one this binding
    /// captured. Every field must match; any divergence (a new commit landed,
    /// the same commit got re-attributed somehow, or the comment changed) means
    /// the log moved and the bound classification no longer applies.
    pub fn matches(&self, entry: &CommitLogEntry) -> bool {
        self.sequence == entry.sequence
            && self.timestamp == entry.timestamp
            && self.user == entry.user
            && self.client == entry.client
            && self.comment_sha256 == sha256_hex(entry.comment.as_deref().unwrap_or(""))
    }
}

/// Apply-time re-check for a guarded plane-owned `rollback_source: 1` (MEC-1880
/// §5.5, review F3).
///
/// Two independent things must both still hold at apply time, not just one:
/// `binding` must still describe the device's current entry 0 (the log did
/// not move underneath the approved plan), *and* a fresh classification of
/// that same entry must still clear the gate (the operator did not edit
/// `plane_commit_logins` between create and apply in a way that would have
/// changed the create-time verdict). Checking only the binding match would
/// miss an inventory edit that re-tags a log entry the plan already bound to;
/// checking only the classification would miss the log moving to a different
/// entry that happens to classify the same way. `fresh_entry` is `None` when
/// the device did not answer or the log did not parse, which fails closed
/// through the `Option` match below.
pub fn rollback_one_still_permitted(
    binding: Option<&CommitZeroBinding>,
    fresh_entry: Option<&CommitLogEntry>,
    plane_commit_logins: &[String],
    device_login: &str,
) -> bool {
    match (fresh_entry, binding) {
        (Some(fresh_entry), Some(binding)) => {
            binding.matches(fresh_entry)
                && classify_commit_zero(Some(fresh_entry), plane_commit_logins, device_login)
                    .allows_rollback_one()
        }
        _ => false,
    }
}

/// Fixed advisory text from design §5.6, verbatim. Never paraphrase this: the
/// wording was chosen so the tool never says or implies the device is "in
/// sync" with the owning plane, which this server has no way to verify
/// (MEC-1870 §9 — it does not read the plane's API).
pub const PLANE_OWNED_ROLLBACK_ADVISORY: &str = "This device is SDC-managed. SDC may still report OUT_OF_BAND_CHANGED (unverified, G11). Check the device in SDC and resolve there. For future reverts, SDC's Reject is the supported path.";

/// Build the `commit0_attribution` object shown to the approver/caller: what
/// the classifier saw, redacted and length-capped (MEC-1870 R10) because the
/// comment is untrusted free text from anyone who has ever had a device
/// session.
pub fn commit0_attribution_output(entry: Option<&CommitLogEntry>, class: CommitZeroClass) -> Value {
    let Some(entry) = entry else {
        return json!({ "class": class.as_str() });
    };

    let comment_excerpt = entry
        .comment
        .as_deref()
        .map(|comment| excerpt(&mecmcp_redact::redact_text(comment)));
    let carries_request_id = entry
        .comment
        .as_deref()
        .is_some_and(|comment| comment.contains("request.id="));

    json!({
        "class": class.as_str(),
        "sequence": entry.sequence,
        "timestamp": entry.timestamp,
        "user": entry.user,
        "client": entry.client,
        "pending_confirm": entry.pending_confirm,
        "comment_excerpt": comment_excerpt,
        "carries_request_id": carries_request_id,
    })
}

/// Fetch `show system commit` from `router` and classify entry 0 against
/// `plane_commit_logins`/`device_login`.
///
/// Any failure to reach the device or read its commit log folds into
/// [`CommitZeroClass::Unreadable`] rather than propagating a transport error:
/// the classifier's job is to say who owns commit 0, and "the device didn't
/// answer" is exactly the kind of missing evidence §5.3 says must fail closed,
/// not a different error class the caller has to special-case.
pub async fn classify_commit_zero_for_router(
    dm: &crate::device_manager::DeviceManager,
    router: &str,
    plane_commit_logins: &[String],
    device_login: &str,
) -> (CommitZeroClass, Option<CommitLogEntry>) {
    let entry = match dm.run_cli(router, "show system commit").await {
        Ok(log) => parse_newest_entry(&log),
        Err(_) => None,
    };
    let class = classify_commit_zero(entry.as_ref(), plane_commit_logins, device_login);
    (class, entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same captured log as `changeset_recovery`'s `REAL_LOG` (vSRX 24.4R1.9,
    /// #370 hardware run), so this module's parser is tested against the same
    /// device-shaped text rather than a hand-written approximation.
    const REAL_LOG: &str = "\
0   2026-09-03 17:03:08 UTC by netconf via netconf
    no-change-ref by reprobe-370-w (agent) on-behalf-of=self via unknown-public request.id=abadcafe-dead-4bad-8bad-c0dedeadbeef change-set=30a15e0b686bae37
1   2026-07-28 17:54:19 UTC by root via other
2   2026-07-20 22:04:08 UTC by netconf via netconf
    Remove unused srxoutpost super-user (shared-credential cleanup)
3   2026-03-30 21:49:31 UTC by netconf via netconf commit confirmed, rollback in 3mins
    provisional change request.id=11111111-2222-4333-8444-555555555555 change-set=deadbeef
";

    #[test]
    fn parses_entry_zero_header_and_comment() {
        let entry = parse_newest_entry(REAL_LOG).expect("entry 0 parses");
        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.timestamp, "2026-09-03 17:03:08 UTC");
        assert_eq!(entry.user, "netconf");
        assert_eq!(entry.client, "netconf");
        assert!(!entry.pending_confirm);
        assert!(entry.comment.unwrap().contains("request.id=abadcafe"));
    }

    #[test]
    fn root_via_other_entry_has_no_comment() {
        // Entry 1 in REAL_LOG is a bare `root via other` header with nothing
        // indented after it. Re-point the log so it is entry 0.
        let log = "1   2026-07-28 17:54:19 UTC by root via other\n";
        let entry = parse_newest_entry(log).expect("parses");
        assert_eq!(entry.user, "root");
        assert_eq!(entry.client, "other");
        assert!(entry.comment.is_none());
    }

    #[test]
    fn pending_confirm_marker_is_detected() {
        let log = "0   2026-03-30 21:49:31 UTC by netconf via netconf commit confirmed, rollback in 3mins\n    provisional\n";
        let entry = parse_newest_entry(log).expect("parses");
        assert!(entry.pending_confirm);
        assert_eq!(entry.client, "netconf");
    }

    #[test]
    fn empty_log_is_unparseable() {
        assert!(parse_newest_entry("").is_none());
    }

    #[test]
    fn log_with_no_header_shape_is_unparseable() {
        assert!(parse_newest_entry("garbage\nnot a commit log\n").is_none());
    }

    #[test]
    fn classify_unreadable_when_log_does_not_parse() {
        let class = classify_commit_zero(None, &["sdc-svc".into()], "rjm-netconf");
        assert_eq!(class, CommitZeroClass::Unreadable);
    }

    #[test]
    fn classify_pending_confirm_checked_before_attribution() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "sdc-svc".into(), // would otherwise classify Plane
            client: "netconf".into(),
            pending_confirm: true,
            comment: None,
        };
        let class = classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf");
        assert_eq!(class, CommitZeroClass::PendingConfirm);
    }

    #[test]
    fn classify_ambiguous_when_plane_commit_logins_absent() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &[], "rjm-netconf"),
            CommitZeroClass::Ambiguous
        );
    }

    /// H9: a session with no login name defaults to `root`/`other`. That can
    /// never be positively attributed to either side, so it must be ambiguous
    /// even when the allowlist is populated and even though "root" is not on it.
    #[test]
    fn classify_ambiguous_for_root_via_other() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "root".into(),
            client: "other".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
            CommitZeroClass::Ambiguous
        );
    }

    #[test]
    fn classify_ambiguous_for_automated_client_forms() {
        for client in ["synchronize", "autoinstall", "button"] {
            let entry = CommitLogEntry {
                sequence: 0,
                timestamp: "t".into(),
                user: "someone".into(),
                client: client.into(),
                pending_confirm: false,
                comment: None,
            };
            assert_eq!(
                classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
                CommitZeroClass::Ambiguous,
                "client {client} must be ambiguous"
            );
        }
    }

    /// The H9/G13 ambiguous case named in the acceptance criteria: the operator
    /// mistakenly (or because Junos collapsed both to the same login) declares
    /// this server's own device login as a plane login. Attribution from the
    /// log alone is then meaningless, so this must not resolve to `Plane` just
    /// because the user string matches.
    #[test]
    fn classify_ambiguous_when_plane_login_equals_device_login() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "rjm-netconf".into(),
            client: "netconf".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &["rjm-netconf".into()], "rjm-netconf"),
            CommitZeroClass::Ambiguous
        );
    }

    #[test]
    fn classify_plane_when_user_on_allowlist() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "sdc-svc".into(),
            client: "netconf".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
            CommitZeroClass::Plane
        );
    }

    #[test]
    fn classify_non_plane_when_user_not_on_allowlist_and_not_ambiguous() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
            CommitZeroClass::NonPlane
        );
    }

    /// F4: an unrecognised or future client string must not clear the gate
    /// just because it isn't one of the three automated forms this module
    /// already knew about. Allowlist, not denylist.
    #[test]
    fn classify_ambiguous_for_unrecognised_client_forms() {
        for client in ["snmp", "other", "j-web", "rest-api"] {
            let entry = CommitLogEntry {
                sequence: 0,
                timestamp: "t".into(),
                user: "alice".into(),
                client: client.into(),
                pending_confirm: false,
                comment: None,
            };
            assert_eq!(
                classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
                CommitZeroClass::Ambiguous,
                "client {client} must be ambiguous, not assumed non-plane"
            );
        }
    }

    /// F4: only entry 0 is ever attributed. A caller that somehow hands the
    /// classifier a non-zero sequence (e.g. a future caller of this function
    /// that didn't go through `parse_newest_entry`) must not get a positive
    /// verdict out of it.
    #[test]
    fn classify_ambiguous_when_sequence_is_not_zero() {
        let entry = CommitLogEntry {
            sequence: 1,
            timestamp: "t".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: None,
        };
        assert_eq!(
            classify_commit_zero(Some(&entry), &["sdc-svc".into()], "rjm-netconf"),
            CommitZeroClass::Ambiguous
        );
    }

    #[test]
    fn only_non_plane_allows_rollback_one() {
        assert!(CommitZeroClass::NonPlane.allows_rollback_one());
        for class in [
            CommitZeroClass::Unreadable,
            CommitZeroClass::PendingConfirm,
            CommitZeroClass::Ambiguous,
            CommitZeroClass::Plane,
        ] {
            assert!(!class.allows_rollback_one(), "{class:?} must refuse");
        }
    }

    #[test]
    fn binding_round_trips_and_detects_drift() {
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "2026-10-05 10:00:00 UTC".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: Some("fix BGP peering".into()),
        };
        let binding = CommitZeroBinding::from_entry(&entry);
        assert!(binding.matches(&entry));

        let mut moved = entry.clone();
        moved.sequence = 0;
        moved.comment = Some("a different commit landed".into());
        assert!(
            !binding.matches(&moved),
            "a changed comment must be detected as log movement"
        );

        let mut reattributed = entry.clone();
        reattributed.user = "sdc-svc".into();
        assert!(!binding.matches(&reattributed));
    }

    #[test]
    fn attribution_output_for_unreadable_has_no_entry_fields() {
        let out = commit0_attribution_output(None, CommitZeroClass::Unreadable);
        assert_eq!(out["class"], "unreadable");
        assert!(out.get("user").is_none());
    }

    #[test]
    fn attribution_output_redacts_and_caps_the_comment() {
        let long_comment = "a".repeat(500);
        let entry = CommitLogEntry {
            sequence: 0,
            timestamp: "t".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: Some(long_comment),
        };
        let out = commit0_attribution_output(Some(&entry), CommitZeroClass::NonPlane);
        let excerpt = out["comment_excerpt"].as_str().unwrap();
        assert!(excerpt.len() <= 120, "comment must be capped: {excerpt}");
    }

    #[test]
    fn attribution_output_reports_request_id_presence() {
        let entry = parse_newest_entry(REAL_LOG).unwrap();
        let out = commit0_attribution_output(Some(&entry), CommitZeroClass::NonPlane);
        assert_eq!(out["carries_request_id"], true);
    }

    fn non_plane_entry() -> CommitLogEntry {
        CommitLogEntry {
            sequence: 0,
            timestamp: "2026-10-05 10:00:00 UTC".into(),
            user: "alice".into(),
            client: "cli".into(),
            pending_confirm: false,
            comment: None,
        }
    }

    /// The ordinary case the create-time check already cleared: the binding
    /// still matches the fresh entry, and the allowlist hasn't changed.
    #[test]
    fn rollback_one_still_permitted_when_binding_matches_and_still_non_plane() {
        let entry = non_plane_entry();
        let binding = CommitZeroBinding::from_entry(&entry);
        assert!(rollback_one_still_permitted(
            Some(&binding),
            Some(&entry),
            &["sdc-svc".into()],
            "rjm-netconf",
        ));
    }

    /// §5.5 TOCTOU binding: a commit landed between create and apply, so the
    /// fresh entry no longer matches the plan's bound entry 0.
    #[test]
    fn rollback_one_refused_when_commit_log_moved() {
        let entry = non_plane_entry();
        let binding = CommitZeroBinding::from_entry(&entry);
        let mut moved = entry.clone();
        moved.comment = Some("a different commit landed".into());
        assert!(!rollback_one_still_permitted(
            Some(&binding),
            Some(&moved),
            &["sdc-svc".into()],
            "rjm-netconf",
        ));
    }

    /// F3: the log entry itself didn't move, but the operator added its user
    /// to `plane_commit_logins` between create and apply. The binding still
    /// matches, but the fresh classification must now refuse.
    #[test]
    fn rollback_one_refused_when_allowlist_edited_after_create() {
        let entry = non_plane_entry();
        let binding = CommitZeroBinding::from_entry(&entry);
        assert!(!rollback_one_still_permitted(
            Some(&binding),
            Some(&entry),
            &["sdc-svc".into(), "alice".into()],
            "rjm-netconf",
        ));
    }

    /// A missing binding (should never happen on a plan this server created,
    /// but the check must fail closed anyway) or a missing fresh entry (the
    /// device didn't answer) both refuse.
    #[test]
    fn rollback_one_refused_when_binding_or_fresh_entry_missing() {
        let entry = non_plane_entry();
        let binding = CommitZeroBinding::from_entry(&entry);
        assert!(!rollback_one_still_permitted(
            None,
            Some(&entry),
            &["sdc-svc".into()],
            "rjm-netconf",
        ));
        assert!(!rollback_one_still_permitted(
            Some(&binding),
            None,
            &["sdc-svc".into()],
            "rjm-netconf",
        ));
    }
}
