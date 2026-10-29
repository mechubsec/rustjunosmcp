//! `get_srx_feed_status` — read-only status of the mecfeedmcp feeds an SRX
//! pulls as `security dynamic-address` feed servers.
//!
//! # RPCs (both `show`-class, one session, sequential)
//!
//! | # | CLI | RPC | Reply |
//! |---|-----|-----|-------|
//! | 1 | `show configuration security dynamic-address` | `get-configuration` (inherited) filtered to `<security><dynamic-address/></security>` | structured config XML |
//! | 2 | `show security dynamic-address summary` | `<get-security-dynamic-address-summary/>` | CLI text wrapped in `<output>` |
//!
//! # Verification status
//!
//! | Item | Status |
//! |------|--------|
//! | RPC names; summary reply is `<output>` text; instance-block layout | verified on vsrx-ci / 26.2R1.7, 2026-10-29 |
//! | Per-feed block layout and labels (`Feed Name` … `Last update status`) | from the srx-dynamic-ip-feed reference, unverified |
//! | Config element names (`feed-server/{name,url,feed-name/{name,path}}`, `address-name/{name,profile/feed-name}`) | Junos config-XML rules, not lab-captured |
//!
//! Captured summary with no feed configured:
//!
//! ```text
//! Dynamic-address session scan status            : Disable
//! Hold-interval for dynamic-address session scan : 10 seconds
//!
//! Instance Name                                  : default
//!     Total number of IPv4 entries               : 0
//!     Total number of IPv4 entries from feed     : 0
//!     Total number of IPv6 entries               : 0
//!     Total number of IPv6 entries from feed     : 0
//! ```
//!
//! The summary is read as `Label<spaces>: value` lines. A per-feed block
//! starts at `Feed Name` and ends at the next `Feed Name`, `Server Name` or
//! `Instance Name`. Labels are compared case-insensitively with internal
//! whitespace collapsed; unknown or missing labels yield `null` fields, never
//! an error.
//!
//! # Rules
//!
//! - **Subscribed:** a feed counts when its effective URL (`url` + `/` +
//!   `path`, or `url` alone) is http(s) and its path ends in
//!   `/feeds/junos-dynamic-address/address` or `…/prefix` (a reverse-proxy
//!   prefix is allowed). No such feed → `state=not_configured`.
//! - **Credentials:** the parser never reads `user-name`, `password` or
//!   `tls-profile`. URLs are reported without userinfo, query or fragment,
//!   and every echo of a credential-bearing URL in device text is replaced
//!   with its sanitised form.
//! - **Failures:** a config rpc-error other than `not-configured` fails
//!   closed (`SrxError::Rpc`). A summary failure degrades only the affected
//!   node: its feeds carry `error: "status unavailable: …"`.
//! - Junos does not report the fetched feed ETag, so there is no
//!   `content_etag`; compare `entries` and `last_update_status` with the feed
//!   server.

use crate::workflows::config_fetch::get_configuration_subtree;
use crate::xml::{multi_re_split, rpc_error_parts, sanitize_rustez_xml};
use crate::{SrxError, SrxToolResponse};
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Config subtree filter for RPC 1.
const CONFIG_FILTER: &str = "<security><dynamic-address/></security>";
/// RPC 2 (verified name).
const SUMMARY_RPC: &str = "get-security-dynamic-address-summary";
/// mecfeed-serve path prefix for the Junos dynamic-address format.
const MECFEED_PATH: &str = "/feeds/junos-dynamic-address/";

// Summary labels. Per-feed labels are from the reference, unverified.
const LABEL_FEED_NAME: &str = "Feed Name";
const LABEL_IPV4: &str = "Total IPv4 entries";
const LABEL_IPV6: &str = "Total IPv6 entries";
const LABEL_NEXT_UPDATE: &str = "Next update";
const LABEL_LAST_STATUS: &str = "Last update status";
const LABELS_ENDING_FEED_BLOCK: [&str; 2] = ["Server Name", "Instance Name"];

const NOT_SUBSCRIBED: &str = "no security dynamic-address feed points at a mecfeedmcp feed path \
     (/feeds/junos-dynamic-address/address|prefix)";
const NO_STATUS: &str = "no status reported (not fetched yet)";
const NO_LAST_STATUS: &str = "no last update status reported";

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for `get_srx_feed_status`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct FeedStatusArgs {
    /// Device name (aliased as router_name).
    #[serde(alias = "router_name")]
    pub router: String,
}

/// mecfeedmcp feed status across all cluster nodes.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct FeedStatusData {
    /// Per-node feed status.
    pub nodes: Vec<NodeFeedStatus>,
}

/// Feed status for one cluster node or a standalone device.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NodeFeedStatus {
    /// Empty string for standalone; "node0" or "node1" for cluster.
    pub re_name: String,
    /// mecfeedmcp feeds in config order.
    pub feeds: Vec<FeedStatus>,
}

/// mecfeedmcp document kind, from the feed URL path.
#[derive(Debug, Serialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeedKind {
    /// `/feeds/junos-dynamic-address/address`
    Address,
    /// `/feeds/junos-dynamic-address/prefix`
    Prefix,
}

/// Status of one subscribed mecfeedmcp feed.
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct FeedStatus {
    /// Config `feed-server` name.
    pub feed_server: String,
    /// Config `feed-name` name.
    pub feed_name: String,
    /// `address-name` whose profile maps this feed; null = not usable in policy.
    pub address_name: Option<String>,
    /// Document kind, from the URL path.
    pub kind: FeedKind,
    /// Effective feed URL with userinfo, query and fragment removed.
    pub url: String,
    /// Summary IPv4 + IPv6 entry totals; null when not reported.
    pub entries: Option<u64>,
    /// Summary `Next update`, device text verbatim.
    pub next_update: Option<String>,
    /// Summary `Last update status`, device text with URLs sanitised.
    pub last_update_status: Option<String>,
    /// Null when the last update succeeded; otherwise why the feed is not healthy.
    pub error: Option<String>,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Read the dynamic-address config and summary, and report mecfeedmcp feeds.
pub async fn run(
    device: &mut PooledDevice,
    args: FeedStatusArgs,
) -> Result<SrxToolResponse<FeedStatusData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;
    let config_xml = get_configuration_subtree(&mut exec, CONFIG_FILTER).await?;
    // A summary failure degrades per node instead of failing the call.
    let summary = exec
        .call(SUMMARY_RPC, &[])
        .await
        .map_err(|e| format!("rpc error: {e}"));
    parse(&config_xml, summary.as_deref().map_err(String::as_str))
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Configured mecfeedmcp feed. Holds raw URLs, so it is never serialized.
struct ConfiguredFeed {
    feed_server: String,
    feed_name: String,
    address_name: Option<String>,
    kind: FeedKind,
    url: String,
    raw_effective_url: String,
    raw_server_url: String,
}

/// One per-feed block of the summary text.
#[derive(Debug, Default, PartialEq, Eq)]
struct SummaryBlock {
    feed_name: String,
    ipv4: Option<u64>,
    ipv6: Option<u64>,
    next_update: Option<String>,
    last_update_status: Option<String>,
}

/// Pure core: config reply plus summary reply (or the reason it failed).
fn parse(
    config_xml: &str,
    summary: Result<&str, &str>,
) -> Result<SrxToolResponse<FeedStatusData>, SrxError> {
    let feeds = configured_feeds(config_xml)?;
    if feeds.is_empty() {
        return Ok(SrxToolResponse::not_configured(NOT_SUBSCRIBED));
    }
    let split = summary
        .map_err(str::to_owned)
        .and_then(|xml| multi_re_split(xml).map_err(|e| e.to_string()));
    let per_node: Vec<(String, Result<Vec<SummaryBlock>, String>)> = match split {
        Ok(re_nodes) if !re_nodes.is_empty() => re_nodes
            .into_iter()
            .map(|n| (n.re_name, summary_blocks(&n.inner_xml)))
            .collect(),
        Ok(_) => vec![(
            String::new(),
            Err("no routing engine returned a summary".into()),
        )],
        Err(reason) => vec![(String::new(), Err(reason))],
    };
    let nodes = per_node
        .into_iter()
        .map(|(re_name, blocks)| NodeFeedStatus {
            re_name,
            feeds: feeds
                .iter()
                .map(|f| feed_status(f, blocks.as_deref()))
                .collect(),
        })
        .collect();
    Ok(SrxToolResponse::active(FeedStatusData { nodes }))
}

/// mecfeedmcp feeds in the config reply, in config order.
///
/// The first node without an rpc-error is read (config is device-wide). A
/// `not-configured` error means nothing is subscribed; any other error fails
/// closed so it cannot read as "not subscribed".
fn configured_feeds(config_xml: &str) -> Result<Vec<ConfiguredFeed>, SrxError> {
    for re_node in multi_re_split(config_xml)? {
        let sanitized = sanitize_rustez_xml(&re_node.inner_xml);
        let doc = roxmltree::Document::parse(&sanitized)
            .map_err(|e| SrxError::Parse(format!("roxmltree: {e}")))?;
        if let Some((tag, message)) = rpc_error_parts(&doc) {
            if tag == "not-configured" {
                continue;
            }
            return Err(SrxError::Rpc {
                tag,
                severity: "error".into(),
                message,
            });
        }
        return Ok(feeds_in(&doc));
    }
    Ok(Vec::new())
}

/// Walk `dynamic-address`. Reads only names, `url`, `path` and
/// `profile/feed-name`: never `user-name`, `password` or `tls-profile`.
fn feeds_in(doc: &roxmltree::Document<'_>) -> Vec<ConfiguredFeed> {
    let Some(dynamic) = doc
        .descendants()
        .find(|n| is_active(n) && n.tag_name().name() == "dynamic-address")
    else {
        return Vec::new();
    };
    let address_names: Vec<(String, String)> = active_children(dynamic, "address-name")
        .filter_map(|a| {
            let feed = active_children(a, "profile")
                .next()
                .and_then(|p| child_text(&p, "feed-name"))?;
            Some((feed, child_text(&a, "name")?))
        })
        .collect();
    let mut feeds = Vec::new();
    for server in active_children(dynamic, "feed-server") {
        let (Some(feed_server), Some(server_url)) =
            (child_text(&server, "name"), child_text(&server, "url"))
        else {
            continue;
        };
        for feed in active_children(server, "feed-name") {
            let Some(feed_name) = child_text(&feed, "name") else {
                continue;
            };
            let effective = match child_text(&feed, "path").filter(|p| !p.is_empty()) {
                Some(path) => format!(
                    "{}/{}",
                    server_url.trim_end_matches('/'),
                    path.trim_start_matches('/')
                ),
                None => server_url.clone(),
            };
            let Some((kind, url)) = mecfeed_url(&effective) else {
                continue;
            };
            let address_name = address_names
                .iter()
                .find(|(mapped, _)| *mapped == feed_name)
                .map(|(_, name)| name.clone());
            feeds.push(ConfiguredFeed {
                feed_server: feed_server.clone(),
                feed_name,
                address_name,
                kind,
                url,
                raw_effective_url: effective,
                raw_server_url: server_url.clone(),
            });
        }
    }
    feeds
}

/// `Some((kind, sanitised url))` when `effective` is an http(s) URL whose
/// path ends in `/feeds/junos-dynamic-address/{address|prefix}`.
fn mecfeed_url(effective: &str) -> Option<(FeedKind, String)> {
    let parsed = url::Url::parse(effective).ok()?;
    // Non-http(s) URLs may have no host, so userinfo could not be removed.
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let kind = match parsed.path().rsplit_once(MECFEED_PATH) {
        Some((_, "address")) => FeedKind::Address,
        Some((_, "prefix")) => FeedKind::Prefix,
        _ => return None,
    };
    Some((kind, strip_secrets(parsed)))
}

/// Remove userinfo, query and fragment.
fn strip_secrets(mut url: url::Url) -> String {
    // Err only for URLs without a host, which cannot carry userinfo.
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.into()
}

/// One node's summary blocks, or why the node gave no summary text.
fn summary_blocks(inner_xml: &str) -> Result<Vec<SummaryBlock>, String> {
    // A node's fragment can hold several sibling elements.
    let wrapped = format!("<_>{inner_xml}</_>");
    let doc = roxmltree::Document::parse(&wrapped).map_err(|e| format!("xml parse: {e}"))?;
    if let Some(output) = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "output")
    {
        return Ok(parse_summary_text(output.text().unwrap_or("")));
    }
    if let Some((_, reason)) = rpc_error_parts(&doc) {
        return Err(reason);
    }
    Err("summary reply carried no <output> text".into())
}

/// Split summary text into per-feed blocks. Total: never fails on odd input.
fn parse_summary_text(text: &str) -> Vec<SummaryBlock> {
    let mut blocks: Vec<SummaryBlock> = Vec::new();
    let mut in_feed_block = false;
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.split_whitespace().collect::<Vec<_>>().join(" ");
        let is = |want: &str| label.eq_ignore_ascii_case(want);
        let value = value.trim();
        if is(LABEL_FEED_NAME) {
            blocks.push(SummaryBlock {
                feed_name: value.to_owned(),
                ..SummaryBlock::default()
            });
            in_feed_block = true;
        } else if LABELS_ENDING_FEED_BLOCK.iter().any(|end| is(end)) {
            in_feed_block = false;
        } else if let Some(block) = blocks.last_mut().filter(|_| in_feed_block) {
            let count = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
            let text = (!value.is_empty()).then(|| value.to_owned());
            // First occurrence wins.
            if is(LABEL_IPV4) {
                block.ipv4 = block.ipv4.or(count);
            } else if is(LABEL_IPV6) {
                block.ipv6 = block.ipv6.or(count);
            } else if is(LABEL_NEXT_UPDATE) {
                block.next_update = block.next_update.take().or(text);
            } else if is(LABEL_LAST_STATUS) {
                block.last_update_status = block.last_update_status.take().or(text);
            }
        }
    }
    blocks
}

/// Assemble one feed's status from its node's summary blocks.
fn feed_status(feed: &ConfiguredFeed, blocks: Result<&[SummaryBlock], &String>) -> FeedStatus {
    let (entries, next_update, last_update_status, error) = match blocks {
        Err(reason) => (
            None,
            None,
            None,
            Some(format!("status unavailable: {reason}")),
        ),
        Ok(blocks) => match blocks.iter().find(|b| b.feed_name == feed.feed_name) {
            None => (None, None, None, Some(NO_STATUS.to_owned())),
            Some(b) => (
                match (b.ipv4, b.ipv6) {
                    (None, None) => None,
                    (v4, v6) => Some(v4.unwrap_or(0).saturating_add(v6.unwrap_or(0))),
                },
                b.next_update.clone(),
                b.last_update_status.clone(),
                status_error(b.last_update_status.as_deref()),
            ),
        },
    };
    let raw_urls = [
        feed.raw_effective_url.as_str(),
        feed.raw_server_url.as_str(),
    ];
    let clean = |text: Option<String>| text.map(|t| scrub(&t, &raw_urls));
    FeedStatus {
        feed_server: feed.feed_server.clone(),
        feed_name: feed.feed_name.clone(),
        address_name: feed.address_name.clone(),
        kind: feed.kind,
        url: feed.url.clone(),
        entries,
        next_update: clean(next_update),
        last_update_status: clean(last_update_status),
        error: clean(error),
    }
}

/// `None` for any `succeeded…` status (covers `succeeded<file not changed>`).
fn status_error(status: Option<&str>) -> Option<String> {
    match status {
        None => Some(NO_LAST_STATUS.to_owned()),
        Some(s) if s.to_ascii_lowercase().starts_with("succeeded") => None,
        Some(s) => Some(s.to_owned()),
    }
}

/// Replace credential-bearing URLs in device text with their sanitised form.
///
/// Exact echoes of `raw_urls` go first (longest first), since they survive
/// delimiter characters inside credentials. Then any other URL token.
fn scrub(text: &str, raw_urls: &[&str]) -> String {
    let mut out = text.to_owned();
    for raw in raw_urls {
        if let Some(clean) = clean_if_secret(raw) {
            out = out.replace(raw, &clean);
        }
    }
    let dirty: Vec<(String, String)> = out
        .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\''))
        .filter(|token| token.contains("://"))
        .filter_map(|token| Some((token.to_owned(), clean_if_secret(token)?)))
        .collect();
    for (token, clean) in dirty {
        out = out.replace(&token, &clean);
    }
    out
}

/// Sanitised `raw` when it parses as a URL with userinfo, a query or a fragment.
fn clean_if_secret(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    let has_secret = !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some();
    if !has_secret {
        return None;
    }
    let clean = strip_secrets(parsed);
    // Url gives an empty path a root "/"; keep the echo's shape so a path that
    // follows a server-URL echo is not doubled.
    if raw.ends_with('/') {
        return Some(clean);
    }
    Some(clean.trim_end_matches('/').to_owned())
}

/// Element children named `name` without Junos's `inactive="inactive"`.
fn active_children<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &'a str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'input>> + 'a {
    node.children()
        .filter(move |n| is_active(n) && n.tag_name().name() == name)
}

/// `true` for an element not deactivated with `inactive="inactive"`.
fn is_active(node: &roxmltree::Node<'_, '_>) -> bool {
    node.is_element() && node.attribute("inactive") != Some("inactive")
}

/// Return the trimmed text of the first direct child element matching `name`.
fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SrxState;
    use pretty_assertions::assert_eq;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/feed_status")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
    }

    /// Parse the subscribed config against a summary fixture; return the nodes.
    fn nodes_for(summary: &str) -> Vec<NodeFeedStatus> {
        let resp = parse(&fixture("config_subscribed.xml"), Ok(&fixture(summary)))
            .expect("parse succeeds");
        assert_eq!(resp.state, SrxState::Active);
        resp.data.expect("active carries data").nodes
    }

    fn feed<'a>(node: &'a NodeFeedStatus, name: &str) -> &'a FeedStatus {
        node.feeds
            .iter()
            .find(|f| f.feed_name == name)
            .unwrap_or_else(|| panic!("feed {name} missing"))
    }

    #[test]
    fn detects_only_mecfeed_paths() {
        let nodes = nodes_for("summary_healthy.xml");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].re_name, "");
        let got: Vec<(&str, &str, FeedKind)> = nodes[0]
            .feeds
            .iter()
            .map(|f| (f.feed_server.as_str(), f.feed_name.as_str(), f.kind))
            .collect();
        // OTHER is foreign and mecfeed-off is deactivated.
        assert_eq!(
            got,
            vec![
                ("MECFEED", "mecfeed-address", FeedKind::Address),
                ("MECFEED", "mecfeed-stray", FeedKind::Prefix),
                ("MECFEED-PFX", "mecfeed-prefix", FeedKind::Prefix),
            ]
        );
    }

    #[test]
    fn url_strips_userinfo_query_fragment() {
        let nodes = nodes_for("summary_healthy.xml");
        let urls: Vec<&str> = nodes[0].feeds.iter().map(|f| f.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://feeds.example.net:8443/feeds/junos-dynamic-address/address",
                "https://feeds.example.net:8443/feeds/junos-dynamic-address/prefix",
                "https://feeds.example.net:8443/proxy/feeds/junos-dynamic-address/prefix",
            ]
        );
    }

    #[test]
    fn serialized_response_never_contains_credentials() {
        for summary in [
            "summary_healthy.xml",
            "summary_failed.xml",
            "summary_cluster.xml",
            "summary_no_feeds.xml",
        ] {
            let resp = parse(&fixture("config_subscribed.xml"), Ok(&fixture(summary)))
                .expect("parse succeeds");
            let json = serde_json::to_string(&resp).expect("serializes");
            for marker in ["QQ", "$9$"] {
                assert!(
                    !json.contains(marker),
                    "{summary}: response leaks {marker}: {json}"
                );
            }
        }
    }

    #[test]
    fn not_configured_when_no_dynamic_address() {
        let not_configured_error = "<rpc-error><error-type>application</error-type>\
             <error-tag>not-configured</error-tag><error-message>not configured</error-message>\
             </rpc-error>";
        for config in [
            "<configuration/>",
            "<configuration><security/></configuration>",
            not_configured_error,
        ] {
            let resp = parse(config, Ok(&fixture("summary_no_feeds.xml"))).expect("parse");
            assert_eq!(resp.state, SrxState::NotConfigured, "config: {config}");
            assert!(
                resp.reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("/feeds/junos-dynamic-address/"),
                "reason names the feed path"
            );
            assert!(resp.data.is_none());
        }
    }

    #[test]
    fn not_configured_when_only_foreign_feeds() {
        let resp = parse(
            &fixture("config_foreign_only.xml"),
            Ok(&fixture("summary_no_feeds.xml")),
        )
        .expect("parse");
        assert_eq!(resp.state, SrxState::NotConfigured);
    }

    #[test]
    fn config_rpc_error_fails_closed() {
        let denied = "<rpc-error><error-type>protocol</error-type>\
             <error-tag>access-denied</error-tag><error-severity>error</error-severity>\
             <error-message>permission denied</error-message></rpc-error>";
        match parse(denied, Ok(&fixture("summary_no_feeds.xml"))) {
            Err(SrxError::Rpc { tag, message, .. }) => {
                assert_eq!(tag, "access-denied");
                assert!(message.contains("permission denied"));
            }
            other => panic!("expected SrxError::Rpc, got {other:?}"),
        }
    }

    #[test]
    fn address_name_none_when_unmapped() {
        let nodes = nodes_for("summary_healthy.xml");
        assert_eq!(
            feed(&nodes[0], "mecfeed-address").address_name.as_deref(),
            Some("MECFEED-ADDRESS")
        );
        assert_eq!(
            feed(&nodes[0], "mecfeed-prefix").address_name.as_deref(),
            Some("MECFEED-PREFIX")
        );
        assert_eq!(feed(&nodes[0], "mecfeed-stray").address_name, None);
    }

    #[test]
    fn healthy_not_changed_and_missing_block_classified() {
        let nodes = nodes_for("summary_healthy.xml");
        let healthy = feed(&nodes[0], "mecfeed-address");
        assert_eq!(healthy.entries, Some(2), "v4 1 + v6 1");
        assert_eq!(
            healthy.next_update.as_deref(),
            Some("2026-10-29 14:10:12 UTC")
        );
        assert_eq!(healthy.last_update_status.as_deref(), Some("succeeded"));
        assert_eq!(healthy.error, None);

        let not_changed = feed(&nodes[0], "mecfeed-prefix");
        assert_eq!(not_changed.entries, Some(2));
        assert_eq!(
            not_changed.last_update_status.as_deref(),
            Some("succeeded<file not changed>")
        );
        assert_eq!(not_changed.error, None);

        let missing = feed(&nodes[0], "mecfeed-stray");
        assert_eq!(missing.entries, None);
        assert_eq!(missing.next_update, None);
        assert_eq!(missing.last_update_status, None);
        assert_eq!(missing.error.as_deref(), Some(NO_STATUS));
    }

    #[test]
    fn instance_totals_are_not_feed_totals() {
        let nodes = nodes_for("summary_no_feeds.xml");
        for f in &nodes[0].feeds {
            assert_eq!(f.entries, None, "{}", f.feed_name);
            assert_eq!(f.error.as_deref(), Some(NO_STATUS), "{}", f.feed_name);
        }
    }

    #[test]
    fn failed_status_is_error_with_raw_url_replaced() {
        let nodes = nodes_for("summary_failed.xml");
        let address = feed(&nodes[0], "mecfeed-address");
        assert_eq!(address.entries, Some(0));
        let want = "failed<http return error code 401 from \
                    https://feeds.example.net:8443/feeds/junos-dynamic-address/address>";
        assert_eq!(address.error.as_deref(), Some(want));
        assert_eq!(address.last_update_status.as_deref(), Some(want));

        assert_eq!(
            feed(&nodes[0], "mecfeed-stray").error.as_deref(),
            Some("failed<tls handshake with https://feeds.example.net:8443 failed>")
        );
        assert_eq!(
            feed(&nodes[0], "mecfeed-prefix").error.as_deref(),
            Some(
                "failed<connect to https://feeds.example.net:8443/proxy/feeds/\
                 junos-dynamic-address/prefix timed out>"
            )
        );
    }

    #[test]
    fn cluster_yields_per_node_status_and_error_slot() {
        let nodes = nodes_for("summary_cluster.xml");
        let names: Vec<&str> = nodes.iter().map(|n| n.re_name.as_str()).collect();
        assert_eq!(names, vec!["node0", "node1"]);

        assert_eq!(feed(&nodes[0], "mecfeed-address").entries, Some(2));
        assert!(nodes[0].feeds.iter().all(|f| f.error.is_none()));

        assert_eq!(nodes[1].feeds.len(), 3, "config feeds repeat on every node");
        for f in &nodes[1].feeds {
            assert_eq!(f.entries, None);
            assert_eq!(
                f.error.as_deref(),
                Some(
                    "status unavailable: rpc-error: dynamic-address daemon not responding \
                     on this node"
                )
            );
        }
    }

    #[test]
    fn summary_failure_degrades_every_feed() {
        let config = fixture("config_subscribed.xml");
        let cases = [
            (
                Err("rpc error: timed out"),
                "status unavailable: rpc error: timed out",
            ),
            (
                Ok("<rpc-error><error-message>syntax error</error-message></rpc-error>"),
                "status unavailable: rpc-error: syntax error",
            ),
            (
                Ok("<dynamic-address-summary/>"),
                "status unavailable: summary reply carried no <output> text",
            ),
            (
                Ok("<multi-routing-engine-results/>"),
                "status unavailable: no routing engine returned a summary",
            ),
        ];
        for (summary, want) in cases {
            let resp = parse(&config, summary).expect("summary failure never fails the call");
            let nodes = resp.data.expect("active").nodes;
            assert_eq!(nodes.len(), 1, "{want}");
            assert_eq!(nodes[0].re_name, "");
            for f in &nodes[0].feeds {
                assert_eq!(f.error.as_deref(), Some(want));
                assert_eq!(f.entries, None);
            }
        }
        // Unparseable XML also degrades rather than failing.
        let resp = parse(&config, Ok("<output>unterminated")).expect("degrades");
        let error = resp.data.expect("active").nodes[0].feeds[0].error.clone();
        assert!(
            error
                .as_deref()
                .unwrap_or("")
                .starts_with("status unavailable: "),
            "{error:?}"
        );
    }

    #[test]
    fn summary_text_parser_tolerates_odd_input() {
        for odd in [
            "",
            ":",
            ":::",
            "no colon here",
            "Feed Name",
            "Total IPv4 entries : 5",
            "\u{fffd}\u{0}: \u{1f600}",
        ] {
            let _ = parse_summary_text(odd);
        }
        assert_eq!(
            parse_summary_text("Total IPv4 entries : 5\nFeed Name"),
            vec![],
            "labels outside a feed block and a value-less label are ignored"
        );

        let text = "  feed   NAME :x\r\n\
                    \x20 Total IPv4 entries : lots\r\n\
                    \x20 Total IPv6 entries : 3 entries\r\n\
                    \x20 Next update :\r\n\
                    \x20 Total IPv6 entries : 9\r\n\
                    Feed Name : y\n\
                    \x20 Total IPv4 entries : 18446744073709551615\n\
                    \x20 Total IPv6 entries : 1\n\
                    Instance Name : default\n\
                    \x20 Last update status : succeeded\n";
        let blocks = parse_summary_text(text);
        assert_eq!(
            blocks,
            vec![
                SummaryBlock {
                    feed_name: "x".into(),
                    ipv4: None,
                    ipv6: Some(3),
                    next_update: None,
                    last_update_status: None,
                },
                SummaryBlock {
                    feed_name: "y".into(),
                    ipv4: Some(u64::MAX),
                    ipv6: Some(1),
                    next_update: None,
                    last_update_status: None,
                },
            ]
        );
    }

    #[test]
    fn block_without_counts_or_status_reports_nulls_and_error() {
        let summary = "<output>Feed Name : mecfeed-address\n  Mapped dynamic address name : X\n\
                       Feed Name : mecfeed-prefix\n  Total IPv4 entries : 18446744073709551615\n\
                       \x20 Total IPv6 entries : 1\n  Last update status : FAILED\n</output>";
        let resp = parse(&fixture("config_subscribed.xml"), Ok(summary)).expect("parse");
        let nodes = resp.data.expect("active").nodes;
        let address = feed(&nodes[0], "mecfeed-address");
        assert_eq!(address.entries, None);
        assert_eq!(address.error.as_deref(), Some(NO_LAST_STATUS));
        let prefix = feed(&nodes[0], "mecfeed-prefix");
        assert_eq!(prefix.entries, Some(u64::MAX), "saturating add");
        assert_eq!(prefix.error.as_deref(), Some("FAILED"));
    }

    #[test]
    fn scrub_catches_url_echo_in_another_form() {
        let raw = [
            "https://QQsvc:QQpw@feeds.example.net:8443/feeds/junos-dynamic-address/address",
            "https://QQsvc:QQpw@feeds.example.net:8443",
        ];
        // Device text with a doubled slash and an extra query: neither raw URL
        // matches the whole echo.
        let text = "data(https://QQsvc:QQpw@feeds.example.net:8443//feeds/x?QQq=1#QQf) \
                    and \"https://QQt@other.example.net/y?QQz\" ok";
        let got = scrub(text, &raw);
        assert!(!got.contains("QQ"), "{got}");
        assert!(
            got.contains("https://feeds.example.net:8443//feeds/x"),
            "{got}"
        );
        assert!(got.contains("https://other.example.net/y"), "{got}");
        // Text without credential-bearing URLs is left alone.
        let clean = "failed<http return error code 404 from https://feeds.example.net/x>";
        assert_eq!(scrub(clean, &raw), clean);
    }

    #[test]
    fn non_http_scheme_is_not_a_mecfeed_feed() {
        let config = "<configuration><security><dynamic-address><feed-server>\
             <name>S</name><url>QQuser:QQpw@feeds.example.net</url>\
             <feed-name><name>f</name><path>feeds/junos-dynamic-address/address</path></feed-name>\
             </feed-server></dynamic-address></security></configuration>";
        let resp = parse(config, Ok("<output/>")).expect("parse");
        assert_eq!(resp.state, SrxState::NotConfigured);
    }
}
