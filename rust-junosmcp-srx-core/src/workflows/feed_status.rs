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
//! - **Credentials:** `user-name`, `password` and `tls-profile` are never read
//!   into the response, and reported `url`s carry no userinfo, query or
//!   fragment. Device text (`next_update`, `last_update_status`, `error`, and
//!   the message of a config-side `SrxError::Rpc` or `SrxError::Parse`) is
//!   scrubbed in three passes, each linear in the text for a given config:
//!   1. An exact echo of a configured raw URL (server or effective) becomes
//!      its sanitised form.
//!   2. Every occurrence of a configured secret becomes `[REDACTED]`, whatever
//!      the echo's shape; overlapping or adjacent occurrences merge into one
//!      `[REDACTED]`. The secrets of every `url` and `path` leaf and every
//!      effective URL are its username, password, query string and fragment
//!      split by text, plus, when the `url` parser accepts it, the username
//!      and password as that parser reads them, raw and percent-decoded.
//!      Every `user-name` and `password` value is a secret too. All come from
//!      a textual scan of the raw config reply, so a reply that does not parse
//!      is covered, as are foreign and deactivated feeds; a leaf with no
//!      matching close tag contributes its text up to the next tag.
//!   3. Best effort, for URLs not in the config: a token split on whitespace
//!      and `<>()"'` that parses as a URL with userinfo, a query or a fragment
//!      is sanitised.
//!
//!   If a matcher cannot be built or a search fails, the whole text becomes
//!   `[REDACTED]`. Not guaranteed: a configured secret echoed in any other
//!   encoding than those above (for example re-escaped); a query value echoed
//!   without its `key=`, which is redacted only when it equals a whole
//!   configured query or fragment string; a credential of an unconfigured URL
//!   that is not one parseable token; a single parameter of a multi-parameter
//!   query echoed together with its key (`token=QQtok` from `a=1&token=QQtok`).
//!   A short secret also redacts unrelated
//!   text that contains it.
//! - **Failures:** a config rpc-error other than `not-configured` fails
//!   closed (`SrxError::Rpc`). A summary failure degrades only the affected
//!   node: its feeds carry `error: "status unavailable: …"`.
//! - Junos does not report the fetched feed ETag, so there is no
//!   `content_etag`; compare `entries` and `last_update_status` with the feed
//!   server.

use crate::workflows::config_fetch::get_configuration_subtree;
use crate::xml::{multi_re_split, rpc_error_parts, sanitize_rustez_xml};
use crate::{SrxError, SrxToolResponse};
use aho_corasick::{AhoCorasick, MatchKind};
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
const REDACTED: &str = "[REDACTED]";

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
    /// Summary `Next update`, device text with credentials scrubbed.
    pub next_update: Option<String>,
    /// Summary `Last update status`, device text with credentials scrubbed.
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
}

/// One per-feed block of the summary text.
#[derive(Debug, Default, PartialEq, Eq)]
struct SummaryBlock {
    feed_name: String,
    /// `None`: label absent; `Some(None)`: present but does not parse.
    ipv4: Option<Option<u64>>,
    ipv6: Option<Option<u64>>,
    next_update: Option<String>,
    last_update_status: Option<String>,
}

/// Pure core: config reply plus summary reply (or the reason it failed).
fn parse(
    config_xml: &str,
    summary: Result<&str, &str>,
) -> Result<SrxToolResponse<FeedStatusData>, SrxError> {
    let feeds =
        configured_feeds(config_xml).map_err(|e| Scrubber::new(config_xml, &[]).scrub_error(e))?;
    if feeds.is_empty() {
        return Ok(SrxToolResponse::not_configured(NOT_SUBSCRIBED));
    }
    let effective_urls: Vec<&str> = feeds.iter().map(|f| f.raw_effective_url.as_str()).collect();
    let scrubber = Scrubber::new(config_xml, &effective_urls);
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
                .map(|f| feed_status(f, blocks.as_deref(), &scrubber))
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
                block.ipv4 = block.ipv4.or(Some(count));
            } else if is(LABEL_IPV6) {
                block.ipv6 = block.ipv6.or(Some(count));
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
fn feed_status(
    feed: &ConfiguredFeed,
    blocks: Result<&[SummaryBlock], &String>,
    scrubber: &Scrubber,
) -> FeedStatus {
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
                entry_total(b.ipv4, b.ipv6),
                b.next_update.clone(),
                b.last_update_status.clone(),
                status_error(b.last_update_status.as_deref()),
            ),
        },
    };
    let clean = |text: Option<String>| text.map(|t| scrubber.scrub(&t));
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

/// v4 + v6, an absent label counting as 0. `None` when neither label is
/// present or a present one does not parse, so a partial sum never
/// under-reports.
fn entry_total(ipv4: Option<Option<u64>>, ipv6: Option<Option<u64>>) -> Option<u64> {
    if ipv4.is_none() && ipv6.is_none() {
        return None;
    }
    Some(
        ipv4.unwrap_or(Some(0))?
            .saturating_add(ipv6.unwrap_or(Some(0))?),
    )
}

/// Removes configured credentials from device text (module doc, "Credentials").
struct Scrubber {
    /// `None` when a matcher could not be built; `scrub` then fails closed.
    matchers: Option<Matchers>,
}

struct Matchers {
    /// Raw URLs that carry a secret, matched leftmost-longest.
    exact: AhoCorasick,
    /// Sanitised form of each `exact` pattern, by pattern index.
    sanitised: Vec<String>,
    /// Secret needles, matched with overlaps.
    secrets: AhoCorasick,
}

impl Scrubber {
    /// Secrets from a textual scan of the raw config reply, plus the
    /// reported feeds' effective URLs.
    fn new(config_xml: &str, effective_urls: &[&str]) -> Self {
        // Older transports deliver a bare `<` inside leaf text; escape it so
        // the leaf is not cut there.
        let config_xml = sanitize_rustez_xml(config_xml);
        let config_xml = config_xml.as_ref();
        let mut raw_urls = leaf_texts(config_xml, "url");
        raw_urls.extend(leaf_texts(config_xml, "path"));
        raw_urls.extend(effective_urls.iter().map(|u| (*u).to_owned()));
        let mut exact: Vec<(String, String)> = Vec::new();
        let mut secrets: Vec<String> = Vec::new();
        for raw in &raw_urls {
            if let Some(clean) = clean_if_secret(raw) {
                exact.push((raw.clone(), clean));
            }
            secrets.extend(secret_parts(raw).into_iter().map(str::to_owned));
            // The lenient parser that accepts a feed also finds userinfo the
            // text split misses (`https:u:p@h`, `https:/u:p@h`, `https:///u:p@h`).
            if let Ok(parsed) = url::Url::parse(raw) {
                for part in [parsed.username(), parsed.password().unwrap_or("")] {
                    secrets.push(part.to_owned());
                    if let Ok(decoded) = percent_encoding::percent_decode_str(part).decode_utf8() {
                        secrets.push(decoded.into_owned());
                    }
                }
            }
        }
        // Never read into the response, but device text could echo them.
        secrets.extend(leaf_texts(config_xml, "user-name"));
        secrets.extend(leaf_texts(config_xml, "password"));
        // An empty needle would match everywhere.
        secrets.retain(|needle| !needle.is_empty());
        let (raw, sanitised): (Vec<String>, Vec<String>) = exact.into_iter().unzip();
        let exact = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&raw)
            .ok();
        let matchers = exact
            .zip(AhoCorasick::new(&secrets).ok())
            .map(|(exact, secrets)| Matchers {
                exact,
                sanitised,
                secrets,
            });
        Self { matchers }
    }

    /// The three passes; the whole text becomes `[REDACTED]` on any failure.
    fn scrub(&self, text: &str) -> String {
        self.try_scrub(text).unwrap_or_else(|| REDACTED.to_owned())
    }

    fn try_scrub(&self, text: &str) -> Option<String> {
        let matchers = self.matchers.as_ref()?;
        let exact = matchers
            .exact
            .try_replace_all(text, &matchers.sanitised)
            .ok()?;
        let redacted = redact_overlapping(&matchers.secrets, &exact)?;
        Some(sanitize_url_tokens(&redacted))
    }

    /// Scrub the device-supplied message of a config-side error.
    fn scrub_error(&self, error: SrxError) -> SrxError {
        match error {
            SrxError::Rpc {
                tag,
                severity,
                message,
            } => SrxError::Rpc {
                tag,
                severity,
                message: self.scrub(&message),
            },
            SrxError::Parse(message) => SrxError::Parse(self.scrub(&message)),
            other => other,
        }
    }
}

/// Replace every occurrence of every needle, overlapping ones included, with
/// one `[REDACTED]` per merged run. `None` when the search fails.
fn redact_overlapping(needles: &AhoCorasick, text: &str) -> Option<String> {
    // Runs stay sorted and disjoint: hits arrive ordered by end, so a hit can
    // only overlap or touch the trailing runs.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for hit in needles.try_find_overlapping_iter(text).ok()? {
        let (mut start, mut end) = (hit.start(), hit.end());
        while let Some(&(run_start, run_end)) = runs.last() {
            if start > run_end {
                break;
            }
            start = start.min(run_start);
            end = end.max(run_end);
            runs.pop();
        }
        runs.push((start, end));
    }
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, end) in runs {
        out.push_str(text.get(copied..start)?);
        out.push_str(REDACTED);
        copied = end;
    }
    out.push_str(text.get(copied..)?);
    Some(out)
}

/// Entity-decoded, trimmed text of every `<tag>…</tag>` element, found by
/// text so a reply that does not parse still yields its values.
fn leaf_texts(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("/{tag}>");
    let mut texts = Vec::new();
    let mut rest = xml;
    while let Some((_, after_open)) = rest.split_once(open.as_str()) {
        rest = after_open;
        // `<url>` or `<url attr…>`; not `<url-x>` or `<url/>`.
        if !after_open.starts_with(|c: char| c == '>' || c.is_whitespace()) {
            continue;
        }
        let Some((attributes, body)) = after_open.split_once('>') else {
            break;
        };
        if attributes.ends_with('/') {
            continue;
        }
        // Leaf text runs to the next `<`. A malformed leaf (no matching close
        // tag there) still yields its text, failing closed, and the scan
        // resumes inside it so the following leaves are not swallowed.
        let (text, after_lt) = body.split_once('<').unwrap_or((body, ""));
        texts.push(decode_entities(text.trim()));
        rest = after_lt.strip_prefix(close.as_str()).unwrap_or(body);
    }
    texts
}

/// Decode the five predefined XML entities (`&amp;` last).
fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Username, password, query and fragment of `raw`, split by text so a URL
/// the parser rejects still yields them. Empty parts are dropped.
fn secret_parts(raw: &str) -> Vec<&str> {
    let (before_fragment, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let (before_query, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    // Userinfo runs to the last `@` before the query, so a raw `/` in a
    // password is still caught.
    let userinfo = before_query
        .split_once("://")
        .and_then(|(_, rest)| rest.rsplit_once('@'))
        .map_or("", |(userinfo, _)| userinfo);
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    [username, password, query, fragment]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect()
}

/// Backstop pass: each token that parses as a URL with userinfo, a query or
/// a fragment is sanitised. One pass; delimiters are kept.
fn sanitize_url_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive(is_token_delimiter) {
        let token = piece.strip_suffix(is_token_delimiter).unwrap_or(piece);
        let clean = token
            .contains("://")
            .then(|| clean_if_secret(token))
            .flatten();
        out.push_str(clean.as_deref().unwrap_or(token));
        out.push_str(piece.strip_prefix(token).unwrap_or(""));
    }
    out
}

fn is_token_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\'')
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

/// Trimmed text of the first active direct child element named `name`.
fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| is_active(n) && n.tag_name().name() == name)
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
                    ipv4: Some(None),
                    ipv6: Some(Some(3)),
                    next_update: None,
                    last_update_status: None,
                },
                SummaryBlock {
                    feed_name: "y".into(),
                    ipv4: Some(Some(u64::MAX)),
                    ipv6: Some(Some(1)),
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
        let scrubber = Scrubber::new(
            "<url>https://QQsvc:QQpw@feeds.example.net:8443</url>",
            &["https://QQsvc:QQpw@feeds.example.net:8443/feeds/junos-dynamic-address/address"],
        );
        // A doubled slash and an extra query (neither raw URL matches the whole
        // echo), and an unconfigured URL left to the token backstop.
        let text = "data(https://QQsvc:QQpw@feeds.example.net:8443//feeds/x?QQq=1#QQf) \
                    and \"https://QQt@other.example.net/y?QQz\" ok";
        let got = scrubber.scrub(text);
        assert!(!got.contains("QQ"), "{got}");
        assert!(
            got.contains("https://feeds.example.net:8443//feeds/x"),
            "{got}"
        );
        assert!(got.contains("https://other.example.net/y"), "{got}");
        // Text without credential-bearing URLs is left alone.
        let clean = "failed<http return error code 404 from https://feeds.example.net/x>";
        assert_eq!(scrubber.scrub(clean), clean);
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

    // ── Fix round 1 ───────────────────────────────────────────────────────────

    /// One mecfeed feed whose server URL carries `QQa:QQb` and path `?token=QQtok`.
    const PROBE_CONFIG: &str = "<configuration><security><dynamic-address><feed-server>\
         <name>S</name><url>https://QQa:QQb@feeds.example.net:8443</url>\
         <feed-name><name>f</name><path>feeds/junos-dynamic-address/address?token=QQtok</path>\
         </feed-name></feed-server></dynamic-address></security></configuration>";

    /// Serialized response for a summary whose `Last update status` is `status`.
    fn status_echo(status: &str) -> String {
        status_echo_with(PROBE_CONFIG, status)
    }

    /// As [`status_echo`], against `config`; the feed must be named `f`.
    fn status_echo_with(config: &str, status: &str) -> String {
        let escaped = status
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let summary = format!("<output>Feed Name : f\n  Last update status : {escaped}\n</output>");
        let resp = parse(config, Ok(&summary)).expect("parse");
        assert_eq!(resp.state, SrxState::Active, "feed f must be subscribed");
        serde_json::to_string(&resp).expect("serializes")
    }

    /// A one-feed config with `server_url` and optional Basic-auth leaves.
    fn feed_config(server_url: &str, auth: &str) -> String {
        format!(
            "<configuration><security><dynamic-address><feed-server>\
             <name>S</name><url>{server_url}</url>{auth}\
             <feed-name><name>f</name><path>feeds/junos-dynamic-address/address</path>\
             </feed-name></feed-server></dynamic-address></security></configuration>"
        )
    }

    fn assert_no_probe_secret(text: &str, context: &str) {
        for secret in ["QQa", "QQb", "QQtok"] {
            assert!(!text.contains(secret), "{context}: leaks {secret}: {text}");
        }
    }

    #[test]
    fn configured_secrets_redacted_in_any_echo_shape() {
        for probe in [
            "url=https://QQa:QQb@h/x",
            "url:https://QQa:QQb@h/x",
            "[https://QQa:QQb@h/x]",
            "{https://QQa:QQb@h/x}",
            "https://QQa:QQb@h:99999/x",
            "https://QQa:QQb@",
            "/feeds/junos-dynamic-address/address?token=QQtok",
        ] {
            assert_no_probe_secret(&status_echo(probe), probe);
        }
    }

    #[test]
    fn exact_echo_still_becomes_the_sanitised_url() {
        let json = status_echo(
            "failed<401 from https://QQa:QQb@feeds.example.net:8443/feeds/\
             junos-dynamic-address/address?token=QQtok>",
        );
        assert!(
            json.contains(
                "failed<401 from https://feeds.example.net:8443/feeds/junos-dynamic-address/address>"
            ),
            "{json}"
        );
    }

    #[test]
    fn scrub_is_linear_on_large_device_text() {
        let start = std::time::Instant::now();
        // 880 KB of credential-bearing URL tokens: one full-string replace per
        // token made this quadratic.
        let json = status_echo(&"http://a@b ".repeat(80_000));
        assert!(!json.contains("a@b"));
        // Uncut: every token survives sanitised, in both status and error.
        assert_eq!(json.matches("http://b").count(), 160_000);
        assert!(start.elapsed().as_secs() < 5);
    }

    #[test]
    fn config_rpc_error_message_is_scrubbed() {
        let cluster = format!(
            "<multi-routing-engine-results>\
             <multi-routing-engine-item><re-name>node0</re-name><rpc-error>\
             <error-tag>operation-failed</error-tag>\
             <error-message>cannot read url:https://QQa:QQb@x?token=QQtok</error-message>\
             </rpc-error></multi-routing-engine-item>\
             <multi-routing-engine-item><re-name>node1</re-name>{PROBE_CONFIG}\
             </multi-routing-engine-item></multi-routing-engine-results>"
        );
        match parse(&cluster, Ok("<output/>")) {
            Err(SrxError::Rpc { message, .. }) => {
                assert_no_probe_secret(&message, "rpc message");
                assert!(message.starts_with("rpc-error: cannot read"), "{message}");
            }
            other => panic!("expected SrxError::Rpc, got {other:?}"),
        }
    }

    #[test]
    fn config_parse_error_message_is_scrubbed() {
        // The stray close tag puts the password into roxmltree's message.
        let malformed = "<configuration><url>https://QQa:QQb@feeds.example.net</url></QQb>";
        match parse(malformed, Ok("<output/>")) {
            Err(SrxError::Parse(message)) => assert_no_probe_secret(&message, "parse message"),
            other => panic!("expected SrxError::Parse, got {other:?}"),
        }
    }

    #[test]
    fn entries_null_when_a_present_count_does_not_parse() {
        let summary = "<output>Feed Name : f\n  Total IPv4 entries : 5\n\
                       \x20 Total IPv6 entries : n/a\n  Last update status : succeeded\n</output>";
        let resp = parse(PROBE_CONFIG, Ok(summary)).expect("parse");
        let nodes = resp.data.expect("active").nodes;
        assert_eq!(feed(&nodes[0], "f").entries, None, "no partial sum");
        // An absent label still counts as zero.
        let summary = "<output>Feed Name : f\n  Total IPv4 entries : 5\n</output>";
        let resp = parse(PROBE_CONFIG, Ok(summary)).expect("parse");
        assert_eq!(
            resp.data.expect("active").nodes[0].feeds[0].entries,
            Some(5)
        );
    }

    #[test]
    fn deactivated_url_or_path_leaf_is_ignored() {
        let config = "<configuration><security><dynamic-address>\
             <feed-server><name>A</name>\
             <url inactive=\"inactive\">https://feeds.example.net/feeds/junos-dynamic-address/address</url>\
             <feed-name><name>a</name></feed-name></feed-server>\
             <feed-server><name>B</name>\
             <url>https://feeds.example.net/feeds/junos-dynamic-address/prefix</url>\
             <feed-name><name>b</name>\
             <path inactive=\"inactive\">feeds/junos-dynamic-address/address</path>\
             </feed-name></feed-server>\
             </dynamic-address></security></configuration>";
        let resp = parse(config, Ok("<output/>")).expect("parse");
        let feeds = &resp.data.expect("active").nodes[0].feeds;
        assert_eq!(feeds.len(), 1, "server A has no active url");
        assert_eq!(feeds[0].feed_name, "b");
        assert_eq!(
            feeds[0].kind,
            FeedKind::Prefix,
            "inactive path is not joined"
        );
        assert_eq!(
            feeds[0].url,
            "https://feeds.example.net/feeds/junos-dynamic-address/prefix"
        );
    }

    // ── Fix round 2 ───────────────────────────────────────────────────────────

    #[test]
    fn lenient_url_forms_still_yield_userinfo_needles() {
        // The `url` parser accepts these as subscribed feeds, but none has a
        // literal `://` before the userinfo (or it has an extra `/`).
        for server_url in [
            r"https:QQa:QQb@feeds.example.net:8443",
            r"https:/QQa:QQb@feeds.example.net:8443",
            r"https:\QQa:QQb@feeds.example.net:8443",
            r"https:\\QQa:QQb@feeds.example.net:8443",
            r"https:///QQa:QQb@feeds.example.net:8443",
        ] {
            let config = feed_config(server_url, "");
            for echo in [
                "url=https://QQa:QQb@h/x",
                "url:https://QQa:QQb@h/x",
                "[https://QQa:QQb@h/x]",
                "{https://QQa:QQb@h/x}",
                "https://QQa:QQb@h:99999/x",
                "https://QQa:QQb@",
                "user QQa rejected",
                "password QQb invalid",
                server_url,
            ] {
                let json = status_echo_with(&config, echo);
                for secret in ["QQa", "QQb"] {
                    assert!(
                        !json.contains(secret),
                        "url {server_url}, echo {echo}: leaks {secret}: {json}"
                    );
                }
            }
        }
    }

    #[test]
    fn overlapping_secrets_merge_into_one_redaction() {
        let config = feed_config(
            "https://feeds.example.net:8443",
            "<user-name>adminQQ</user-name><password>QQpass</password>",
        );
        let status = |echo: &str| -> String {
            let resp = parse(
                &config,
                Ok(&format!(
                    "<output>Feed Name : f\n  Last update status : {echo}\n</output>"
                )),
            )
            .expect("parse");
            let mut nodes = resp.data.expect("active").nodes;
            nodes
                .remove(0)
                .feeds
                .remove(0)
                .last_update_status
                .expect("status")
        };
        assert_eq!(status("adminQQpass"), REDACTED);
        assert_eq!(status("x adminQQpass y"), format!("x {REDACTED} y"));
        // Adjacent occurrences merge too.
        assert_eq!(status("adminQQQQpass"), REDACTED);

        // A needle overlapping itself.
        let self_overlap = feed_config(
            "https://feeds.example.net:8443",
            "<user-name>QQxQQ</user-name>",
        );
        let resp = parse(
            &self_overlap,
            Ok("<output>Feed Name : f\n  Last update status : QQxQQxQQ!\n</output>"),
        )
        .expect("parse");
        let got = resp.data.expect("active").nodes[0].feeds[0]
            .last_update_status
            .clone();
        assert_eq!(got.as_deref(), Some("[REDACTED]!"));
    }

    #[test]
    fn scrubber_keeps_a_secret_containing_a_bare_angle_bracket_whole() {
        // rustnetconf decodes `&lt;` in leaf text, so the config can carry a bare `<`.
        let xml = "<url>https://ZZuser:ZZhead<-ZZtail@h/feeds/junos-dynamic-address/address</url>";
        let got = Scrubber::new(xml, &[]).scrub("echo ZZhead<-ZZtail end");
        assert!(!got.contains("ZZ"), "{got}");
    }

    #[test]
    fn leaf_texts_skips_a_malformed_leaf_and_continues() {
        // A mis-closed leaf, a good one, then an unclosed one at the end.
        let xml = "<url>https://QQa:QQb@x</path><url>https://QQc:QQd@h</url><url>https://QQe:QQf@t";
        assert_eq!(
            leaf_texts(xml, "url"),
            vec![
                "https://QQa:QQb@x",
                "https://QQc:QQd@h",
                "https://QQe:QQf@t"
            ]
        );
        let got = Scrubber::new(xml, &[]).scrub("QQa QQb QQc QQd QQe QQf");
        assert!(!got.contains("QQ"), "{got}");
    }
}
