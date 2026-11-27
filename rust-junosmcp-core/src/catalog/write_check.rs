//! Write-path validation: reject configuration paths the device's release
//! does not have, the main defence against invented configuration.

use rustez::ConfigPayload;

use super::{Catalog, Family, Resolution};
use crate::error::JmcpError;

/// `set`-format verbs whose argument is a configuration path. Other verbs
/// (`insert`, `rename`, `annotate`, `copy`, `edit`, ...) are left to the device.
const PATH_VERBS: [&str; 6] = [
    "set",
    "delete",
    "deactivate",
    "activate",
    "protect",
    "unprotect",
];
/// Bad lines named in one error or warning; the rest are counted.
const MAX_REPORTED: usize = 20;
const MAX_SUGGESTIONS: usize = 3;
/// Paths devices accept that Juniper's published YANG lacks, found by loading
/// real configurations (the bench-lab baselines). Add to this when a real
/// configuration line is falsely rejected.
const KNOWN_OMISSIONS: &[&[&str]] = &[
    // SRX branch factory default (SRX345, SRX1600 on 25.4).
    &["system", "phone-home"],
];

/// Whether a token path exists on a resolved train.
type PathCheck = fn(&Catalog, &Resolution, &[&str]) -> bool;

/// Checks every configuration path in `payload` against the resolved train.
///
/// `set` lines check the path after the verb; text and XML check top-level and
/// second-level statement names only. Skips `groups`, `apply-groups`,
/// comments, blank lines and wildcard (`<*>`) or `replace:`-style markers.
///
/// On an exact resolution (`res.warning.is_none()`) unknown paths are an
/// error naming each bad line and up to 3 nearest catalog paths; otherwise
/// they come back as warnings, since the catalog may not match the device.
pub fn check_config_paths(
    catalog: &Catalog,
    res: &Resolution,
    payload: &ConfigPayload,
) -> Result<Vec<String>, JmcpError> {
    let (paths, exists): (_, PathCheck) = match payload {
        ConfigPayload::Set(text) => (set_paths(text), Catalog::config_path_exists),
        ConfigPayload::Text(text) => (text_paths(text), Catalog::config_path_exists),
        ConfigPayload::Xml(text) => (xml_paths(text), xml_path_exists),
    };
    // Juniper's junos-evo YANG omits the SRX security hierarchy that SRX
    // models running Junos OS Evolved (SRX4xx) accept, so an EVO path also
    // passes when junos-es has it.
    let es = (res.family == Family::JunosEvo)
        .then(|| catalog.resolve(Family::JunosEs, res.requested, true));
    let bad: Vec<(String, Vec<String>)> = paths
        .into_iter()
        .filter(|(_, tokens)| !skipped(tokens))
        .filter(|(_, tokens)| {
            let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
            !(exists(catalog, res, &tokens)
                || es.as_ref().is_some_and(|es| exists(catalog, es, &tokens))
                || KNOWN_OMISSIONS
                    .iter()
                    .any(|omitted| tokens.starts_with(omitted)))
        })
        .collect();
    if bad.is_empty() {
        return Ok(Vec::new());
    }

    let mut lines: Vec<String> = bad
        .iter()
        .take(MAX_REPORTED)
        .map(|(line, tokens)| {
            let nearest = nearest(catalog, res, tokens);
            if nearest.is_empty() {
                format!("`{line}`")
            } else {
                format!("`{line}` (nearest: {})", nearest.join(", "))
            }
        })
        .collect();
    if bad.len() > MAX_REPORTED {
        lines.push(format!("and {} more", bad.len() - MAX_REPORTED));
    }
    let target = format!("{} {}", res.family, res.used);
    match &res.warning {
        None => Err(JmcpError::Validation(format!(
            "configuration paths not in the {target} API catalog: {}. Use lookup_junos_api \
             (kind=config) to find the right path.",
            lines.join("; ")
        ))),
        Some(why) => Ok(vec![format!(
            "configuration paths not in the {target} API catalog were not rejected because {why}: {}",
            lines.join("; ")
        )]),
    }
}

/// True for paths the catalog cannot judge: group definitions and references,
/// and wildcard or template markers.
fn skipped(tokens: &[String]) -> bool {
    tokens.first().is_none_or(|first| first == "groups")
        || tokens.iter().any(|token| {
            token == "apply-groups"
                || token == "apply-groups-except"
                || token == "wildcard"
                || token.starts_with('<')
        })
}

/// Splits on whitespace, keeping a double-quoted string (with `\"` escapes)
/// as one token.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quoted => {
                current.push(ch);
                current.extend(chars.next());
            }
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ch if ch.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// `(line, path tokens)` for each path-verb line of a `set`-format load.
fn set_paths(text: &str) -> Vec<(String, Vec<String>)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("/*"))
        .filter_map(|line| {
            let mut tokens = tokenize(line);
            if tokens.len() < 2 || !PATH_VERBS.contains(&tokens[0].as_str()) {
                return None;
            }
            tokens.remove(0);
            Some((line.to_owned(), tokens))
        })
        .collect()
}

/// Strips `/* ... */` and `#` comments outside quoted strings.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quoted => {
                out.push(ch);
                out.extend(chars.next());
            }
            '"' => {
                quoted = !quoted;
                out.push(ch);
            }
            '/' if !quoted && chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for next in chars.by_ref() {
                    if last == '*' && next == '/' {
                        break;
                    }
                    last = next;
                }
                out.push(' ');
            }
            '#' if !quoted => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ch => out.push(ch),
        }
    }
    out
}

/// `(statement, path tokens)` for each top-level and second-level statement
/// of a curly-brace load.
fn text_paths(text: &str) -> Vec<(String, Vec<String>)> {
    let text = strip_comments(text);
    let mut paths = Vec::new();
    // Tokens of the open top-level statement while at depth >= 1.
    let mut top: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut statement = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in text.chars() {
        if quoted {
            statement.push(ch);
            match ch {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => {
                quoted = true;
                statement.push(ch);
            }
            '{' | ';' | '}' => {
                let mut tokens = tokenize(&statement);
                statement.clear();
                // `replace:`, `inactive:`, `protect:` ... mark a statement.
                if tokens.first().is_some_and(|token| token.ends_with(':')) {
                    tokens.remove(0);
                }
                if !tokens.is_empty() {
                    match depth {
                        0 => {
                            paths.push((tokens.join(" "), tokens.clone()));
                            top = tokens;
                        }
                        1 => {
                            let mut path = top.clone();
                            path.extend(tokens);
                            paths.push((path.join(" "), path));
                        }
                        _ => {}
                    }
                }
                match ch {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            ch => statement.push(ch),
        }
    }
    paths
}

/// `(element path, names)` for each top-level and second-level element of an
/// XML load, below an optional `<configuration>` wrapper.
fn xml_paths(text: &str) -> Vec<(String, Vec<String>)> {
    let mut paths = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if let Some(after) = rest.strip_prefix("!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            continue;
        }
        if let Some(after) = rest.strip_prefix("![CDATA[") {
            rest = after.find("]]>").map_or("", |end| &after[end + 3..]);
            continue;
        }
        let Some(end) = rest.find('>') else {
            break;
        };
        let tag = &rest[..end];
        rest = &rest[end + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if tag.starts_with('/') {
            stack.pop();
            continue;
        }
        let name = tag
            .split(|ch: char| ch.is_whitespace() || ch == '/')
            .next()
            .unwrap_or_default();
        // Namespace prefixes (`junos:`) are not part of the path.
        let name = name.rsplit(':').next().unwrap_or_default().to_owned();
        let wrapped = stack.first().is_some_and(|first| first == "configuration");
        let depth = stack.len() - usize::from(wrapped);
        if !(stack.is_empty() && name == "configuration") && depth < 2 {
            let mut path: Vec<String> = stack.iter().skip(usize::from(wrapped)).cloned().collect();
            path.push(name.clone());
            paths.push((path.join(" "), path));
        }
        if !tag.ends_with('/') {
            stack.push(name);
        }
    }
    paths
}

/// Whether XML element names (`["system", "host-name"]`) are a catalog
/// path. XML never elides list keywords, so the names must match exactly,
/// except below a list that mirrors the root hierarchy (`logical-systems`).
fn xml_path_exists(catalog: &Catalog, res: &Resolution, names: &[&str]) -> bool {
    let Some(data) = catalog.config_data(res.family) else {
        return false;
    };
    let node = |path: &str| {
        data.entries
            .get(path)
            .and_then(|variants| variants.iter().find(|v| v.trains.contains(&res.used)))
    };
    let mirrors_root = names
        .first()
        .and_then(|first| node(first))
        .is_some_and(|entry| {
            entry
                .note
                .as_deref()
                .is_some_and(|note| note.contains("root hierarchy"))
        });
    match names {
        [_, second] if mirrors_root => node(second).is_some() || second == &"name",
        _ => node(&names.join(" ")).is_some(),
    }
}

/// Levenshtein distance between two tokens.
fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut row: Vec<usize> = (0..=right.len()).collect();
    for (i, lch) in left.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, rch) in right.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (above + 1)
                .min(row[j] + 1)
                .min(diagonal + usize::from(lch != *rch));
            diagonal = above;
        }
    }
    row[right.len()]
}

/// Up to 3 catalog paths nearest the first bad token of `tokens`: paths whose
/// parent words all appear earlier in the line, most shared words first, then
/// by edit distance of their last word to the bad token.
fn nearest(catalog: &Catalog, res: &Resolution, tokens: &[String]) -> Vec<String> {
    let Some(data) = catalog.config_data(res.family) else {
        return Vec::new();
    };
    let in_train: Vec<&String> = data
        .entries
        .iter()
        .filter(|(_, variants)| variants.iter().any(|v| v.trains.contains(&res.used)))
        .map(|(path, _)| path)
        .collect();
    let words: std::collections::HashSet<&str> =
        in_train.iter().flat_map(|path| path.split(' ')).collect();
    let closest_word = |token: &str| {
        words
            .iter()
            .map(|word| edit_distance(token, word))
            .min()
            .unwrap_or(usize::MAX)
    };
    // The bad token: the first one that is not a catalog word but is close to
    // one (a typo), else the last token (an invented name or value).
    let bad = tokens
        .iter()
        .position(|token| {
            !words.contains(token.as_str()) && closest_word(token) <= token.len().div_ceil(3)
        })
        .unwrap_or(tokens.len().saturating_sub(1));
    let Some(bad_token) = tokens.get(bad) else {
        return Vec::new();
    };
    let before: std::collections::HashSet<&str> =
        tokens[..bad].iter().map(String::as_str).collect();

    let is_list = |path: &str| {
        data.entries.get(path).is_some_and(|variants| {
            variants
                .iter()
                .any(|v| v.trains.contains(&res.used) && v.kind == "list")
        })
    };
    // (parent words found in the line, edit distance, depth, path). A parent
    // word missing from the line is allowed only where the CLI elides it: a
    // list keyword (`interfaces ge-0/0/0` for `interfaces interface ge-0/0/0`).
    let mut ranked: Vec<(usize, usize, usize, &String)> = in_train
        .into_iter()
        .filter_map(|path| {
            let (parent, last) = path.rsplit_once(' ').unwrap_or(("", path));
            let mut matched = 0;
            let mut prefix = String::new();
            for word in parent.split(' ').filter(|w| !w.is_empty()) {
                if !prefix.is_empty() {
                    prefix.push(' ');
                }
                prefix.push_str(word);
                if before.contains(word) {
                    matched += 1;
                } else if !is_list(&prefix) {
                    return None;
                }
            }
            Some((
                matched,
                edit_distance(bad_token, last),
                path.matches(' ').count(),
                path,
            ))
        })
        .collect();
    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(&right.2))
            .then(left.3.cmp(right.3))
    });
    ranked
        .into_iter()
        .take(MAX_SUGGESTIONS)
        .map(|(.., path)| path.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::{Train, fixture_catalog};
    use super::*;

    fn resolution(major: u16, minor: u16) -> Resolution {
        fixture_catalog().resolve(Family::JunosEs, Train { major, minor }, true)
    }

    fn set(text: &str) -> ConfigPayload {
        ConfigPayload::Set(text.into())
    }

    #[test]
    fn write_check_accepts_known_set_paths() {
        let warnings = check_config_paths(
            &fixture_catalog(),
            &resolution(25, 4),
            &set(
                "set system name-server 1.1.1.2 routing-instance mgmt_junos\n\
                  delete interfaces ge-0/0/0 unit 0\n\
                  deactivate security policies from-zone a to-zone b policy \"p 1\"\n\
                  set system host-name \"r1 lab\"\n\
                  rename interfaces ge-0/0/0 to ge-0/0/1",
            ),
        )
        .unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn write_check_rejects_typo_with_suggestion() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let error = check_config_paths(
            &catalog,
            &res,
            &set("set securty policies from-zone a to-zone b policy p match source-address any"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("set securty policies"), "{error}");
        assert!(error.contains("nearest: security"), "{error}");

        let error = check_config_paths(&catalog, &res, &set("set system name-serverz 1.1.1.1"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("nearest: system name-server"), "{error}");

        let error = check_config_paths(&catalog, &res, &set("set firewal family inet"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("set firewal family inet"), "{error}");

        let error = check_config_paths(&catalog, &res, &set("set interfaces ge-0/0/0 unti 0"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("nearest: interfaces interface unit"),
            "{error}"
        );
    }

    #[test]
    fn write_check_skips_groups_and_comments() {
        let warnings = check_config_paths(
            &fixture_catalog(),
            &resolution(25, 4),
            &set("# set bogus\n\n/* set bogus */\n\
                  set groups G bogus thing\n\
                  set apply-groups G\n\
                  set interfaces ge-0/0/0 apply-groups G\n\
                  set interfaces <ge-*> unit 0 bogus\n\
                  set interfaces wildcard range bogus"),
        )
        .unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn write_check_fallback_only_warns() {
        let catalog = fixture_catalog();
        for res in [resolution(25, 2), resolution(24, 2)] {
            assert!(res.warning.is_some());
            let warnings =
                check_config_paths(&catalog, &res, &set("set securty policies")).unwrap();
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("set securty policies"), "{warnings:?}");
        }
        let guessed = catalog.resolve(
            Family::JunosEs,
            Train {
                major: 25,
                minor: 4,
            },
            false,
        );
        assert_eq!(
            check_config_paths(&catalog, &guessed, &set("set securty x"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn write_check_text_format_top_level() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let good = "/* lab */\nsystem {\n    host-name \"r1 {x}\";\n    name-server {\n        \
                    1.1.1.2;\n    }\n}\nreplace: interfaces {\n    ge-0/0/0 {\n        unit 0 { \
                    bogus-deep; }\n    }\n}\ngroups { G { anything; } }\n";
        let payload = ConfigPayload::Text(good.into());
        assert!(
            check_config_paths(&catalog, &res, &payload)
                .unwrap()
                .is_empty()
        );

        let error = check_config_paths(
            &catalog,
            &res,
            &ConfigPayload::Text("system { host-nam r1; }\nsecurty { }".into()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`system host-nam r1`"), "{error}");
        assert!(error.contains("`securty`"), "{error}");
    }

    #[test]
    fn write_check_xml_format_two_levels() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let good = "<configuration><!-- c --><system><host-name>r1</host-name>\
                    <name-server><name>1.1.1.2</name></name-server></system>\
                    <interfaces><interface><name>ge-0/0/0</name><bogus/></interface>\
                    </interfaces></configuration>";
        assert!(
            check_config_paths(&catalog, &res, &ConfigPayload::Xml(good.into()))
                .unwrap()
                .is_empty()
        );
        let error = check_config_paths(
            &catalog,
            &res,
            &ConfigPayload::Xml("<system><host-nam>r1</host-nam></system>".into()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`system host-nam`"), "{error}");
    }

    /// The bench-lab baselines (`tests/fixtures/write_check/`, secrets and
    /// public addresses replaced) must load without a single rejection, even
    /// when the resolution is forced exact.
    #[test]
    fn write_check_accepts_bench_lab_baselines() {
        let devices = [
            (
                "bench-ex2300",
                Family::JunosEx,
                "23.4R2-S2.1",
                include_str!("../../tests/fixtures/write_check/bench-ex2300.set"),
            ),
            (
                "bench-srx1600",
                Family::JunosEs,
                "25.4R1.12",
                include_str!("../../tests/fixtures/write_check/bench-srx1600.set"),
            ),
            (
                "bench-srx440",
                Family::JunosEvo,
                "25.4X300-D40.2-EVO",
                include_str!("../../tests/fixtures/write_check/bench-srx440.set"),
            ),
            (
                "bench-srx345",
                Family::JunosEs,
                "25.4R1-S2.3",
                include_str!("../../tests/fixtures/write_check/bench-srx345.set"),
            ),
            (
                "bench-vsrx-inet",
                Family::JunosEs,
                "26.2R1.7",
                include_str!("../../tests/fixtures/write_check/bench-vsrx-inet.set"),
            ),
            (
                "bench-csrx",
                Family::JunosEs,
                "26.2R1.7",
                include_str!("../../tests/fixtures/write_check/bench-csrx.set"),
            ),
        ];
        let catalog = Catalog::embedded();
        let mut failures = Vec::new();
        for (device, family, release, text) in devices {
            let train = super::super::train_for(release).unwrap();
            let res = Resolution {
                warning: None,
                ..catalog.resolve(family, train, true)
            };
            if let Err(error) = check_config_paths(catalog, &res, &set(text)) {
                failures.push(format!("{device}: {error}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The lenience that admits those lines still rejects invented ones.
        for family in [Family::JunosEs, Family::JunosEvo, Family::JunosEx] {
            let res = catalog.resolve(
                family,
                Train {
                    major: 25,
                    minor: 4,
                },
                true,
            );
            let res = Resolution {
                warning: None,
                ..res
            };
            for line in [
                "set securty policies from-zone a to-zone b policy p then permit",
                "set system name-serverz 1.1.1.1",
                "set firewal family inet",
                "set interfaces ge-0/0/0 unti 0 family inet",
                "set security policies default-policy deny-all extra-knob",
            ] {
                assert!(
                    check_config_paths(catalog, &res, &set(line)).is_err(),
                    "{family}: {line}"
                );
            }
        }
    }

    #[test]
    fn edit_distance_counts_edits() {
        assert_eq!(edit_distance("securty", "security"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("unti", "unit"), 2);
    }
}
