//! Catalog queries: RPC and Configuration path lookup and path validation.

use serde::Serialize;

use super::{
    Catalog, ConfigEntry, Data, OutputTree, Resolution, RpcInput, RpcVariant, Text, Train,
};

/// An RPC as defined for a Resolution's train.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RpcHit {
    /// The RPC name (`get-arp-table-information`).
    pub name: String,
    /// The trains this definition holds for.
    pub trains: Vec<Train>,
    /// False only from [`Catalog::rpc`] when the RPC is absent from the
    /// resolved train and the newest definition was returned instead.
    pub in_train: bool,
    /// The CLI equivalent (`show arp`).
    pub cli: Text,
    /// What the RPC does.
    pub description: Option<Text>,
    /// The arguments it accepts.
    pub input: Vec<RpcInput>,
    /// The reply element tree.
    pub output: OutputTree,
    /// Generator guidance, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
}

/// A Configuration path as defined for a Resolution's train.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigHit {
    /// The space-joined path (`system name-server`); list keys appear as
    /// child leaves, never inside the path.
    pub path: String,
    /// The definition for the resolved train.
    #[serde(flatten)]
    pub entry: ConfigEntry,
}

/// The definition of an entry that holds for `train`.
fn for_train<T>(variants: &[T], train: Train, trains: impl Fn(&T) -> &[Train]) -> Option<&T> {
    variants
        .iter()
        .find(|variant| trains(variant).contains(&train))
}

fn rpc_variant(variants: &[RpcVariant], train: Train) -> Option<&RpcVariant> {
    for_train(variants, train, |variant| &variant.trains)
}

fn config_entry(variants: &[ConfigEntry], train: Train) -> Option<&ConfigEntry> {
    for_train(variants, train, |entry| &entry.trains)
}

fn rpc_hit(data: &Data<RpcVariant>, name: &str, variant: &RpcVariant, in_train: bool) -> RpcHit {
    RpcHit {
        name: name.to_owned(),
        trains: variant.trains.clone(),
        in_train,
        cli: variant.cli.clone(),
        description: variant.description.clone(),
        input: variant.input.clone(),
        output: data
            .outputs
            .get(variant.output)
            .cloned()
            .unwrap_or_default(),
        note: variant.note.clone(),
    }
}

/// How many lowercase `words` occur in `haystack`.
fn score(words: &[&str], haystack: &str) -> usize {
    let haystack = haystack.to_lowercase();
    words.iter().filter(|word| haystack.contains(*word)).count()
}

/// The number of tokens in `cli` when it is a whole-token prefix of `query`.
fn cli_prefix_len(cli: &str, query: &str) -> Option<usize> {
    let mut query_tokens = query.split_whitespace();
    let mut matched = 0;
    for token in cli.split_whitespace() {
        if query_tokens.next() != Some(token) {
            return None;
        }
        matched += 1;
    }
    (matched > 0).then_some(matched)
}

fn child(parent: &str, token: &str) -> String {
    if parent.is_empty() {
        token.to_owned()
    } else {
        format!("{parent} {token}")
    }
}

impl Catalog {
    /// RPCs matching `query` on the resolved train, best first.
    ///
    /// Tries, in order, and returns the first stage that matches: the exact
    /// RPC name; the longest catalog CLI that is a whole-token prefix of the
    /// query (anything after the first `|` is dropped); then a case-insensitive
    /// keyword match over name, CLI and description, ranked by words matched.
    pub fn lookup_rpc(&self, res: &Resolution, query: &str, limit: usize) -> Vec<RpcHit> {
        let Some(data) = self.rpc_data(res.family) else {
            return Vec::new();
        };
        let query = query.trim().to_lowercase();
        let in_train = || {
            data.entries.iter().filter_map(|(name, variants)| {
                rpc_variant(variants, res.used).map(|variant| (name, variant))
            })
        };

        if let Some(variant) = data
            .entries
            .get(&query)
            .and_then(|variants| rpc_variant(variants, res.used))
        {
            return vec![rpc_hit(data, &query, variant, true)];
        }

        let command = query.split('|').next().unwrap_or_default();
        let mut best = 0;
        let mut by_cli = Vec::new();
        for (name, variant) in in_train() {
            let Some(len) = cli_prefix_len(&variant.cli, command) else {
                continue;
            };
            if len > best {
                best = len;
                by_cli.clear();
            }
            if len == best {
                by_cli.push(rpc_hit(data, name, variant, true));
            }
        }
        if !by_cli.is_empty() {
            by_cli.truncate(limit);
            return by_cli;
        }

        let words: Vec<&str> = query.split_whitespace().collect();
        let mut ranked: Vec<(usize, &String, &RpcVariant)> = in_train()
            .map(|(name, variant)| {
                let text = format!(
                    "{name} {} {}",
                    variant.cli,
                    variant.description.as_deref().unwrap_or_default()
                );
                (score(&words, &text), name, variant)
            })
            .filter(|(matched, ..)| *matched > 0)
            .collect();
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(right.1)));
        ranked
            .into_iter()
            .take(limit)
            .map(|(_, name, variant)| rpc_hit(data, name, variant, true))
            .collect()
    }

    /// Configuration paths matching `query` (space- or `/`-separated) on the
    /// resolved train: the exact path followed by its descendants, shallowest
    /// first; when neither exists, a keyword match over path and description.
    pub fn lookup_config(&self, res: &Resolution, query: &str, limit: usize) -> Vec<ConfigHit> {
        let Some(data) = self.config_data(res.family) else {
            return Vec::new();
        };
        let query = query.to_lowercase();
        let words: Vec<&str> = query
            .split(|ch: char| ch == '/' || ch.is_whitespace())
            .filter(|word| !word.is_empty())
            .collect();
        if words.is_empty() {
            return Vec::new();
        }
        let path = words.join(" ");
        let hit = |path: &String, entry: &ConfigEntry| ConfigHit {
            path: path.clone(),
            entry: entry.clone(),
        };
        let depth = |path: &str| path.matches(' ').count();

        let below = format!("{path} ");
        let mut found: Vec<(&String, &ConfigEntry)> = data
            .entries
            .range(path.clone()..)
            .take_while(|(candidate, _)| **candidate == path || candidate.starts_with(&below))
            .filter_map(|(candidate, variants)| {
                config_entry(variants, res.used).map(|entry| (candidate, entry))
            })
            .collect();
        if !found.is_empty() {
            found.sort_by(|left, right| {
                depth(left.0).cmp(&depth(right.0)).then(left.0.cmp(right.0))
            });
            return found
                .into_iter()
                .take(limit)
                .map(|(path, entry)| hit(path, entry))
                .collect();
        }

        let mut ranked: Vec<(usize, &String, &ConfigEntry)> = data
            .entries
            .iter()
            .filter_map(|(candidate, variants)| {
                let entry = config_entry(variants, res.used)?;
                let text = format!(
                    "{candidate} {}",
                    entry.description.as_deref().unwrap_or_default()
                );
                let matched = score(&words, &text);
                (matched > 0).then_some((matched, candidate, entry))
            })
            .collect();
        ranked.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then(depth(left.1).cmp(&depth(right.1)))
                .then(left.1.cmp(right.1))
        });
        ranked
            .into_iter()
            .take(limit)
            .map(|(_, path, entry)| hit(path, entry))
            .collect()
    }

    /// The RPC `name` for the resolved train. When the RPC exists in the
    /// Family but not in that train, returns its newest definition with
    /// `in_train: false`; `None` when the Family has no such RPC at all.
    pub fn rpc(&self, res: &Resolution, name: &str) -> Option<RpcHit> {
        let data = self.rpc_data(res.family)?;
        let variants = data.entries.get(name)?;
        if let Some(variant) = rpc_variant(variants, res.used) {
            return Some(rpc_hit(data, name, variant, true));
        }
        let newest = variants
            .iter()
            .max_by_key(|variant| variant.trains.iter().max().copied())?;
        Some(rpc_hit(data, name, newest, false))
    }

    /// Whether a `set`-style token path (`["system", "name-server",
    /// "1.1.1.2", "routing-instance", "mgmt_junos"]`) exists on the
    /// resolved train.
    ///
    /// Walks left to right. Tokens after a leaf or leaf-list are its value.
    /// The token after a list is its key value. Junos CLI shorthands are
    /// accepted: an elided list keyword (`interfaces ge-0/0/0` for
    /// `interfaces interface ge-0/0/0`), keyword-named keys (`from-zone X
    /// to-zone Y` for the `from-zone-name`/`to-zone-name` keys), a trailing
    /// positional value after a list entry (`address a1 10.0.0.0/8`), and the
    /// root hierarchy repeated under `logical-systems <name>` and
    /// `tenants <name>`.
    pub fn config_path_exists(&self, res: &Resolution, path: &[&str]) -> bool {
        let Some(data) = self.config_data(res.family) else {
            return false;
        };
        let node = |path: &str| {
            data.entries
                .get(path)
                .and_then(|variants| config_entry(variants, res.used))
        };
        let is_list = |path: &str| node(path).is_some_and(|entry| entry.kind == "list");
        // Direct children of `parent` on the train, in catalog order.
        let direct_children = |parent: &str| {
            let below = child(parent, "");
            let start = below.clone();
            data.entries
                .range(start.clone()..)
                .take_while(move |(candidate, _)| candidate.starts_with(&start))
                .filter(move |(candidate, variants)| {
                    !candidate[below.len()..].contains(' ')
                        && config_entry(variants, res.used).is_some()
                })
                .map(|(candidate, _)| candidate.clone())
        };
        let list_children = |parent: &str| {
            direct_children(parent)
                .filter(|candidate| is_list(candidate))
                .collect::<Vec<_>>()
        };

        let mut current = String::new();
        let mut index = 0;
        while index < path.len() {
            let token = path[index];
            let next = path.get(index + 1).copied();

            let mut named = child(&current, token);
            if node(&named).is_none() {
                // YANG renames some CLI keywords to avoid clashes: CLI `match`
                // under a NAT rule is `src-nat-rule-match`.
                let suffix = format!("-{token}");
                if let Some(renamed) =
                    direct_children(&current).find(|candidate| candidate.ends_with(&suffix))
                {
                    named = renamed;
                }
            }
            if let Some(entry) = node(&named) {
                if entry.kind != "list" && entry.kind != "container" {
                    return true;
                }
                current = named;
                index += 1;
                if entry.kind == "list" && next.is_some() {
                    // The key value; a list that mirrors the root hierarchy
                    // (`logical-systems <name>`) continues from the root.
                    index += 1;
                    if entry
                        .note
                        .as_deref()
                        .is_some_and(|note| note.contains("root hierarchy"))
                    {
                        current.clear();
                    }
                }
                continue;
            }

            let in_list = is_list(&current);
            if in_list && node(&child(&current, &format!("{token}-name"))).is_some() {
                index += 2;
                continue;
            }
            if in_list && next.is_none() {
                return true;
            }
            if current.is_empty() {
                return false;
            }
            let elided = list_children(&current).into_iter().find_map(|list| {
                if node(&child(&list, &format!("{token}-name"))).is_some() {
                    return Some((list, 2));
                }
                let next_fits = next.is_none_or(|next| node(&child(&list, next)).is_some());
                next_fits.then_some((list, 1))
            });
            if let Some((list, consumed)) = elided {
                current = list;
                index += consumed;
                continue;
            }
            // A positional leaf value: Junos omits the keyword of some leaves
            // (`storm-control default` for `storm-control profile-name
            // default`, `traceoptions file f1`, `default-policy deny-all`).
            let has_leaf = direct_children(&current)
                .any(|candidate| node(&candidate).is_some_and(|entry| entry.kind == "leaf"));
            let next_fits = next.is_none_or(|next| node(&child(&current, next)).is_some());
            if !(has_leaf && next_fits) {
                return false;
            }
            index += 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Family, fixture_catalog};
    use super::*;

    fn resolution(major: u16, minor: u16) -> Resolution {
        fixture_catalog().resolve(Family::JunosEs, Train { major, minor }, true)
    }

    fn names(hits: &[RpcHit]) -> Vec<&str> {
        hits.iter().map(|hit| hit.name.as_str()).collect()
    }

    #[test]
    fn lookup_by_exact_name_resolves_output_tree() {
        let catalog = fixture_catalog();
        let hits = catalog.lookup_rpc(&resolution(25, 4), "get-arp-table-information", 10);
        assert_eq!(names(&hits), ["get-arp-table-information"]);
        assert_eq!(hits[0].output.0[0].0, "arp-table-information");
        assert!(hits[0].input.iter().any(|input| input.name == "no-resolve"));
    }

    #[test]
    fn lookup_by_cli_text_with_pipe() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let hits = catalog.lookup_rpc(&res, "show arp   no-resolve | match 10.", 10);
        assert_eq!(names(&hits), ["get-arp-table-information"]);
        let hits = catalog.lookup_rpc(&res, "show route summary extensive", 10);
        assert_eq!(names(&hits), ["get-route-summary-information"]);
    }

    #[test]
    fn lookup_by_keywords_ranks() {
        let catalog = fixture_catalog();
        let hits = catalog.lookup_rpc(&resolution(25, 4), "Route SUMMARY", 10);
        assert_eq!(
            names(&hits),
            ["get-route-summary-information", "get-route-information"]
        );
        let hits = catalog.lookup_rpc(&resolution(25, 4), "route summary", 1);
        assert_eq!(names(&hits), ["get-route-summary-information"]);
    }

    #[test]
    fn lookup_skips_rpcs_outside_the_train() {
        let catalog = fixture_catalog();
        assert!(
            catalog
                .lookup_rpc(&resolution(24, 2), "get-new-feature-information", 10)
                .is_empty()
        );
        let hits = catalog.lookup_rpc(&resolution(25, 4), "new feature", 10);
        assert_eq!(names(&hits), ["get-new-feature-information"]);
    }

    #[test]
    fn rpc_picks_train_variant_and_falls_back() {
        let catalog = fixture_catalog();
        let hit = catalog
            .rpc(&resolution(25, 4), "get-software-information")
            .unwrap();
        assert_eq!(hit.note.as_deref(), Some("25.4 adds no arguments"));
        let hit = catalog
            .rpc(&resolution(24, 2), "get-software-information")
            .unwrap();
        assert!(hit.in_train && hit.note.is_none());
        let hit = catalog
            .rpc(&resolution(24, 2), "get-new-feature-information")
            .unwrap();
        assert!(!hit.in_train);
        assert!(catalog.rpc(&resolution(25, 4), "get-nothing").is_none());
    }

    #[test]
    fn lookup_config_exact_then_descendants_then_keywords() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let hits = catalog.lookup_config(&res, "system/name-server", 10);
        let paths: Vec<&str> = hits.iter().map(|hit| hit.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "system name-server",
                "system name-server name",
                "system name-server routing-instance"
            ]
        );
        assert_eq!(hits[0].entry.kind, "list");
        let hits = catalog.lookup_config(&res, "dns", 10);
        assert_eq!(hits[0].path, "system name-server");
        assert!(catalog.lookup_config(&res, "  ", 10).is_empty());
        let hits = catalog.lookup_config(&resolution(24, 2), "system new-knob", 10);
        assert!(hits.iter().all(|hit| hit.path != "system new-knob"));
    }

    #[test]
    fn config_path_exists_ignores_list_keys() {
        let catalog = fixture_catalog();
        let res = resolution(25, 4);
        let accepted: &[&[&str]] = &[
            &[
                "system",
                "name-server",
                "1.1.1.2",
                "routing-instance",
                "mgmt_junos",
            ],
            &["system", "host-name", "r1"],
            &["system", "name-server", "1.1.1.2"],
            &[
                "interfaces",
                "ge-0/0/0",
                "unit",
                "0",
                "description",
                "\"uplink",
                "a\"",
            ],
            &["interfaces", "ge-0/0/0"],
            &[
                "security",
                "policies",
                "from-zone",
                "trust",
                "to-zone",
                "untrust",
                "policy",
                "p1",
                "match",
                "source-address",
                "any",
            ],
            &[
                "security",
                "address-book",
                "global",
                "address",
                "a1",
                "10.0.0.0/8",
            ],
            &["logical-systems", "LS1", "system", "host-name", "r1"],
            &["system", "new-knob", "1"],
        ];
        for path in accepted {
            assert!(catalog.config_path_exists(&res, path), "{path:?}");
        }
        let rejected: &[&[&str]] = &[
            &["securty", "policies"],
            &["system", "name-server", "1.1.1.2", "bogus", "extra"],
            &["interfaces", "ge-0/0/0", "unti", "0"],
            &["logical-systems", "LS1", "securty"],
            &["nonsense"],
        ];
        for path in rejected {
            assert!(!catalog.config_path_exists(&res, path), "{path:?}");
        }
        assert!(!catalog.config_path_exists(&resolution(24, 2), &["system", "new-knob", "1"]));
    }
}
