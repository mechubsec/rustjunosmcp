//! The embedded Junos API Catalog: every RPC and Configuration path per Family
//! and Release train, generated from `Juniper/yang` into `catalog/data/`.
//!
//! Each Family's RPC and configuration data is decoded the first time it is
//! queried, so a server that only talks to SRX never parses the EX or EVO data.

mod lookup;
mod version;
mod write_check;

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{BufReader, Read};
use std::ops::Deref;
use std::sync::{Arc, OnceLock};

use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use lookup::{ConfigHit, RpcHit};
pub use version::{Family, SRX_EVO_WARNING, Train, family_for, train_for};
pub use write_check::check_config_paths;

use crate::error::JmcpError;

/// Gzipped `(rpc, config)` data per Family, in [`Family::ALL`] order.
const EMBEDDED: [(&[u8], &[u8]); 3] = [
    (
        include_bytes!("../../catalog/data/rpc-junos-es.json.gz"),
        include_bytes!("../../catalog/data/config-junos-es.json.gz"),
    ),
    (
        include_bytes!("../../catalog/data/rpc-junos-ex.json.gz"),
        include_bytes!("../../catalog/data/config-junos-ex.json.gz"),
    ),
    (
        include_bytes!("../../catalog/data/rpc-junos-evo.json.gz"),
        include_bytes!("../../catalog/data/config-junos-evo.json.gz"),
    ),
];

/// Which Family and Release train a query runs against, and why it may not be
/// an exact match for the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Resolution {
    /// The Family queried.
    pub family: Family,
    /// The train the device runs (or the caller asked for).
    pub requested: Train,
    /// The catalog train actually used: the highest one at or below
    /// `requested`, else the lowest the catalog has.
    pub used: Train,
    /// Set when the answer may not match the device: a different train, a
    /// guessed Family, or catalog data missing for the train. `None` means exact.
    pub warning: Option<String>,
}

/// Catalog text. The generated data repeats the same descriptions, types and
/// element names thousands of times, so equal strings share one allocation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text(Arc<str>);

thread_local! {
    /// Strings seen by the parse running on this thread; emptied after each parse.
    static INTERNED: RefCell<HashSet<Arc<str>>> = RefCell::default();
}

impl Text {
    fn intern(text: &str) -> Text {
        INTERNED.with_borrow_mut(|seen| {
            if let Some(shared) = seen.get(text) {
                return Text(shared.clone());
            }
            let shared: Arc<str> = text.into();
            seen.insert(shared.clone());
            Text(shared)
        })
    }
}

impl Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl Visitor<'_> for TextVisitor {
            type Value = Text;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Text, E> {
                Ok(Text::intern(text))
            }
        }
        deserializer.deserialize_str(TextVisitor)
    }
}

/// One element of an RPC reply: its child elements in document order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputTree(pub Vec<(Text, OutputTree)>);

impl Serialize for OutputTree {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(name, child)| (name, child)))
    }
}

impl<'de> Deserialize<'de> for OutputTree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TreeVisitor;
        impl<'de> Visitor<'de> for TreeVisitor {
            type Value = OutputTree;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RPC reply tree object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OutputTree, A::Error> {
                let mut children = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    children.push(entry);
                }
                children.shrink_to_fit();
                Ok(OutputTree(children))
            }
        }
        deserializer.deserialize_map(TreeVisitor)
    }
}

/// One RPC argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcInput {
    /// The argument element name.
    pub name: Text,
    /// The YANG type (`string`, `empty`, an enumeration, …).
    #[serde(rename = "type")]
    pub type_name: Option<Text>,
    /// What the argument does.
    pub description: Option<Text>,
}

/// An RPC's definition over a run of trains.
#[derive(Clone, Debug, Deserialize)]
struct RpcVariant {
    trains: Vec<Train>,
    cli: Text,
    description: Option<Text>,
    input: Vec<RpcInput>,
    output: usize,
    note: Option<Text>,
}

/// A Configuration path's definition over a run of trains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigEntry {
    /// The trains this definition holds for.
    pub trains: Vec<Train>,
    /// `container`, `list`, `leaf` or `leaf-list`.
    pub kind: Text,
    /// The YANG type of a leaf.
    #[serde(rename = "type")]
    pub type_name: Option<Text>,
    /// What the node configures.
    pub description: Option<Text>,
    /// The allowed value range of a leaf.
    pub range: Option<Text>,
    /// The units of a leaf's value.
    pub units: Option<Text>,
    /// Generator guidance, such as the root-mirror note on `logical-systems`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
}

/// A module the generator could not read for one train, so that train's data
/// is incomplete.
#[derive(Clone, Debug, Deserialize)]
struct Gap {
    train: Train,
    kind: String,
    module: String,
    reason: String,
}

/// The on-disk shape of one `{rpc,config}-<family>.json` file.
#[derive(Deserialize)]
struct File<T> {
    trains: Vec<Train>,
    #[serde(default)]
    gaps: Vec<Gap>,
    #[serde(default)]
    outputs: Vec<OutputTree>,
    families: BTreeMap<String, BTreeMap<String, Vec<T>>>,
}

/// One Family's data of one kind (RPC or configuration).
struct Data<T> {
    trains: Vec<Train>,
    gaps: Vec<Gap>,
    /// Interned RPC reply trees; empty for configuration.
    outputs: Vec<OutputTree>,
    /// RPC name, or space-joined Configuration path → definitions per train run.
    entries: BTreeMap<String, Vec<T>>,
}

/// Parses one catalog file, which must hold exactly one Family.
fn parse<T: DeserializeOwned>(json: impl Read) -> Result<(Family, Data<T>), JmcpError> {
    let file = serde_json::from_reader::<_, File<T>>(BufReader::new(json));
    INTERNED.with_borrow_mut(|seen| *seen = HashSet::new());
    let file = file?;
    let mut families = file.families.into_iter();
    let (Some((name, mut entries)), None) = (families.next(), families.next()) else {
        return Err(JmcpError::Validation(
            "a catalog file must hold exactly one family".into(),
        ));
    };
    // Deserialized Vecs start at capacity 4; most entries hold one variant.
    entries.values_mut().for_each(Vec::shrink_to_fit);
    let data = Data {
        trains: file.trains,
        gaps: file.gaps,
        outputs: file.outputs,
        entries,
    };
    Ok((name.parse()?, data))
}

/// Decodes one embedded gzip file; the data is fixed at build time and
/// `embedded_catalog_loads` proves it decodes, so failure is a build defect.
fn load_embedded<T: DeserializeOwned>(family: Family, gz: &[u8]) -> Data<T> {
    // Streamed: the decoded JSON (up to 37 MB) is never resident at once.
    let (found, data) =
        parse(flate2::read::GzDecoder::new(gz)).expect("embedded catalog is valid gzip JSON");
    assert_eq!(
        found, family,
        "embedded catalog file holds the wrong family"
    );
    data
}

/// The on-disk RPC file read for names and CLIs only: the reply trees and
/// arguments are skipped without being kept.
#[derive(Deserialize)]
struct CliFile {
    families: BTreeMap<String, BTreeMap<String, Vec<CliVariant>>>,
}

#[derive(Deserialize)]
struct CliVariant {
    trains: Vec<Train>,
    cli: String,
}

/// RPC name → CLI of its newest definition, for one embedded Family.
fn load_embedded_clis(family: Family) -> BTreeMap<String, String> {
    let file: CliFile = serde_json::from_reader(BufReader::new(flate2::read::GzDecoder::new(
        EMBEDDED[family as usize].0,
    )))
    .expect("embedded catalog is valid gzip JSON");
    file.families
        .into_values()
        .flatten()
        .filter_map(|(name, variants)| {
            let newest = variants
                .into_iter()
                .max_by_key(|variant| variant.trains.iter().max().copied())?;
            Some((name, newest.cli))
        })
        .collect()
}

/// Runs `f`, which may parse a catalog file on first use (about a second),
/// without stalling a tokio worker: through `block_in_place` on a
/// multi-thread runtime, inline elsewhere (current-thread tests).
pub fn off_runtime<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// The Junos API Catalog.
pub struct Catalog {
    /// Empty slots are filled from [`EMBEDDED`] on first use when set.
    embedded: bool,
    rpc: [OnceLock<Data<RpcVariant>>; 3],
    config: [OnceLock<Data<ConfigEntry>>; 3],
    /// Name-only RPC index per Family, for checks before the Family is known.
    rpc_clis: [OnceLock<BTreeMap<String, String>>; 3],
}

impl Catalog {
    /// The catalog compiled into this binary.
    pub fn embedded() -> &'static Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(Catalog::embedded_unloaded)
    }

    fn embedded_unloaded() -> Catalog {
        Catalog {
            embedded: true,
            rpc: Default::default(),
            config: Default::default(),
            rpc_clis: Default::default(),
        }
    }

    /// A fresh embedded catalog with nothing loaded, for load-state tests.
    #[cfg(test)]
    pub(crate) fn embedded_fresh() -> Catalog {
        Catalog::embedded_unloaded()
    }

    /// Which Families' `(rpc, config)` data are loaded, in [`Family::ALL`] order.
    #[cfg(test)]
    pub(crate) fn loaded(&self) -> [(bool, bool); 3] {
        [0, 1, 2].map(|slot| {
            (
                self.rpc[slot].get().is_some(),
                self.config[slot].get().is_some(),
            )
        })
    }

    /// A catalog holding one Family, from plain (not gzipped) RPC and
    /// configuration files in the generator's per-family format. For tests.
    pub fn from_json(rpc: &[u8], config: &[u8]) -> Result<Catalog, JmcpError> {
        let (rpc_family, rpc) = parse::<RpcVariant>(rpc)?;
        let (config_family, config) = parse::<ConfigEntry>(config)?;
        if rpc_family != config_family {
            return Err(JmcpError::Validation(format!(
                "rpc file is {rpc_family} but config file is {config_family}"
            )));
        }
        let catalog = Catalog {
            embedded: false,
            rpc: Default::default(),
            config: Default::default(),
            rpc_clis: Default::default(),
        };
        let slot = rpc_family as usize;
        // Fresh slots cannot already be set.
        let _ = catalog.rpc[slot].set(rpc);
        let _ = catalog.config[slot].set(config);
        Ok(catalog)
    }

    fn rpc_data(&self, family: Family) -> Option<&Data<RpcVariant>> {
        let slot = &self.rpc[family as usize];
        if !self.embedded {
            return slot.get();
        }
        Some(slot.get_or_init(|| load_embedded(family, EMBEDDED[family as usize].0)))
    }

    fn config_data(&self, family: Family) -> Option<&Data<ConfigEntry>> {
        let slot = &self.config[family as usize];
        if !self.embedded {
            return slot.get();
        }
        Some(slot.get_or_init(|| load_embedded(family, EMBEDDED[family as usize].1)))
    }

    /// The CLI of the newest definition of RPC `name` in `family`, read from
    /// a name-only index when the Family's full RPC data is not loaded, so a
    /// check before the device's Family is known parses no reply trees.
    pub fn rpc_cli(&self, family: Family, name: &str) -> Option<String> {
        if let Some(data) = self.rpc[family as usize].get() {
            let newest = data
                .entries
                .get(name)?
                .iter()
                .max_by_key(|variant| variant.trains.iter().max().copied())?;
            return Some(newest.cli.to_string());
        }
        if !self.embedded {
            return None;
        }
        self.rpc_clis[family as usize]
            .get_or_init(|| load_embedded_clis(family))
            .get(name)
            .cloned()
    }

    /// Picks the catalog train to answer for `requested` on `family`.
    ///
    /// `exact_family` is false when the Family was inferred rather than
    /// matched to the device (SRX on Junos OS Evolved, see [`family_for`]).
    /// Loads both the RPC and configuration data of `family`, and warns of
    /// gaps in either; [`resolve_rpc`](Self::resolve_rpc) and
    /// [`resolve_config`](Self::resolve_config) load one kind.
    pub fn resolve(&self, family: Family, requested: Train, exact_family: bool) -> Resolution {
        self.resolve_in(
            family,
            requested,
            exact_family,
            self.rpc_data(family),
            self.config_data(family),
        )
    }

    /// [`resolve`](Self::resolve) for an RPC query: loads only the RPC data.
    pub fn resolve_rpc(&self, family: Family, requested: Train, exact_family: bool) -> Resolution {
        self.resolve_in(family, requested, exact_family, self.rpc_data(family), None)
    }

    /// [`resolve`](Self::resolve) for a configuration query: loads only the
    /// configuration data.
    pub fn resolve_config(
        &self,
        family: Family,
        requested: Train,
        exact_family: bool,
    ) -> Resolution {
        self.resolve_in(
            family,
            requested,
            exact_family,
            None,
            self.config_data(family),
        )
    }

    fn resolve_in(
        &self,
        family: Family,
        requested: Train,
        exact_family: bool,
        rpc: Option<&Data<RpcVariant>>,
        config: Option<&Data<ConfigEntry>>,
    ) -> Resolution {
        let trains = config
            .map(|data| data.trains.as_slice())
            .or(rpc.map(|data| data.trains.as_slice()))
            .unwrap_or_default();
        let used = trains
            .iter()
            .filter(|train| **train <= requested)
            .max()
            .or(trains.iter().min())
            .copied()
            .unwrap_or(requested);

        let mut warnings = Vec::new();
        if trains.is_empty() {
            warnings.push(format!("the catalog has no data for {family}"));
        } else if used != requested {
            warnings.push(format!(
                "the catalog has no {family} {requested}; using the nearest train {used}"
            ));
        }
        if !exact_family {
            // An inexact junos-es is only ever inferred for SRX on EVO.
            warnings.push(if family == Family::JunosEs {
                SRX_EVO_WARNING.to_owned()
            } else {
                format!(
                    "family {family} was not detected from the device; results are unverified for this device"
                )
            });
        }
        let gaps: Vec<String> = rpc
            .map(|data| data.gaps.as_slice())
            .unwrap_or_default()
            .iter()
            .chain(config.map(|data| data.gaps.as_slice()).unwrap_or_default())
            .filter(|gap| gap.train == used)
            .map(|gap| {
                format!(
                    "{} module {} not read ({})",
                    gap.kind, gap.module, gap.reason
                )
            })
            .collect();
        if !gaps.is_empty() {
            warnings.push(format!(
                "catalog for {used} is incomplete: {}",
                gaps.join("; ")
            ));
        }

        Resolution {
            family,
            requested,
            used,
            warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
        }
    }
}

/// A catalog of the junos-es fixture in `tests/fixtures/catalog/`.
#[cfg(test)]
pub(crate) fn fixture_catalog() -> Catalog {
    Catalog::from_json(
        include_bytes!("../../tests/fixtures/catalog/rpc.json"),
        include_bytes!("../../tests/fixtures/catalog/config.json"),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn train(major: u16, minor: u16) -> Train {
        Train { major, minor }
    }

    #[test]
    fn resolve_exact_has_no_warning() {
        let res = fixture_catalog().resolve(Family::JunosEs, train(25, 4), true);
        assert_eq!(res.used, train(25, 4));
        assert_eq!(res.warning, None);
    }

    #[test]
    fn resolve_nearest_lower_train_warns() {
        let res = fixture_catalog().resolve(Family::JunosEs, train(25, 2), true);
        assert_eq!(res.requested, train(25, 2));
        assert_eq!(res.used, train(24, 2));
        let warning = res.warning.unwrap();
        assert!(warning.contains("nearest train 24.2"), "{warning}");
    }

    #[test]
    fn resolve_below_lowest_uses_lowest() {
        let res = fixture_catalog().resolve(Family::JunosEs, train(23, 1), true);
        assert_eq!(res.used, train(23, 4));
        assert!(res.warning.unwrap().contains("23.4"));
    }

    #[test]
    fn resolve_guessed_family_warns() {
        let res = fixture_catalog().resolve(Family::JunosEs, train(25, 4), false);
        assert_eq!(res.used, train(25, 4));
        assert_eq!(res.warning.unwrap(), SRX_EVO_WARNING);
    }

    #[test]
    fn resolve_gap_train_warns_incomplete() {
        let res = fixture_catalog().resolve(Family::JunosEs, train(24, 2), true);
        assert_eq!(res.used, train(24, 2));
        let warning = res.warning.unwrap();
        assert!(
            warning.contains("catalog for 24.2 is incomplete")
                && warning.contains("junos-es-conf-wlan"),
            "{warning}"
        );
    }

    #[test]
    fn resolve_family_absent_from_catalog_warns() {
        let res = fixture_catalog().resolve(Family::JunosEx, train(24, 2), true);
        assert_eq!(res.used, train(24, 2));
        assert!(res.warning.unwrap().contains("no data for junos-ex"));
    }

    #[test]
    fn resolve_one_kind_loads_one_kind() {
        let catalog = Catalog::embedded_fresh();
        catalog.resolve_rpc(Family::JunosEs, train(24, 4), true);
        assert_eq!(
            catalog
                .rpc_cli(Family::JunosEx, "get-arp-table-information")
                .as_deref(),
            Some("show arp")
        );
        assert_eq!(
            catalog.loaded(),
            [(true, false), (false, false), (false, false)]
        );
        catalog.resolve_config(Family::JunosEs, train(24, 4), true);
        assert_eq!(
            catalog.loaded(),
            [(true, true), (false, false), (false, false)]
        );
    }

    #[test]
    fn from_json_rejects_mismatched_families() {
        let rpc = include_bytes!("../../tests/fixtures/catalog/rpc.json");
        let config = br#"{"trains":[],"families":{"junos-ex":{}}}"#;
        assert!(Catalog::from_json(rpc, config).is_err());
    }

    #[test]
    fn embedded_catalog_loads() {
        let catalog = Catalog::embedded();
        for family in Family::ALL {
            let res = catalog.resolve(family, train(25, 4), true);
            assert_eq!(res.used, train(25, 4), "{family}");
            let hits = catalog.lookup_rpc(&res, "show version", 5);
            assert!(
                hits.iter()
                    .any(|hit| hit.name == "get-software-information"),
                "{family}: {hits:?}"
            );
            assert!(
                catalog.config_path_exists(&res, &["system", "host-name"]),
                "{family}"
            );
        }
        let srx = catalog.resolve(Family::JunosEs, train(24, 4), true);
        let set_lines = [
            "system name-server 1.1.1.2 routing-instance mgmt_junos",
            "interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
            "security policies from-zone trust to-zone untrust policy p1 match source-address any",
            "security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh",
            "security address-book global address a1 10.0.0.0/8",
            "security nat source rule-set rs1 from zone trust",
            "routing-options static route 0.0.0.0/0 next-hop 10.0.0.254",
            "logical-systems LS1 security policies from-zone trust to-zone untrust policy p1 then permit",
        ];
        for line in set_lines {
            let path: Vec<&str> = line.split_whitespace().collect();
            assert!(catalog.config_path_exists(&srx, &path), "{line}");
        }
        assert!(!catalog.config_path_exists(&srx, &["securty", "policies"]));
    }

    fn status_kb(field: &str) -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|rest| rest.trim().trim_end_matches(" kB").trim().parse().ok())
            .unwrap()
    }

    /// Ruling P6 budget: one Family's rpc + config parsed stays under 150 MB.
    /// `CATALOG_FAMILY=junos-es cargo test --release -p rust-junosmcp-core
    /// embedded_family_memory -- --ignored --nocapture`
    #[test]
    #[ignore = "measures RSS of the embedded catalog; run by hand"]
    fn embedded_family_memory() {
        let family: Family = std::env::var("CATALOG_FAMILY")
            .unwrap_or_else(|_| "junos-evo".into())
            .parse()
            .unwrap();
        let before = status_kb("VmRSS:");
        let started = std::time::Instant::now();
        let catalog = Catalog::embedded();
        catalog.rpc_data(family).unwrap();
        let rpc_done = started.elapsed();
        let rpc_rss = status_kb("VmRSS:");
        catalog.config_data(family).unwrap();
        let elapsed = started.elapsed();
        let after = status_kb("VmRSS:");
        let peak = status_kb("VmHWM:");
        println!(
            "{family}: rss before {before} kB, after {after} kB (+{} MB; rpc +{} MB), peak {} MB, rpc {rpc_done:?}, total {elapsed:?}",
            (after - before) / 1024,
            (rpc_rss - before) / 1024,
            peak / 1024
        );
        assert!(after - before < 150 * 1024, "over the 150 MB budget");
    }
}
