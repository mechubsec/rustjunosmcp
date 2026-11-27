//! `lookup_junos_api` — look up an RPC or configuration path in the embedded
//! Junos API catalog for a device's Family and Release train.

use crate::catalog::{Catalog, Family, Train, check_config_paths, family_for, train_for};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// The most a write's catalog check spends opening the device and reading
/// its facts; the write keeps the rest of its timeout.
pub const CATALOG_CHECK_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a router's detected Family and train are trusted.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
/// A router's detected Family, train and whether the Family is certain.
pub type Detected = (Family, Train, bool);

const DEFAULT_LIMIT: u8 = 10;
const MAX_LIMIT: u8 = 50;

/// What to look up.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LookupKind {
    /// An operational RPC (the default).
    #[default]
    Rpc,
    /// A configuration path.
    Config,
}

/// Arguments for `lookup_junos_api`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupApiArgs {
    /// Inventory name of a device whose model and version select the Family
    /// and Release train. Use this or `family` + `release`, not both.
    #[serde(default)]
    pub router: Option<String>,
    /// `junos-es` (SRX), `junos-ex` (EX) or `junos-evo`. Requires `release`.
    #[serde(default)]
    pub family: Option<String>,
    /// A Junos version or train, such as `24.4` or `24.4R2-S1`. Requires `family`.
    #[serde(default)]
    pub release: Option<String>,
    /// An RPC name (`get-arp-table-information`), CLI command (`show arp`),
    /// configuration path (`security policies`) or keywords.
    pub query: String,
    /// `rpc` (default) or `config`.
    #[serde(default)]
    pub kind: LookupKind,
    /// Maximum hits (default 10, max 50).
    #[serde(default)]
    pub limit: Option<u8>,
    /// Device connection timeout in seconds; only used with `router`.
    #[serde(default = "super::default_timeout")]
    pub timeout: u64,
}

/// A router's detected `(Family, Train, exact_family)`, cached for 15 minutes
/// so repeated lookups do not reconnect to the device.
#[derive(Default)]
pub struct DeviceTrainCache {
    entries: Mutex<HashMap<String, (Instant, Detected)>>,
}

impl DeviceTrainCache {
    /// The cached detection for `router`, unless absent or older than 15 minutes.
    pub fn get(&self, router: &str) -> Option<Detected> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let (stored_at, detected) = entries.get(router)?;
        (stored_at.elapsed() < CACHE_TTL).then_some(*detected)
    }

    /// Records the detection for `router`.
    pub fn put(&self, router: &str, detected: Detected) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(router.to_owned(), (Instant::now(), detected));
    }

    /// Drops the cached detection for each named router.
    pub fn invalidate(&self, routers: &[String]) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for router in routers {
            entries.remove(router);
        }
    }

    /// Drops every cached detection.
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Family and train of `router`, from the cache or else from the device's
    /// facts (model and version), under `timeout`.
    ///
    /// Returns a validation error when the device cannot be read or is not a
    /// supported model/release, telling the caller to pass `family` + `release`.
    pub async fn detect(
        &self,
        dm: &Arc<DeviceManager>,
        router: &str,
        timeout: Duration,
    ) -> Result<Detected, JmcpError> {
        if let Some(detected) = self.get(router) {
            return Ok(detected);
        }
        let fetched = tokio::time::timeout(timeout, async {
            let mut dev = dm.open(router).await?;
            let facts = dev.facts().await?;
            Ok::<_, JmcpError>((facts.model.clone(), facts.version.clone()))
        })
        .await;
        let (model, version) = match fetched {
            Ok(Ok(pair)) => pair,
            Ok(Err(JmcpError::UnknownRouter(name))) => return Err(JmcpError::UnknownRouter(name)),
            Ok(Err(e)) => return Err(unreachable_error(router, &e.to_string())),
            Err(_) => return Err(unreachable_error(router, "timed out")),
        };
        let detected = detect_from_facts(router, &model, &version)?;
        self.put(router, detected);
        Ok(detected)
    }
}

impl DeviceTrainCache {
    /// Checks the configuration paths of each payload against `router`'s
    /// Family and train before a write (see [`check_config_paths`]): an
    /// unknown path is an error on an exact catalog match and a warning
    /// otherwise.
    ///
    /// A device whose facts cannot be read, or whose model or release the
    /// catalog does not cover, is not blocked: the check is skipped with a
    /// warning and the device validates the load itself. A device that cannot
    /// be opened is skipped the same way when `skip_unreachable` (a change-set
    /// plan, which needs no device); otherwise it fails here with the error the
    /// write's own open would hit, rather than retrying the connect twice.
    /// Open and facts share one budget, the smaller of `timeout` and
    /// [`CATALOG_CHECK_TIMEOUT`]; running out of it skips the check with a
    /// warning. Cancelling `ct` returns [`JmcpError::Cancelled`].
    pub async fn check_write(
        &self,
        dm: &Arc<DeviceManager>,
        router: &str,
        payloads: &[rustez::ConfigPayload],
        timeout: Duration,
        skip_unreachable: bool,
        ct: &CancellationToken,
    ) -> Result<Vec<String>, JmcpError> {
        // A declared Mist device is refused before any connect by the write's
        // plane guard; opening it here first would break that promise.
        if payloads.is_empty()
            || dm.inventory().get(router)?.config_authority
                == crate::config_authority::JunosAuthority::Mist
        {
            return Ok(Vec::new());
        }
        let detected = match self.get(router) {
            Some(detected) => Ok(detected),
            None => {
                // One budget for open + facts, so the write keeps the rest.
                let budget = timeout.min(CATALOG_CHECK_TIMEOUT);
                let opened = std::sync::atomic::AtomicBool::new(false);
                let detection = async {
                    let mut dev = dm.open(router).await?;
                    opened.store(true, std::sync::atomic::Ordering::Relaxed);
                    // Pooled only once the facts RPC completes: a dropped
                    // future would otherwise pool a session mid-RPC.
                    dev.prevent_reuse();
                    let facts = dev.facts().await?;
                    let detected = detect_from_facts(router, &facts.model, &facts.version);
                    dev.allow_reuse();
                    detected
                };
                let outcome = tokio::select! {
                    biased;
                    _ = ct.cancelled() => return Err(JmcpError::Cancelled),
                    outcome = tokio::time::timeout(budget, detection) => outcome,
                };
                match outcome {
                    Ok(Err(JmcpError::UnknownRouter(name))) => {
                        return Err(JmcpError::UnknownRouter(name));
                    }
                    // The write's own open would fail the same way.
                    Ok(Err(error))
                        if !opened.load(std::sync::atomic::Ordering::Relaxed)
                            && !skip_unreachable =>
                    {
                        return Err(error);
                    }
                    Ok(result) => result,
                    // Slow, not refused: leave the rest of the budget to the write.
                    Err(_) => Err(JmcpError::Timeout(budget)),
                }
            }
        };
        let (family, train, exact_family) = match detected {
            Ok(detected) => {
                self.put(router, detected);
                detected
            }
            Err(error) => return Ok(vec![skipped_warning(router, &error)]),
        };
        let catalog = Catalog::embedded();
        let resolution = catalog.resolve(family, train, exact_family);
        let mut warnings = Vec::new();
        for payload in payloads {
            warnings.extend(check_config_paths(catalog, &resolution, payload)?);
        }
        Ok(warnings)
    }
}

fn skipped_warning(router: &str, error: &JmcpError) -> String {
    tracing::warn!(router, %error, "API catalog write check skipped");
    format!(
        "configuration paths were not checked against the API catalog: the family and \
         release of {router} could not be determined"
    )
}

/// Maps a device's facts to its `(Family, Train, exact_family)`, or a validation
/// error when the model or release is outside the catalog.
pub fn detect_from_facts(router: &str, model: &str, version: &str) -> Result<Detected, JmcpError> {
    let unsupported = || {
        JmcpError::Validation(format!(
            "device {router} reports model {model:?} version {version:?}, which the API catalog \
             does not cover: families are junos-es, junos-ex, junos-evo and releases are 23.1 or \
             later. Pass `family` and `release` to look up a nearby one."
        ))
    };
    let (family, exact_family) = family_for(model, version).ok_or_else(unsupported)?;
    let train = train_for(version).ok_or_else(unsupported)?;
    Ok((family, train, exact_family))
}

fn unreachable_error(router: &str, why: &str) -> JmcpError {
    JmcpError::Validation(format!(
        "could not read facts from {router} ({why}); pass `family` and `release` instead of `router`"
    ))
}

/// Look up an RPC or configuration path for a device or an explicit
/// family and release, using the embedded catalog.
pub async fn handle(
    args: LookupApiArgs,
    dm: Arc<DeviceManager>,
    cache: &DeviceTrainCache,
) -> Result<Value, JmcpError> {
    run(Catalog::embedded(), args, dm, cache).await
}

pub(crate) async fn run(
    catalog: &Catalog,
    args: LookupApiArgs,
    dm: Arc<DeviceManager>,
    cache: &DeviceTrainCache,
) -> Result<Value, JmcpError> {
    if args.query.trim().is_empty() {
        return Err(JmcpError::Validation("query must not be empty".into()));
    }
    let (family, train, exact_family) = match (&args.router, &args.family, &args.release) {
        (Some(router), None, None) => {
            cache
                .detect(&dm, router, Duration::from_secs(args.timeout))
                .await?
        }
        (None, Some(family), Some(release)) => {
            let train = train_for(release).ok_or_else(|| {
                JmcpError::Validation(format!(
                    "release {release:?} is not a Junos release of 23.1 or later (trains >= 23.1)"
                ))
            })?;
            (family.parse::<Family>()?, train, true)
        }
        _ => {
            return Err(JmcpError::Validation(
                "pass exactly one of `router`, or both `family` and `release`".into(),
            ));
        }
    };
    let limit = usize::from(args.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT));
    let resolution = catalog.resolve(family, train, exact_family);
    let hits = match args.kind {
        LookupKind::Rpc => {
            serde_json::to_value(catalog.lookup_rpc(&resolution, &args.query, limit))?
        }
        LookupKind::Config => {
            serde_json::to_value(catalog.lookup_config(&resolution, &args.query, limit))?
        }
    };
    Ok(json!({
        "family": resolution.family.as_str(),
        "train_requested": resolution.requested.to_string(),
        "train_used": resolution.used.to_string(),
        "warning": resolution.warning,
        "hits": hits,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixture_catalog;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn manager() -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        Arc::new(DeviceManager::new(Arc::new(
            Inventory::load(f.path()).unwrap(),
        )))
    }

    #[test]
    fn detect_from_facts_maps_models_and_releases() {
        assert!(detect_from_facts("r", "MX204", "24.4R1.9").is_err());
        assert!(detect_from_facts("r", "SRX345", "22.4R3.25").is_err());
        let family = |model, version| detect_from_facts("r", model, version).unwrap().0;
        assert_eq!(family("SRX345", "24.4R1.9"), Family::JunosEs);
        assert_eq!(family("EX2300-24T", "23.4R2-S1.3"), Family::JunosEx);
        assert_eq!(
            detect_from_facts("r", "SRX440", "25.4X300-D40.2-EVO").unwrap(),
            (
                Family::JunosEs,
                Train {
                    major: 25,
                    minor: 4
                },
                false
            )
        );
    }

    #[tokio::test]
    async fn check_write_rejects_on_exact_train_and_fails_unreachable_devices() {
        let payload = [rustez::ConfigPayload::Set("set securty policies".into())];
        let seeded = DeviceTrainCache::default();
        seeded.put(
            "r1",
            (
                Family::JunosEs,
                Train {
                    major: 25,
                    minor: 4,
                },
                true,
            ),
        );
        let error = seeded
            .check_write(
                &manager(),
                "r1",
                &payload,
                Duration::from_secs(5),
                false,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("set securty policies"), "{error}");

        // An unreachable device fails as the write's own open would.
        let unseeded = DeviceTrainCache::default();
        let error = unseeded
            .check_write(
                &manager(),
                "r1",
                &payload,
                Duration::from_secs(30),
                false,
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(!matches!(error, JmcpError::Validation(_)), "{error:?}");
        // A change-set plan needs no device, so it is only warned.
        let warnings = unseeded
            .check_write(
                &manager(),
                "r1",
                &payload,
                Duration::from_secs(1),
                true,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            warnings.len() == 1 && warnings[0].contains("not checked"),
            "{warnings:?}"
        );
        assert!(matches!(
            unseeded
                .check_write(
                    &manager(),
                    "nope",
                    &payload,
                    Duration::from_secs(5),
                    false,
                    &CancellationToken::new()
                )
                .await,
            Err(JmcpError::UnknownRouter(_))
        ));
        assert!(
            unseeded
                .check_write(
                    &manager(),
                    "nope",
                    &[],
                    Duration::from_secs(5),
                    false,
                    &CancellationToken::new()
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn check_write_honours_cancellation() {
        let payload = [rustez::ConfigPayload::Set("set system host-name r1".into())];
        let ct = CancellationToken::new();
        ct.cancel();
        let result = DeviceTrainCache::default()
            .check_write(
                &manager(),
                "r1",
                &payload,
                Duration::from_secs(30),
                false,
                &ct,
            )
            .await;
        assert!(matches!(result, Err(JmcpError::Cancelled)), "{result:?}");
    }

    #[test]
    fn invalidate_and_clear_drop_entries() {
        let cache = DeviceTrainCache::default();
        let detected = detect_from_facts("a", "SRX345", "24.4R1.9").unwrap();
        for name in ["a", "b", "c"] {
            cache.put(name, detected);
        }
        cache.invalidate(&["a".to_string()]);
        assert!(cache.get("a").is_none() && cache.get("b").is_some());
        cache.clear();
        assert!(cache.get("b").is_none() && cache.get("c").is_none());
    }

    fn args(router: Option<&str>, family: Option<&str>, release: Option<&str>) -> LookupApiArgs {
        LookupApiArgs {
            router: router.map(Into::into),
            family: family.map(Into::into),
            release: release.map(Into::into),
            query: "show".into(),
            kind: LookupKind::Rpc,
            limit: None,
            timeout: 5,
        }
    }

    #[tokio::test]
    async fn lookup_by_family_release() {
        let cache = DeviceTrainCache::default();
        let out = run(
            &fixture_catalog(),
            args(None, Some("junos-es"), Some("24.4R2-S1")),
            manager(),
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(out["family"], "junos-es");
        assert_eq!(out["train_requested"], "24.4");
        assert!(out["hits"].is_array());
    }

    #[tokio::test]
    async fn lookup_requires_router_or_family_release() {
        let cache = DeviceTrainCache::default();
        for bad in [
            args(None, None, None),
            args(None, Some("junos-es"), None),
            args(Some("r1"), Some("junos-es"), Some("24.4")),
        ] {
            let err = run(&fixture_catalog(), bad, manager(), &cache)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("router") && err.contains("family") && err.contains("release"));
        }
    }

    #[tokio::test]
    async fn lookup_router_unreachable_suggests_family_release() {
        let cache = DeviceTrainCache::default();
        let err = run(
            &fixture_catalog(),
            args(Some("r1"), None, None),
            manager(),
            &cache,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("family") && err.contains("release"), "{err}");
    }

    #[tokio::test]
    async fn lookup_unsupported_model_errors() {
        let cache = DeviceTrainCache::default();
        let err = run(
            &fixture_catalog(),
            args(None, Some("junos-es"), Some("21.4R1")),
            manager(),
            &cache,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("23.1"), "{err}");
        assert_eq!(family_for("MX480", "24.4R1"), None);
    }

    /// A full `get-interface-information` reply tree is ~470 KB; the lookup
    /// result must stay small enough for a model's context.
    #[tokio::test]
    async fn lookup_of_large_rpc_stays_small() {
        let mut lookup = args(None, Some("junos-es"), Some("24.4"));
        lookup.query = "get-interface-information".into();
        let out = run(
            Catalog::embedded(),
            lookup,
            manager(),
            &DeviceTrainCache::default(),
        )
        .await
        .unwrap();
        assert_eq!(out["hits"][0]["output_truncated"], true, "{out}");
        let size = serde_json::to_string_pretty(&out).unwrap().len();
        assert!(size < 64 * 1024, "{size} bytes");
    }

    #[test]
    fn cache_returns_fresh_entries_only() {
        let cache = DeviceTrainCache::default();
        assert!(cache.get("r1").is_none());
        let detected = (
            Family::JunosEs,
            Train {
                major: 24,
                minor: 4,
            },
            true,
        );
        cache.put("r1", detected);
        assert_eq!(cache.get("r1"), Some(detected));
    }
}
