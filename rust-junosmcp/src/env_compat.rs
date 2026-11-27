use crate::cli::Cli;
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub(crate) trait EnvSource {
    fn get(&self, name: &'static str) -> Option<OsString>;
}

struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyEnvWarning {
    Applied {
        legacy: &'static str,
        canonical: &'static str,
    },
    Ignored {
        legacy: &'static str,
        canonical: Option<&'static str>,
    },
}

#[derive(Debug)]
pub(crate) struct ParsedCli {
    pub cli: Cli,
    pub warnings: Vec<LegacyEnvWarning>,
}

pub(crate) fn parse() -> ParsedCli {
    try_parse_from_with_env(std::env::args_os(), &ProcessEnv).unwrap_or_else(|error| error.exit())
}

pub(crate) fn emit_warnings(warnings: &[LegacyEnvWarning]) {
    for warning in warnings {
        match warning {
            LegacyEnvWarning::Applied { legacy, canonical } => {
                tracing::warn!(
                    legacy = *legacy,
                    canonical = *canonical,
                    "deprecated environment alias applied; migrate to canonical name"
                );
            }
            LegacyEnvWarning::Ignored { legacy, canonical } => {
                tracing::warn!(
                    legacy = *legacy,
                    canonical = canonical.unwrap_or("none"),
                    "deprecated environment variable ignored"
                );
            }
        }
    }
}

struct Resolver<'a, E: EnvSource + ?Sized> {
    matches: &'a clap::ArgMatches,
    env: &'a E,
    warnings: Vec<LegacyEnvWarning>,
}

impl<E: EnvSource + ?Sized> Resolver<'_, E> {
    fn resolve<T>(
        &mut self,
        current: &mut T,
        arg_id: &str,
        canonical: &'static str,
        legacy: Option<&'static str>,
        parse: impl Fn(&'static str, &OsStr) -> Result<T, clap::Error>,
    ) -> Result<(), clap::Error> {
        let command_line = self.matches.value_source(arg_id) == Some(ValueSource::CommandLine);
        let canonical_value = self.env.get(canonical);
        let legacy_value = legacy.and_then(|name| self.env.get(name).map(|value| (name, value)));

        if command_line {
            if let Some((legacy, _)) = legacy_value.as_ref() {
                self.warnings.push(LegacyEnvWarning::Ignored {
                    legacy,
                    canonical: Some(canonical),
                });
            }
            return Ok(());
        }

        if let Some(value) = canonical_value {
            *current = parse(canonical, &value)?;
            if let Some((legacy, _)) = legacy_value.as_ref() {
                self.warnings.push(LegacyEnvWarning::Ignored {
                    legacy,
                    canonical: Some(canonical),
                });
            }
            return Ok(());
        }

        if let Some((legacy, value)) = legacy_value {
            *current = parse(legacy, &value)?;
            self.warnings
                .push(LegacyEnvWarning::Applied { legacy, canonical });
        }
        Ok(())
    }
}

fn invalid_value(name: &'static str, value: &OsStr, detail: &str) -> clap::Error {
    clap::Error::raw(
        clap::error::ErrorKind::ValueValidation,
        format!(
            "invalid value {:?} for environment variable {name}: {detail}",
            value
        ),
    )
}

fn parse_utf8<'a>(name: &'static str, value: &'a OsStr) -> Result<&'a str, clap::Error> {
    value
        .to_str()
        .ok_or_else(|| invalid_value(name, value, "value must be UTF-8"))
}

fn parse_string(name: &'static str, value: &OsStr) -> Result<String, clap::Error> {
    Ok(parse_utf8(name, value)?.to_owned())
}

fn parse_path(_name: &'static str, value: &OsStr) -> Result<PathBuf, clap::Error> {
    Ok(PathBuf::from(value))
}

fn parse_optional_path(_name: &'static str, value: &OsStr) -> Result<Option<PathBuf>, clap::Error> {
    Ok(Some(PathBuf::from(value)))
}

fn parse_number<T>(name: &'static str, value: &OsStr) -> Result<T, clap::Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = parse_utf8(name, value)?;
    raw.parse::<T>()
        .map_err(|error| invalid_value(name, value, &error.to_string()))
}

fn parse_bool(name: &'static str, value: &OsStr) -> Result<bool, clap::Error> {
    match parse_utf8(name, value)?.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(invalid_value(
            name,
            value,
            "expected true/false, 1/0, yes/no, or on/off",
        )),
    }
}

pub(crate) fn try_parse_from_with_env<I, T>(
    args: I,
    env: &impl EnvSource,
) -> Result<ParsedCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = Cli::command().try_get_matches_from(args)?;
    let mut cli = Cli::from_arg_matches(&matches)?;
    let mut resolver = Resolver {
        matches: &matches,
        env,
        warnings: Vec::new(),
    };

    resolver.resolve(
        &mut cli.host,
        "host",
        "JMCP_HTTP_HOST",
        Some("JMCP_SRX_HTTP_HOST"),
        parse_string,
    )?;
    resolver.resolve(
        &mut cli.port,
        "port",
        "JMCP_HTTP_PORT",
        None,
        parse_number::<u16>,
    )?;
    resolver.resolve(
        &mut cli.tokens_file,
        "tokens_file",
        "JMCP_TOKENS_PATH",
        None,
        parse_optional_path,
    )?;
    resolver.resolve(
        &mut cli.device_mapping,
        "device_mapping",
        "JMCP_DEVICES_PATH",
        None,
        parse_path,
    )?;
    resolver.resolve(
        &mut cli.skills_dir,
        "skills_dir",
        "JMCP_SKILLS_DIR",
        None,
        parse_path,
    )?;
    resolver.resolve(
        &mut cli.device_lease_dir,
        "device_lease_dir",
        "JMCP_DEVICE_LEASE_DIR",
        None,
        parse_path,
    )?;
    resolver.resolve(
        &mut cli.tls_cert,
        "tls_cert",
        "JMCP_TLS_CERT",
        Some("JMCP_SRX_TLS_CERT"),
        parse_optional_path,
    )?;
    resolver.resolve(
        &mut cli.tls_key,
        "tls_key",
        "JMCP_TLS_KEY",
        Some("JMCP_SRX_TLS_KEY"),
        parse_optional_path,
    )?;
    resolver.resolve(
        &mut cli.enable_metrics,
        "enable_metrics",
        "JMCP_ENABLE_METRICS",
        Some("JMCP_SRX_ENABLE_METRICS"),
        parse_bool,
    )?;
    resolver.resolve(
        &mut cli.max_request_body_bytes,
        "max_request_body_bytes",
        "JMCP_MAX_REQUEST_BODY_BYTES",
        Some("JMCP_SRX_MAX_REQUEST_BODY_BYTES"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.max_inflight_requests,
        "max_inflight_requests",
        "JMCP_MAX_INFLIGHT_REQUESTS",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.max_inflight_requests_per_token,
        "max_inflight_requests_per_token",
        "JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.max_requests_per_second_per_token,
        "max_requests_per_second_per_token",
        "JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN",
        Some("JMCP_SRX_MAX_REQUESTS_PER_SECOND_PER_TOKEN"),
        parse_number::<u64>,
    )?;
    resolver.resolve(
        &mut cli.max_request_burst_per_token,
        "max_request_burst_per_token",
        "JMCP_MAX_REQUEST_BURST_PER_TOKEN",
        Some("JMCP_SRX_MAX_REQUEST_BURST_PER_TOKEN"),
        parse_number::<u64>,
    )?;
    resolver.resolve(
        &mut cli.max_inflight_requests_per_router,
        "max_inflight_requests_per_router",
        "JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER",
        Some("JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_ROUTER"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.max_sessions,
        "max_sessions",
        "JMCP_MAX_SESSIONS",
        Some("JMCP_SRX_MAX_SESSIONS"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.max_sessions_per_token,
        "max_sessions_per_token",
        "JMCP_MAX_SESSIONS_PER_TOKEN",
        Some("JMCP_SRX_MAX_SESSIONS_PER_TOKEN"),
        parse_number::<usize>,
    )?;
    resolver.resolve(
        &mut cli.session_idle_timeout_secs,
        "session_idle_timeout_secs",
        "JMCP_SESSION_IDLE_TIMEOUT_SECS",
        Some("JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS"),
        parse_number::<u64>,
    )?;
    resolver.resolve(
        &mut cli.session_max_lifetime_secs,
        "session_max_lifetime_secs",
        "JMCP_SESSION_MAX_LIFETIME_SECS",
        Some("JMCP_SRX_SESSION_MAX_LIFETIME_SECS"),
        parse_number::<u64>,
    )?;
    resolver.resolve(
        &mut cli.audit_format,
        "audit_format",
        "JMCP_AUDIT_FORMAT",
        Some("JMCP_SRX_AUDIT_FORMAT"),
        parse_string,
    )?;
    resolver.resolve(
        &mut cli.audit_log_file,
        "audit_log_file",
        "JMCP_AUDIT_LOG_FILE",
        Some("JMCP_SRX_AUDIT_LOG_FILE"),
        parse_optional_path,
    )?;
    resolver.resolve(
        &mut cli.audit_journald,
        "audit_journald",
        "JMCP_AUDIT_JOURNALD",
        Some("JMCP_SRX_AUDIT_JOURNALD"),
        parse_bool,
    )?;
    resolver.resolve(
        &mut cli.audit_redact,
        "audit_redact",
        "JMCP_AUDIT_REDACT",
        Some("JMCP_SRX_AUDIT_REDACT"),
        parse_string,
    )?;
    resolver.resolve(
        &mut cli.audit_hmac_key_file,
        "audit_hmac_key_file",
        "JMCP_AUDIT_HMAC_KEY_FILE",
        Some("JMCP_SRX_AUDIT_HMAC_KEY_FILE"),
        parse_optional_path,
    )?;
    #[cfg(feature = "srx")]
    resolver.resolve(
        &mut cli.support_bundle_staging_dir,
        "support_bundle_staging_dir",
        "JMCP_SUPPORT_BUNDLE_STAGING_DIR",
        Some("JMCP_SRX_STAGING_DIR"),
        parse_path,
    )?;
    #[cfg(feature = "srx")]
    resolver.resolve(
        &mut cli.support_bundle_staging_max_bytes,
        "support_bundle_staging_max_bytes",
        "JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES",
        Some("JMCP_SRX_STAGING_MAX_BYTES"),
        parse_number::<u64>,
    )?;

    if env.get("JMCP_SRX_HTTP_PORT").is_some() {
        resolver.warnings.push(LegacyEnvWarning::Ignored {
            legacy: "JMCP_SRX_HTTP_PORT",
            canonical: None,
        });
    }

    Ok(ParsedCli {
        cli,
        warnings: resolver.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    #[cfg(feature = "srx")]
    use std::path::PathBuf;

    #[derive(Default)]
    struct TestEnv(BTreeMap<&'static str, OsString>);

    impl<const N: usize> From<[(&'static str, &'static str); N]> for TestEnv {
        fn from(entries: [(&'static str, &'static str); N]) -> Self {
            Self(
                entries
                    .into_iter()
                    .map(|(name, value)| (name, OsString::from(value)))
                    .collect(),
            )
        }
    }

    impl EnvSource for TestEnv {
        fn get(&self, name: &'static str) -> Option<OsString> {
            self.0.get(name).cloned()
        }
    }

    #[test]
    fn legacy_only_host_is_applied_and_warned() {
        let env = TestEnv::from([("JMCP_SRX_HTTP_HOST", "192.0.2.10")]);
        let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
        assert_eq!(parsed.cli.host, "192.0.2.10");
        assert_eq!(
            parsed.warnings,
            vec![LegacyEnvWarning::Applied {
                legacy: "JMCP_SRX_HTTP_HOST",
                canonical: "JMCP_HTTP_HOST",
            }]
        );
    }

    #[test]
    fn command_line_beats_both_environment_names() {
        let env = TestEnv::from([
            ("JMCP_HTTP_HOST", "192.0.2.20"),
            ("JMCP_SRX_HTTP_HOST", "192.0.2.30"),
        ]);
        let parsed =
            try_parse_from_with_env(["rust-junosmcp", "--host", "127.0.0.9"], &env).unwrap();
        assert_eq!(parsed.cli.host, "127.0.0.9");
        assert_eq!(
            parsed.warnings,
            vec![LegacyEnvWarning::Ignored {
                legacy: "JMCP_SRX_HTTP_HOST",
                canonical: Some("JMCP_HTTP_HOST"),
            }]
        );
    }

    #[test]
    fn canonical_environment_beats_legacy() {
        let env = TestEnv::from([("JMCP_MAX_SESSIONS", "77"), ("JMCP_SRX_MAX_SESSIONS", "88")]);
        let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
        assert_eq!(parsed.cli.max_sessions, 77);
        assert!(matches!(
            parsed.warnings.as_slice(),
            [LegacyEnvWarning::Ignored {
                legacy: "JMCP_SRX_MAX_SESSIONS",
                canonical: Some("JMCP_MAX_SESSIONS"),
            }]
        ));
    }

    #[test]
    fn legacy_port_is_never_applied() {
        let env = TestEnv::from([("JMCP_SRX_HTTP_PORT", "30032")]);
        let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
        assert_eq!(parsed.cli.port, 30030);
        assert_eq!(
            parsed.warnings,
            vec![LegacyEnvWarning::Ignored {
                legacy: "JMCP_SRX_HTTP_PORT",
                canonical: None,
            }]
        );
    }

    #[test]
    fn invalid_applied_legacy_value_is_a_startup_error() {
        let env = TestEnv::from([("JMCP_SRX_MAX_SESSIONS", "many")]);
        let error = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap_err();
        assert!(error.to_string().contains("JMCP_SRX_MAX_SESSIONS"));
        assert!(error.to_string().contains("many"));
    }

    #[cfg(feature = "srx")]
    #[test]
    fn legacy_support_bundle_settings_are_applied_and_warned() {
        let env = TestEnv::from([
            ("JMCP_SRX_STAGING_DIR", "/tmp/legacy-srx-bundles"),
            ("JMCP_SRX_STAGING_MAX_BYTES", "123456"),
        ]);
        let parsed = try_parse_from_with_env(["rust-junosmcp"], &env).unwrap();
        assert_eq!(
            parsed.cli.support_bundle_staging_dir,
            PathBuf::from("/tmp/legacy-srx-bundles")
        );
        assert_eq!(parsed.cli.support_bundle_staging_max_bytes, 123456);
        assert_eq!(parsed.warnings.len(), 2);
        assert!(parsed.warnings.contains(&LegacyEnvWarning::Applied {
            legacy: "JMCP_SRX_STAGING_DIR",
            canonical: "JMCP_SUPPORT_BUNDLE_STAGING_DIR",
        }));
        assert!(parsed.warnings.contains(&LegacyEnvWarning::Applied {
            legacy: "JMCP_SRX_STAGING_MAX_BYTES",
            canonical: "JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES",
        }));
    }
}
